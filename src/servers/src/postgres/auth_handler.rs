// Copyright 2023 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::Debug;
use std::sync::Exclusive;

use ::auth::{userinfo_by_name, UserInfoRef, UserProviderRef};
use async_trait::async_trait;
use common_catalog::parse_catalog_and_schema_from_db_string;
use futures::{Sink, SinkExt};
use pgwire::api::auth::StartupHandler;
use pgwire::api::{auth, ClientInfo, PgWireConnectionState};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::response::ErrorResponse;
use pgwire::messages::startup::Authentication;
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use session::Session;

use crate::common::auth::CredentialExtractor;
use crate::error::Result;
use crate::postgres::auth_extractor::{create_postgres_auth_data, PostgresAuthenticator};
use crate::postgres::types::PgErrorCode;
use crate::postgres::PostgresServerHandlerInner;
use crate::query_handler::sql::ServerSqlQueryHandlerRef;

pub(crate) struct PgLoginVerifier {
    user_provider: Option<UserProviderRef>,
}

impl PgLoginVerifier {
    pub(crate) fn new(user_provider: Option<UserProviderRef>) -> Self {
        Self { user_provider }
    }
}

#[allow(dead_code)]
struct LoginInfo {
    user: Option<String>,
    catalog: Option<String>,
    schema: Option<String>,
    host: String,
}

impl LoginInfo {
    pub fn from_client_info<C>(client: &C) -> LoginInfo
    where
        C: ClientInfo,
    {
        LoginInfo {
            user: client.metadata().get(super::METADATA_USER).map(Into::into),
            catalog: client
                .metadata()
                .get(super::METADATA_CATALOG)
                .map(Into::into),
            schema: client
                .metadata()
                .get(super::METADATA_SCHEMA)
                .map(Into::into),
            host: client.socket_addr().ip().to_string(),
        }
    }
}

impl PgLoginVerifier {
    /// PostgreSQL authentication function using the common auth system.
    async fn common_auth(&self, login: &LoginInfo, password: &str) -> Result<Option<UserInfoRef>> {
        // Create PostgreSQL auth data
        let postgres_auth_data = create_postgres_auth_data(
            login.user.clone(),
            login.catalog.clone().or_else(|| login.schema.clone()),
            password.to_string(),
            login.host.clone(),
        );

        // Use common authenticator
        let authenticator = PostgresAuthenticator::new(self.user_provider.clone());

        // Extract auth context from the auth data
        let extractor = crate::postgres::auth_extractor::PostgresCredentialExtractor::new();
        let context = extractor.extract_auth_context(&postgres_auth_data);

        match authenticator
            .authenticate_postgres(&postgres_auth_data, &context)
            .await
        {
            Ok(user_info) => Ok(user_info),
            Err(e) => Err(e),
        }
    }
}

fn set_client_info<C>(client: &mut C, session: &Session)
where
    C: ClientInfo,
{
    if let Some(current_catalog) = client.metadata().get(super::METADATA_CATALOG) {
        session.set_catalog(current_catalog.clone());
    }
    if let Some(current_schema) = client.metadata().get(super::METADATA_SCHEMA) {
        session.set_schema(current_schema.clone());
    }

    // pass generated process id and secret key to client, this information will
    // be sent to postgres client for query cancellation.
    client.set_pid_and_secret_key(session.process_id() as i32, rand::random::<i32>());
    // set userinfo outside
}

#[async_trait]
impl StartupHandler for PostgresServerHandlerInner {
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        match message {
            PgWireFrontendMessage::Startup(ref startup) => {
                // check ssl requirement
                if !client.is_secure() && self.force_tls {
                    send_error(
                        client,
                        PgErrorCode::Ec28000.to_err_info("No encryption".to_string()),
                    )
                    .await?;
                    return Ok(());
                }

                auth::save_startup_parameters_to_metadata(client, startup);

                // check if db is valid
                match resolve_db_info(Exclusive::new(client), self.query_handler.clone()).await? {
                    DbResolution::Resolved(catalog, schema) => {
                        let metadata = client.metadata_mut();
                        let _ = metadata.insert(super::METADATA_CATALOG.to_owned(), catalog);
                        let _ = metadata.insert(super::METADATA_SCHEMA.to_owned(), schema);
                    }
                    DbResolution::NotFound(msg) => {
                        send_error(client, PgErrorCode::Ec3D000.to_err_info(msg)).await?;
                        return Ok(());
                    }
                }

                if self.login_verifier.user_provider.is_some() {
                    client.set_state(PgWireConnectionState::AuthenticationInProgress);
                    client
                        .send(PgWireBackendMessage::Authentication(
                            Authentication::CleartextPassword,
                        ))
                        .await?;
                } else {
                    self.session.set_user_info(userinfo_by_name(
                        client.metadata().get(super::METADATA_USER).cloned(),
                    ));
                    set_client_info(client, &self.session);
                    auth::finish_authentication(client, self.param_provider.as_ref()).await?;
                }
            }
            PgWireFrontendMessage::PasswordMessageFamily(pwd) => {
                // the newer version of pgwire has a few variant password
                // message like cleartext/md5 password, saslresponse, etc. Here
                // we must manually coerce it into password
                let pwd = pwd.into_password()?;

                let login_info = LoginInfo::from_client_info(client);

                // do authenticate using the new common auth system
                let auth_result = self
                    .login_verifier
                    .common_auth(&login_info, &pwd.password)
                    .await;

                if let Ok(Some(user_info)) = auth_result {
                    self.session.set_user_info(user_info);
                    set_client_info(client, &self.session);
                    auth::finish_authentication(client, self.param_provider.as_ref()).await?;
                } else {
                    return send_error(
                        client,
                        PgErrorCode::Ec28P01
                            .to_err_info("password authentication failed".to_string()),
                    )
                    .await;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

async fn send_error<C>(client: &mut C, err_info: ErrorInfo) -> PgWireResult<()>
where
    C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
    C::Error: Debug,
    PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
{
    let error = ErrorResponse::from(err_info);
    client
        .feed(PgWireBackendMessage::ErrorResponse(error))
        .await?;
    client.close().await?;
    Ok(())
}

enum DbResolution {
    Resolved(String, String),
    NotFound(String),
}

/// A function extracted to resolve lifetime and readability issues:
async fn resolve_db_info<C>(
    client: Exclusive<&mut C>,
    query_handler: ServerSqlQueryHandlerRef,
) -> PgWireResult<DbResolution>
where
    C: ClientInfo + Unpin + Send,
{
    let db_ref = client.into_inner().metadata().get(super::METADATA_DATABASE);
    if let Some(db) = db_ref {
        let (catalog, schema) = parse_catalog_and_schema_from_db_string(db);
        if query_handler
            .is_valid_schema(&catalog, &schema)
            .await
            .map_err(|e| PgWireError::ApiError(Box::new(e)))?
        {
            Ok(DbResolution::Resolved(catalog, schema))
        } else {
            Ok(DbResolution::NotFound(format!("Database not found: {db}")))
        }
    } else {
        Ok(DbResolution::NotFound("Database not specified".to_owned()))
    }
}
