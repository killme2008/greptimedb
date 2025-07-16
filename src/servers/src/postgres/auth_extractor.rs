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

//! PostgreSQL-specific authentication credential extraction.

use auth::{Identity, UserInfoRef, UserProviderRef};
use common_base::secrets::SecretString;
use common_catalog::parse_catalog_and_schema_from_db_string;
use common_error::ext::ErrorExt;
use snafu::ResultExt;

use crate::common::auth::{AuthContext, CredentialExtractor, Credentials};
use crate::error::{AuthSnafu, Result};

/// PostgreSQL authentication data context.
pub struct PostgresAuthData {
    pub user: Option<String>,
    pub database: Option<String>,
    pub password: String,
    pub client_addr: String,
}

/// PostgreSQL-specific credential extractor.
#[derive(Default)]
pub struct PostgresCredentialExtractor;

impl PostgresCredentialExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialExtractor<PostgresAuthData> for PostgresCredentialExtractor {
    type Error = crate::error::Error;

    fn extract_credentials(
        &self,
        req: &PostgresAuthData,
    ) -> std::result::Result<Credentials, Self::Error> {
        match &req.user {
            Some(username) => Ok(Credentials::Basic {
                username: username.clone(),
                password: SecretString::new(Box::new(req.password.clone())),
            }),
            None => Ok(Credentials::None),
        }
    }

    fn extract_auth_context(&self, req: &PostgresAuthData) -> AuthContext {
        let (catalog, schema) = match &req.database {
            Some(db_name) => parse_catalog_and_schema_from_db_string(db_name),
            None => ("greptime".to_string(), "public".to_string()),
        };

        AuthContext {
            catalog,
            schema,
            require_auth: self.requires_auth(req),
        }
    }

    fn requires_auth(&self, req: &PostgresAuthData) -> bool {
        // PostgreSQL requires auth if user is provided
        req.user.is_some()
    }
}

/// PostgreSQL-specific authenticator that handles PostgreSQL auth flow
pub struct PostgresAuthenticator {
    user_provider: Option<UserProviderRef>,
}

impl PostgresAuthenticator {
    pub fn new(user_provider: Option<UserProviderRef>) -> Self {
        Self { user_provider }
    }

    /// Authenticate PostgreSQL credentials
    pub async fn authenticate_postgres(
        &self,
        auth_data: &PostgresAuthData,
        context: &AuthContext,
    ) -> Result<Option<UserInfoRef>> {
        let user_provider = match &self.user_provider {
            Some(provider) => provider,
            None => return Ok(None),
        };

        let user_name = match &auth_data.user {
            Some(name) => name,
            None => return Ok(None),
        };

        match user_provider
            .auth(
                Identity::UserId(user_name, None),
                auth::Password::PlainText(auth_data.password.clone().into()),
                &context.catalog,
                &context.schema,
            )
            .await
        {
            Err(e) => {
                crate::metrics::METRIC_AUTH_FAILURE
                    .with_label_values(&[e.status_code().as_ref()])
                    .inc();
                Err(e).context(AuthSnafu)
            }
            Ok(user_info) => Ok(Some(user_info)),
        }
    }
}

/// Helper function to create PostgresAuthData from login info
pub fn create_postgres_auth_data(
    user: Option<String>,
    database: Option<String>,
    password: String,
    client_addr: String,
) -> PostgresAuthData {
    PostgresAuthData {
        user,
        database,
        password,
        client_addr,
    }
}

#[cfg(test)]
mod tests {
    use common_base::secrets::ExposeSecret;

    use super::*;

    fn create_test_auth_data() -> PostgresAuthData {
        PostgresAuthData {
            user: Some("testuser".to_string()),
            database: Some("testdb".to_string()),
            password: "testpass".to_string(),
            client_addr: "127.0.0.1".to_string(),
        }
    }

    #[test]
    fn test_extract_credentials() {
        let auth_data = create_test_auth_data();
        let extractor = PostgresCredentialExtractor::new();
        let credentials = extractor.extract_credentials(&auth_data).unwrap();

        match credentials {
            Credentials::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password.expose_secret(), "testpass");
            }
            _ => panic!("Expected Basic credentials"),
        }
    }

    #[test]
    fn test_extract_credentials_no_user() {
        let mut auth_data = create_test_auth_data();
        auth_data.user = None;

        let extractor = PostgresCredentialExtractor::new();
        let credentials = extractor.extract_credentials(&auth_data).unwrap();

        assert!(matches!(credentials, Credentials::None));
    }

    #[test]
    fn test_requires_auth() {
        let auth_data = create_test_auth_data();
        let extractor = PostgresCredentialExtractor::new();
        assert!(extractor.requires_auth(&auth_data));

        let mut auth_data_no_user = create_test_auth_data();
        auth_data_no_user.user = None;
        assert!(!extractor.requires_auth(&auth_data_no_user));
    }

    #[test]
    fn test_extract_auth_context() {
        let auth_data = create_test_auth_data();
        let extractor = PostgresCredentialExtractor::new();
        let context = extractor.extract_auth_context(&auth_data);

        // Should parse the database name
        assert!(!context.catalog.is_empty());
        assert!(!context.schema.is_empty());
        assert!(context.require_auth);
    }

    #[test]
    fn test_extract_auth_context_no_database() {
        let mut auth_data = create_test_auth_data();
        auth_data.database = None;

        let extractor = PostgresCredentialExtractor::new();
        let context = extractor.extract_auth_context(&auth_data);

        assert_eq!(context.catalog, "greptime");
        assert_eq!(context.schema, "public");
    }
}
