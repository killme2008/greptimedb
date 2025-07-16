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

//! Common authentication abstractions for all server protocols.

use async_trait::async_trait;
use auth::UserProviderRef;
use common_base::secrets::SecretString;
use common_error::ext::ErrorExt;
use snafu::ResultExt;

use crate::error::{AuthSnafu, Result};

pub mod credentials;
pub mod provider;

/// Represents different types of credentials that can be extracted from requests.
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Basic authentication with username and password.
    Basic {
        username: String,
        password: SecretString,
    },
    /// Token-based authentication (e.g., for InfluxDB v2).
    Token { token: SecretString },
    /// No authentication provided.
    None,
}

/// Context information needed for authentication.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The catalog name for the request.
    pub catalog: String,
    /// The schema name for the request.
    pub schema: String,
    /// Whether authentication is required for this request.
    pub require_auth: bool,
}

/// Trait for extracting credentials from protocol-specific requests.
pub trait CredentialExtractor<T> {
    type Error;

    /// Extract credentials from the request.
    fn extract_credentials(&self, req: &T) -> std::result::Result<Credentials, Self::Error>;

    /// Extract authentication context (catalog, schema) from the request.
    fn extract_auth_context(&self, req: &T) -> AuthContext;

    /// Determine if authentication is required for this request.
    fn requires_auth(&self, req: &T) -> bool;
}

/// Trait for performing authentication using extracted credentials.
#[async_trait]
pub trait Authenticator {
    type Error;

    /// Authenticate the credentials and return the authenticated user info.
    async fn authenticate(
        &self,
        credentials: Credentials,
        context: &AuthContext,
    ) -> std::result::Result<auth::UserInfoRef, Self::Error>;
}

/// Common authentication state that can be used across different protocols.
#[derive(Clone)]
pub struct CommonAuthState {
    user_provider: Option<UserProviderRef>,
}

impl CommonAuthState {
    pub fn new(user_provider: Option<UserProviderRef>) -> Self {
        Self { user_provider }
    }

    pub fn user_provider(&self) -> Option<UserProviderRef> {
        self.user_provider.clone()
    }
}

/// Main authentication service that combines credential extraction and authentication.
/// Note: This is kept for future use but currently unused.
#[allow(dead_code)]
pub struct AuthenticationService<E> {
    extractor: E,
    auth_state: CommonAuthState,
}

#[allow(dead_code)]
impl<E> AuthenticationService<E> {
    pub fn new(extractor: E, auth_state: CommonAuthState) -> Self {
        Self {
            extractor,
            auth_state,
        }
    }
}

#[async_trait]
impl<E> Authenticator for AuthenticationService<E>
where
    E: Send + Sync,
{
    type Error = crate::error::Error;

    async fn authenticate(
        &self,
        credentials: Credentials,
        context: &AuthContext,
    ) -> std::result::Result<auth::UserInfoRef, Self::Error> {
        if !context.require_auth {
            return Ok(auth::userinfo_by_name(None));
        }

        let user_provider =
            self.auth_state
                .user_provider()
                .ok_or_else(|| crate::error::Error::Internal {
                    err_msg: "User provider not configured".to_string(),
                })?;

        let (identity, password) = match &credentials {
            Credentials::Basic { username, password } => (
                auth::Identity::UserId(username, None),
                auth::Password::PlainText(password.clone()),
            ),
            Credentials::Token { token: _ } => {
                return Err(crate::error::Error::Internal {
                    err_msg: "Token authentication not yet supported in common auth".to_string(),
                });
            }
            Credentials::None => {
                return Err(crate::error::Error::NotFoundAuthHeader {});
            }
        };

        match user_provider
            .auth(identity, password, &context.catalog, &context.schema)
            .await
        {
            Ok(userinfo) => Ok(userinfo),
            Err(e) => {
                crate::metrics::METRIC_AUTH_FAILURE
                    .with_label_values(&[e.status_code().as_ref()])
                    .inc();
                Err(e).context(AuthSnafu)
            }
        }
    }
}

/// Convenience function to perform authentication for a request.
pub async fn authenticate_request<E, T>(
    extractor: &E,
    auth_state: &CommonAuthState,
    req: &T,
) -> Result<(auth::UserInfoRef, AuthContext)>
where
    E: CredentialExtractor<T> + Send + Sync,
    T: Send + Sync,
    E::Error: Into<crate::error::Error>,
{
    let context = extractor.extract_auth_context(req);
    let credentials = extractor.extract_credentials(req).map_err(|e| e.into())?;

    // Use the CachingAuthProvider directly instead of AuthenticationService
    let auth_provider =
        crate::common::auth::provider::CachingAuthProvider::new(auth_state.user_provider());
    let user_info = auth_provider.authenticate(credentials, &context).await?;

    Ok((user_info, context))
}
