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

//! MySQL-specific authentication credential extraction.

use auth::{Identity, Password, UserProviderRef};
use common_base::secrets::{ExposeSecret, SecretString};
use common_error::ext::ErrorExt;
use snafu::ResultExt;

use crate::common::auth::{AuthContext, CredentialExtractor, Credentials};
use crate::error::{AuthSnafu, InternalSnafu, Result};

const MYSQL_NATIVE_PASSWORD: &str = "mysql_native_password";
const MYSQL_CLEAR_PASSWORD: &str = "mysql_clear_password";

/// MySQL authentication data context.
pub struct MysqlAuthData {
    pub username: String,
    pub auth_plugin: String,
    pub auth_data: Vec<u8>,
    pub salt: Vec<u8>,
    pub client_addr: Option<String>,
}

/// MySQL-specific credential extractor.
#[derive(Default)]
pub struct MysqlCredentialExtractor;

impl MysqlCredentialExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Convert MySQL auth plugin and data to common Password type
    fn convert_mysql_password<'a>(
        auth_plugin: &str,
        auth_data: &'a [u8],
        salt: &'a [u8],
    ) -> Result<Password<'a>> {
        match auth_plugin {
            MYSQL_NATIVE_PASSWORD => Ok(Password::MysqlNativePassword(auth_data, salt)),
            MYSQL_CLEAR_PASSWORD => {
                // The raw bytes received could be represented in C-like string, ended in '\0'.
                // We must "trim" it to get the real password string.
                let password = if let &[password @ .., 0] = &auth_data {
                    password
                } else {
                    auth_data
                };
                Ok(Password::PlainText(
                    String::from_utf8_lossy(password).to_string().into(),
                ))
            }
            other => InternalSnafu {
                err_msg: format!("Unsupported mysql auth plugin: {}", other),
            }
            .fail(),
        }
    }

    /// Create Identity from MySQL username and client address
    fn create_mysql_identity<'a>(username: &'a str, client_addr: Option<&'a str>) -> Identity<'a> {
        Identity::UserId(username, client_addr)
    }
}

impl CredentialExtractor<MysqlAuthData> for MysqlCredentialExtractor {
    type Error = crate::error::Error;

    fn extract_credentials(
        &self,
        req: &MysqlAuthData,
    ) -> std::result::Result<Credentials, Self::Error> {
        // For MySQL, we convert to a custom credential type that can hold the MySQL-specific data
        // Since MySQL auth is more complex than simple Basic auth, we use a special approach
        match Self::convert_mysql_password(&req.auth_plugin, &req.auth_data, &req.salt) {
            Ok(Password::PlainText(password)) => Ok(Credentials::Basic {
                username: req.username.clone(),
                password: SecretString::new(Box::new(password.expose_secret().to_string())),
            }),
            Ok(_) => {
                // For MySQL native password, we'll need to handle it specially
                // For now, create a special marker that indicates MySQL auth
                Ok(Credentials::Basic {
                    username: req.username.clone(),
                    password: SecretString::new(Box::new("__mysql_native__".to_string())),
                })
            }
            Err(e) => Err(e),
        }
    }

    fn extract_auth_context(&self, req: &MysqlAuthData) -> AuthContext {
        // MySQL uses default catalog/schema for now
        // This could be enhanced to extract from connection parameters
        AuthContext {
            catalog: "greptime".to_string(),
            schema: "public".to_string(),
            require_auth: self.requires_auth(req),
        }
    }

    fn requires_auth(&self, _req: &MysqlAuthData) -> bool {
        // MySQL always requires authentication if a user provider is configured
        true
    }
}

/// MySQL-specific authenticator that handles MySQL native password
pub struct MysqlAuthenticator {
    user_provider: Option<UserProviderRef>,
}

impl MysqlAuthenticator {
    pub fn new(user_provider: Option<UserProviderRef>) -> Self {
        Self { user_provider }
    }

    /// Authenticate MySQL credentials with special handling for MySQL native password
    pub async fn authenticate_mysql(
        &self,
        auth_data: &MysqlAuthData,
        context: &AuthContext,
    ) -> Result<auth::UserInfoRef> {
        // If no user provider, return default user
        if self.user_provider.is_none() {
            return Ok(auth::userinfo_by_name(Some(auth_data.username.clone())));
        }

        let user_provider = self.user_provider.as_ref().unwrap();

        // Create identity with client address for MySQL
        let identity = MysqlCredentialExtractor::create_mysql_identity(
            &auth_data.username,
            auth_data.client_addr.as_deref(),
        );

        // Convert auth data to password
        let password = MysqlCredentialExtractor::convert_mysql_password(
            &auth_data.auth_plugin,
            &auth_data.auth_data,
            &auth_data.salt,
        )?;

        // Authenticate using user provider
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

#[cfg(test)]
mod tests {
    use common_base::secrets::ExposeSecret;

    use super::*;

    fn create_test_auth_data() -> MysqlAuthData {
        MysqlAuthData {
            username: "testuser".to_string(),
            auth_plugin: MYSQL_CLEAR_PASSWORD.to_string(),
            auth_data: b"testpass".to_vec(),
            salt: vec![0; 20],
            client_addr: Some("127.0.0.1".to_string()),
        }
    }

    #[test]
    fn test_extract_credentials_clear_password() {
        let auth_data = create_test_auth_data();
        let extractor = MysqlCredentialExtractor::new();
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
    fn test_extract_credentials_native_password() {
        let mut auth_data = create_test_auth_data();
        auth_data.auth_plugin = MYSQL_NATIVE_PASSWORD.to_string();

        let extractor = MysqlCredentialExtractor::new();
        let credentials = extractor.extract_credentials(&auth_data).unwrap();

        match credentials {
            Credentials::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password.expose_secret(), "__mysql_native__");
            }
            _ => panic!("Expected Basic credentials"),
        }
    }

    #[test]
    fn test_requires_auth() {
        let auth_data = create_test_auth_data();
        let extractor = MysqlCredentialExtractor::new();
        assert!(extractor.requires_auth(&auth_data));
    }

    #[test]
    fn test_extract_auth_context() {
        let auth_data = create_test_auth_data();
        let extractor = MysqlCredentialExtractor::new();
        let context = extractor.extract_auth_context(&auth_data);

        assert_eq!(context.catalog, "greptime");
        assert_eq!(context.schema, "public");
        assert!(context.require_auth);
    }
}
