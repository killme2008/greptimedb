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

//! Common credential parsing utilities.

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use common_base::secrets::{ExposeSecret, SecretString};
use snafu::{OptionExt, ResultExt};

use super::Credentials;
use crate::error::{
    InvalidAuthHeaderInvalidUtf8ValueSnafu, InvalidAuthHeaderSnafu, InvalidBase64ValueSnafu, Result,
};

/// Parse Basic authentication from an Authorization header value.
pub fn parse_basic_auth(auth_header: &str) -> Result<Credentials> {
    let credential = auth_header
        .strip_prefix("Basic ")
        .context(InvalidAuthHeaderSnafu)?;

    let (username, password) = decode_basic_credential(credential)?;
    Ok(Credentials::Basic { username, password })
}

/// Parse Bearer token authentication from an Authorization header value.
pub fn parse_bearer_token(auth_header: &str) -> Result<Credentials> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .context(InvalidAuthHeaderSnafu)?;

    Ok(Credentials::Token {
        token: SecretString::new(Box::new(token.to_string())),
    })
}

/// Parse authentication from an Authorization header value.
/// Supports both Basic and Bearer authentication schemes.
pub fn parse_authorization_header(auth_header: &str) -> Result<Credentials> {
    if auth_header.starts_with("Basic ") {
        parse_basic_auth(auth_header)
    } else if auth_header.starts_with("Bearer ") {
        parse_bearer_token(auth_header)
    } else {
        InvalidAuthHeaderSnafu {}.fail()
    }
}

/// Decode a base64-encoded Basic authentication credential.
/// Returns (username, password) tuple.
fn decode_basic_credential(credential: &str) -> Result<(String, SecretString)> {
    // Check for invisible ASCII characters that could indicate an attack
    for ch in credential.chars() {
        if ch.is_ascii_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            return Err(crate::error::Error::InvalidAuthHeader {
                location: snafu::Location::new(file!(), line!(), 0),
            });
        }
    }

    let decoded = BASE64_STANDARD
        .decode(credential)
        .context(InvalidBase64ValueSnafu)?;

    let as_utf8 = String::from_utf8(decoded).context(InvalidAuthHeaderInvalidUtf8ValueSnafu)?;

    if let Some((username, password)) = as_utf8.split_once(':') {
        Ok((
            username.to_string(),
            SecretString::new(Box::new(password.to_string())),
        ))
    } else {
        InvalidAuthHeaderSnafu {}.fail()
    }
}

/// Extract username and password from various authentication schemes.
/// This is a convenience function that handles different credential types.
pub fn extract_username_password(credentials: &Credentials) -> Option<(&str, &SecretString)> {
    match credentials {
        Credentials::Basic { username, password } => Some((username, password)),
        Credentials::Token { .. } | Credentials::None => None,
    }
}

/// Check if credentials are present and valid.
pub fn has_valid_credentials(credentials: &Credentials) -> bool {
    match credentials {
        Credentials::Basic { username, .. } => !username.is_empty(),
        Credentials::Token { token } => !token.expose_secret().is_empty(),
        Credentials::None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_auth() {
        let header = "Basic dXNlcjpwYXNz"; // user:pass
        let credentials = parse_basic_auth(header).unwrap();

        match credentials {
            Credentials::Basic { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password.expose_secret(), "pass");
            }
            _ => panic!("Expected Basic credentials"),
        }
    }

    #[test]
    fn test_parse_bearer_token() {
        let header = "Bearer my-secret-token";
        let credentials = parse_bearer_token(header).unwrap();

        match credentials {
            Credentials::Token { token } => {
                assert_eq!(token.expose_secret(), "my-secret-token");
            }
            _ => panic!("Expected Token credentials"),
        }
    }

    #[test]
    fn test_parse_authorization_header() {
        // Test Basic auth
        let basic_header = "Basic dXNlcjpwYXNz";
        let credentials = parse_authorization_header(basic_header).unwrap();
        assert!(matches!(credentials, Credentials::Basic { .. }));

        // Test Bearer token
        let bearer_header = "Bearer token123";
        let credentials = parse_authorization_header(bearer_header).unwrap();
        assert!(matches!(credentials, Credentials::Token { .. }));

        // Test invalid scheme
        let invalid_header = "Digest realm=test";
        assert!(parse_authorization_header(invalid_header).is_err());
    }

    #[test]
    fn test_extract_username_password() {
        let basic_creds = Credentials::Basic {
            username: "user".to_string(),
            password: SecretString::new(Box::new("pass".to_string())),
        };

        let (username, password) = extract_username_password(&basic_creds).unwrap();
        assert_eq!(username, "user");
        assert_eq!(password.expose_secret(), "pass");

        let token_creds = Credentials::Token {
            token: SecretString::new(Box::new("token".to_string())),
        };
        assert!(extract_username_password(&token_creds).is_none());
    }

    #[test]
    fn test_has_valid_credentials() {
        let valid_basic = Credentials::Basic {
            username: "user".to_string(),
            password: SecretString::new(Box::new("pass".to_string())),
        };
        assert!(has_valid_credentials(&valid_basic));

        let empty_basic = Credentials::Basic {
            username: "".to_string(),
            password: SecretString::new(Box::new("pass".to_string())),
        };
        assert!(!has_valid_credentials(&empty_basic));

        let valid_token = Credentials::Token {
            token: SecretString::new(Box::new("token".to_string())),
        };
        assert!(has_valid_credentials(&valid_token));

        let none_creds = Credentials::None;
        assert!(!has_valid_credentials(&none_creds));
    }
}
