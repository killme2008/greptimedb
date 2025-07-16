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

//! HTTP-specific authentication credential extraction.

use axum::http;
use common_base::secrets::SecretString;
use common_catalog::consts::DEFAULT_SCHEMA_NAME;
use common_catalog::parse_catalog_and_schema_from_db_string;
use common_time::timezone::parse_timezone;
use common_time::Timezone;
use headers::Header;
use snafu::{OptionExt, ResultExt};

use crate::common::auth::{AuthContext, CredentialExtractor, Credentials};
use crate::error::{
    InvalidAuthHeaderInvisibleASCIISnafu, InvalidAuthHeaderSnafu, NotFoundAuthHeaderSnafu, Result,
    UnsupportedAuthSchemeSnafu,
};
use crate::http::header::{GreptimeDbName, GREPTIME_TIMEZONE_HEADER_NAME};
use crate::http::{HTTP_API_PREFIX, PUBLIC_APIS};
use crate::influxdb::{is_influxdb_request, is_influxdb_v2_request};

/// HTTP-specific credential extractor.
#[derive(Default)]
pub struct HttpCredentialExtractor;

impl HttpCredentialExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract timezone from HTTP headers.
    pub fn extract_timezone(request: &axum::extract::Request) -> Timezone {
        let timezone = request
            .headers()
            .get(&GREPTIME_TIMEZONE_HEADER_NAME)
            .and_then(|header| header.to_str().ok())
            .unwrap_or("");
        parse_timezone(Some(timezone))
    }

    /// Extract database name from HTTP request (header or query parameter).
    fn extract_database_name(request: &axum::extract::Request) -> &str {
        request
            .headers()
            .get(GreptimeDbName::name())
            .and_then(|header| header.to_str().ok())
            .or_else(|| {
                let query = request.uri().query().unwrap_or_default();
                if is_influxdb_v2_request(request) {
                    extract_db_from_query(query).or_else(|| extract_bucket_from_query(query))
                } else {
                    extract_db_from_query(query)
                }
            })
            .unwrap_or(DEFAULT_SCHEMA_NAME)
    }

    /// Extract InfluxDB-specific credentials from headers or query parameters.
    fn get_influxdb_credentials(request: &axum::extract::Request) -> Result<Option<Credentials>> {
        // Try header first
        if let Some(header) = request.headers().get(http::header::AUTHORIZATION) {
            let header_str = header
                .to_str()
                .context(InvalidAuthHeaderInvisibleASCIISnafu)?;

            let (auth_scheme, credential) =
                header_str.split_once(' ').context(InvalidAuthHeaderSnafu)?;

            return Ok(Some(match auth_scheme.to_lowercase().as_str() {
                "token" => {
                    let (username, password) =
                        credential.split_once(':').context(InvalidAuthHeaderSnafu)?;
                    Credentials::Basic {
                        username: username.to_string(),
                        password: SecretString::new(Box::new(password.to_string())),
                    }
                }
                "basic" => crate::common::auth::credentials::parse_basic_auth(header_str)?,
                _ => return UnsupportedAuthSchemeSnafu { name: auth_scheme }.fail(),
            }));
        }

        // Try query parameters for InfluxDB v1
        if let Some(query) = request.uri().query() {
            if let (Some(u), Some(p)) = (
                extract_param_from_query(query, "u"),
                extract_param_from_query(query, "p"),
            ) {
                return Ok(Some(Credentials::Basic {
                    username: urlencoding::decode(u)
                        .map_err(|e| crate::error::Error::UrlDecode {
                            error: e,
                            location: snafu::Location::new(file!(), line!(), 0),
                        })?
                        .to_string(),
                    password: SecretString::new(Box::new(
                        urlencoding::decode(p)
                            .map_err(|e| crate::error::Error::UrlDecode {
                                error: e,
                                location: snafu::Location::new(file!(), line!(), 0),
                            })?
                            .to_string(),
                    )),
                }));
            }
        }

        Ok(None)
    }

    /// Extract standard HTTP credentials from Authorization header.
    fn get_standard_credentials(request: &axum::extract::Request) -> Result<Option<Credentials>> {
        let header = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .context(NotFoundAuthHeaderSnafu)?;

        let header_str = header
            .to_str()
            .context(InvalidAuthHeaderInvisibleASCIISnafu)?;

        Ok(Some(
            crate::common::auth::credentials::parse_authorization_header(header_str)?,
        ))
    }
}

impl CredentialExtractor<axum::extract::Request> for HttpCredentialExtractor {
    type Error = crate::error::Error;

    fn extract_credentials(
        &self,
        req: &axum::extract::Request,
    ) -> std::result::Result<Credentials, Self::Error> {
        // Handle InfluxDB requests specially
        if is_influxdb_request(req) {
            if let Some(credentials) = Self::get_influxdb_credentials(req)? {
                return Ok(credentials);
            }
        }

        // Try standard HTTP authentication
        match Self::get_standard_credentials(req) {
            Ok(Some(credentials)) => Ok(credentials),
            Ok(None) | Err(_) => Ok(Credentials::None),
        }
    }

    fn extract_auth_context(&self, req: &axum::extract::Request) -> AuthContext {
        let db_name = Self::extract_database_name(req);
        let (catalog, schema) = parse_catalog_and_schema_from_db_string(db_name);

        AuthContext {
            catalog,
            schema,
            require_auth: self.requires_auth(req),
        }
    }

    fn requires_auth(&self, req: &axum::extract::Request) -> bool {
        let path = req.uri().path();

        for api in PUBLIC_APIS {
            if path.starts_with(api) {
                return false;
            }
        }

        path.starts_with(HTTP_API_PREFIX)
    }
}

/// Extract parameter value from query string.
fn extract_param_from_query<'a>(query: &'a str, param: &'a str) -> Option<&'a str> {
    let prefix = format!("{}=", param);
    for pair in query.split('&') {
        if let Some(param) = pair.strip_prefix(&prefix) {
            return if param.is_empty() { None } else { Some(param) };
        }
    }
    None
}

/// Extract database name from query string.
fn extract_db_from_query(query: &str) -> Option<&str> {
    extract_param_from_query(query, "db")
}

/// Extract bucket name from query string (InfluxDB v2).
fn extract_bucket_from_query(query: &str) -> Option<&str> {
    extract_param_from_query(query, "bucket")
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderValue, Method, Request};
    use common_base::secrets::ExposeSecret;

    use super::*;

    fn create_test_request(path: &str) -> axum::extract::Request {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[test]
    fn test_extract_credentials_basic_auth() {
        let mut req = create_test_request("/v1/sql");
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"), // user:pass
        );

        let extractor = HttpCredentialExtractor::new();
        let credentials = extractor.extract_credentials(&req).unwrap();

        match credentials {
            Credentials::Basic { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password.expose_secret(), "pass");
            }
            _ => panic!("Expected Basic credentials"),
        }
    }

    #[test]
    fn test_extract_credentials_no_auth() {
        let req = create_test_request("/v1/sql");
        let extractor = HttpCredentialExtractor::new();
        let credentials = extractor.extract_credentials(&req).unwrap();

        assert!(matches!(credentials, Credentials::None));
    }

    #[test]
    fn test_requires_auth() {
        let extractor = HttpCredentialExtractor::new();

        // Public API should not require auth
        let public_req = create_test_request("/health");
        assert!(!extractor.requires_auth(&public_req));

        // API endpoints should require auth
        let api_req = create_test_request("/v1/sql");
        assert!(extractor.requires_auth(&api_req));

        // Non-API paths should not require auth
        let other_req = create_test_request("/dashboard");
        assert!(!extractor.requires_auth(&other_req));
    }

    #[test]
    fn test_extract_auth_context() {
        let extractor = HttpCredentialExtractor::new();
        let req = create_test_request("/v1/sql");

        let context = extractor.extract_auth_context(&req);
        assert_eq!(context.catalog, DEFAULT_SCHEMA_NAME);
        assert_eq!(context.schema, DEFAULT_SCHEMA_NAME);
        assert!(context.require_auth);
    }
}
