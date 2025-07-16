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

//! gRPC-specific authentication credential extraction.

use common_base::secrets::{ExposeSecret, SecretString};
use tonic::body::BoxBody;

use crate::common::auth::{AuthContext, CredentialExtractor, Credentials};
use crate::http::authorize::{extract_catalog_and_schema, extract_username_and_password};

/// gRPC-specific credential extractor.
#[derive(Default)]
pub struct GrpcCredentialExtractor;

impl GrpcCredentialExtractor {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }
}

impl CredentialExtractor<http::Request<BoxBody>> for GrpcCredentialExtractor {
    type Error = crate::error::Error;

    fn extract_credentials(
        &self,
        req: &http::Request<BoxBody>,
    ) -> std::result::Result<Credentials, Self::Error> {
        // gRPC uses HTTP-style authentication headers
        match extract_username_and_password(req) {
            Ok((username, password)) => Ok(Credentials::Basic {
                username,
                password: SecretString::new(Box::new(password.expose_secret().to_string())),
            }),
            Err(_) => Ok(Credentials::None),
        }
    }

    fn extract_auth_context(&self, req: &http::Request<BoxBody>) -> AuthContext {
        let (catalog, schema) = extract_catalog_and_schema(req);

        AuthContext {
            catalog,
            schema,
            require_auth: self.requires_auth(req),
        }
    }

    fn requires_auth(&self, _req: &http::Request<BoxBody>) -> bool {
        // gRPC always requires authentication if a user provider is configured
        // The actual check is done at the middleware level
        true
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use common_base::secrets::ExposeSecret;
    use http::Request;
    use tonic::body::BoxBody;

    use super::*;

    fn create_test_request() -> Request<BoxBody> {
        Request::builder()
            .method(http::Method::POST)
            .uri("/test")
            .body(BoxBody::default())
            .unwrap()
    }

    #[test]
    fn test_extract_credentials_basic_auth() {
        let mut req = create_test_request();

        // Add basic auth header (user:pass)
        let auth_value = BASE64_STANDARD.encode("user:pass");
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Basic {}", auth_value)).unwrap(),
        );

        let extractor = GrpcCredentialExtractor::new();
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
        let req = create_test_request();
        let extractor = GrpcCredentialExtractor::new();
        let credentials = extractor.extract_credentials(&req).unwrap();

        assert!(matches!(credentials, Credentials::None));
    }

    #[test]
    fn test_requires_auth() {
        let req = create_test_request();
        let extractor = GrpcCredentialExtractor::new();
        assert!(extractor.requires_auth(&req));
    }

    #[test]
    fn test_extract_auth_context() {
        let req = create_test_request();
        let extractor = GrpcCredentialExtractor::new();
        let context = extractor.extract_auth_context(&req);

        // Default context should be returned
        assert!(!context.catalog.is_empty());
        assert!(!context.schema.is_empty());
        assert!(context.require_auth);
    }
}
