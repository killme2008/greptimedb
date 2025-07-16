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

//! Common authentication provider implementations for all protocols.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use auth::{UserInfoRef, UserProviderRef};
use common_error::ext::ErrorExt;
use common_telemetry::debug;
use session::context::{Channel, QueryContextBuilder};
use snafu::ResultExt;

use super::{AuthContext, Authenticator, Credentials};
use crate::error::{AuthSnafu, Result};

/// Cached authentication result with expiration.
#[derive(Clone)]
struct CachedAuth {
    user_info: UserInfoRef,
    expires_at: Instant,
}

impl CachedAuth {
    fn new(user_info: UserInfoRef, ttl: Duration) -> Self {
        Self {
            user_info,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Authentication provider with optional caching for performance.
pub struct CachingAuthProvider {
    user_provider: Option<UserProviderRef>,
    cache: Arc<RwLock<HashMap<String, CachedAuth>>>,
    cache_ttl: Duration,
    cache_enabled: bool,
}

impl CachingAuthProvider {
    /// Create a new authentication provider without caching.
    pub fn new(user_provider: Option<UserProviderRef>) -> Self {
        Self {
            user_provider,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(0),
            cache_enabled: false,
        }
    }

    /// Create a new authentication provider with caching enabled.
    pub fn with_cache(user_provider: Option<UserProviderRef>, cache_ttl: Duration) -> Self {
        Self {
            user_provider,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            cache_enabled: true,
        }
    }

    /// Generate a cache key for the given credentials and context.
    fn cache_key(credentials: &Credentials, context: &AuthContext) -> Option<String> {
        match credentials {
            Credentials::Basic { username, .. } => Some(format!(
                "{}:{}:{}",
                username, context.catalog, context.schema
            )),
            // Don't cache token-based auth for security reasons
            Credentials::Token { .. } | Credentials::None => None,
        }
    }

    /// Check if a cached authentication result exists and is still valid.
    fn get_cached(&self, key: &str) -> Option<UserInfoRef> {
        if !self.cache_enabled {
            return None;
        }

        let cache = self.cache.read().ok()?;
        let cached = cache.get(key)?;

        if cached.is_expired() {
            debug!("Authentication cache entry expired for key: {}", key);
            return None;
        }

        debug!("Authentication cache hit for key: {}", key);
        Some(cached.user_info.clone())
    }

    /// Store an authentication result in the cache.
    fn cache_result(&self, key: String, user_info: UserInfoRef) {
        if !self.cache_enabled {
            return;
        }

        if let Ok(mut cache) = self.cache.write() {
            // Clean up expired entries periodically (simple approach)
            if cache.len() > 1000 {
                cache.retain(|_, v| !v.is_expired());
            }

            let cached = CachedAuth::new(user_info, self.cache_ttl);
            debug!("Cached authentication result for key: {}", key);
            cache.insert(key, cached);
        }
    }

    /// Perform authentication without caching.
    async fn authenticate_uncached(
        &self,
        credentials: Credentials,
        context: &AuthContext,
    ) -> Result<UserInfoRef> {
        if !context.require_auth {
            return Ok(auth::userinfo_by_name(None));
        }

        let user_provider =
            self.user_provider
                .as_ref()
                .ok_or_else(|| crate::error::Error::Internal {
                    err_msg: "User provider not configured".to_string(),
                })?;

        let (identity, password) = match &credentials {
            Credentials::Basic { username, password } => (
                auth::Identity::UserId(username, None),
                auth::Password::PlainText(password.clone()),
            ),
            Credentials::Token { .. } => {
                return Err(crate::error::Error::Internal {
                    err_msg: "Token authentication not yet supported".to_string(),
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

#[async_trait]
impl Authenticator for CachingAuthProvider {
    type Error = crate::error::Error;

    async fn authenticate(
        &self,
        credentials: Credentials,
        context: &AuthContext,
    ) -> std::result::Result<UserInfoRef, Self::Error> {
        // Try cache first if enabled
        if let Some(cache_key) = Self::cache_key(&credentials, context) {
            if let Some(cached_user) = self.get_cached(&cache_key) {
                return Ok(cached_user);
            }

            // Cache miss - authenticate and cache result
            let user_info = self.authenticate_uncached(credentials, context).await?;
            self.cache_result(cache_key, user_info.clone());
            Ok(user_info)
        } else {
            // No caching for this credential type
            self.authenticate_uncached(credentials, context).await
        }
    }
}

/// Create a query context with authentication information.
pub fn create_authenticated_query_context(
    user_info: UserInfoRef,
    context: &AuthContext,
    channel: Channel,
    timezone: Option<common_time::Timezone>,
) -> session::context::QueryContextRef {
    let mut builder = QueryContextBuilder::default()
        .current_catalog(context.catalog.clone())
        .current_schema(context.schema.clone())
        .channel(channel);

    if let Some(tz) = timezone {
        builder = builder.timezone(tz);
    }

    let query_ctx = builder.build();
    query_ctx.set_current_user(user_info);
    std::sync::Arc::new(query_ctx)
}

/// Extract catalog and schema from a database string in the format "catalog.schema".
/// Falls back to defaults if parsing fails.
pub fn parse_catalog_and_schema(
    db_string: &str,
    default_catalog: &str,
    default_schema: &str,
) -> (String, String) {
    let parts: Vec<&str> = db_string.splitn(2, '.').collect();
    if parts.len() == 2 {
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (default_catalog.to_string(), default_schema.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use common_base::secrets::SecretString;

    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let credentials = Credentials::Basic {
            username: "user".to_string(),
            password: SecretString::new(Box::new("pass".to_string())),
        };
        let context = AuthContext {
            catalog: "catalog1".to_string(),
            schema: "schema1".to_string(),
            require_auth: true,
        };

        let key = CachingAuthProvider::cache_key(&credentials, &context);
        assert_eq!(key, Some("user:catalog1:schema1".to_string()));

        // Token credentials should not generate cache keys
        let token_credentials = Credentials::Token {
            token: SecretString::new(Box::new("token".to_string())),
        };
        let token_key = CachingAuthProvider::cache_key(&token_credentials, &context);
        assert_eq!(token_key, None);
    }

    #[test]
    fn test_cached_auth_expiration() {
        let user_info = auth::userinfo_by_name(Some("test".to_string()));
        let ttl = Duration::from_millis(100);
        let cached = CachedAuth::new(user_info, ttl);

        assert!(!cached.is_expired());

        std::thread::sleep(Duration::from_millis(150));
        assert!(cached.is_expired());
    }

    #[test]
    fn test_parse_catalog_and_schema() {
        // Valid format
        let (catalog, schema) = parse_catalog_and_schema("cat.sch", "default_cat", "default_sch");
        assert_eq!(catalog, "cat");
        assert_eq!(schema, "sch");

        // Invalid format - should use defaults
        let (catalog, schema) = parse_catalog_and_schema("invalid", "default_cat", "default_sch");
        assert_eq!(catalog, "default_cat");
        assert_eq!(schema, "default_sch");
    }
}
