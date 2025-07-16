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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Query, State};
use axum::Extension;
use common_catalog::parse_catalog_and_schema_from_db_string;
use common_telemetry::tracing;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use session::context::{Channel, QueryContext};

use crate::error::{InvalidParameterSnafu, Result};
use crate::http::result::csv_result::{CsvResponse, TsvResponse};
use crate::http::result::error_result::ErrorResponse;
use crate::http::result::json_result::JsonResponse;
use crate::http::{ApiState, HttpResponse, ResponseFormat};

const SUFFIX_WITH_NAMES_AND_TYPES: &str = "withnamesandtypes";
const SUFFIX_WITH_NAMES: &str = "withnames";
const SUFFIX_COMPACT: &str = "compact";
const SUFFIX_STRINGS: &str = "strings";
const SUFFIX_EACHROW: &str = "eachrow";

#[derive(Debug, Default, Clone)]
pub struct ClickhouseTypeSuffixJson {
    pub is_compact: bool,
    pub is_strings: bool,
    pub is_eachrow: bool,
}

#[derive(Debug, Default, Clone)]
pub struct ClickhouseSuffix {
    pub headers: usize,
    pub json: Option<ClickhouseTypeSuffixJson>,
}

/// ClickHouse foramt type
#[derive(Debug, Default, Clone)]
pub struct ClickhouseFormatType {
    pub fmt: ResponseFormat,
    pub suffixes: ClickhouseSuffix,
}

fn try_remove_suffix<'a>(name: &'a str, suffix: &str) -> (&'a str, bool) {
    if name.ends_with(suffix) {
        (&name[0..(name.len() - suffix.len())], true)
    } else {
        (name, false)
    }
}

impl ClickhouseFormatType {
    pub fn parse_clickhouse_format(name: &str) -> Result<ClickhouseFormatType> {
        let lower = name.to_lowercase();

        let mut suffixes = ClickhouseSuffix::default();

        let (mut base, mut ok) = try_remove_suffix(&lower, SUFFIX_WITH_NAMES_AND_TYPES);
        if ok {
            suffixes.headers = 2;
        } else {
            (base, ok) = try_remove_suffix(base, SUFFIX_WITH_NAMES);
            if ok {
                suffixes.headers = 1;
            }
        }

        if base.starts_with("json") {
            let mut json = ClickhouseTypeSuffixJson::default();
            (base, json.is_eachrow) = try_remove_suffix(base, SUFFIX_EACHROW);
            (base, json.is_strings) = try_remove_suffix(base, SUFFIX_STRINGS);
            (base, json.is_compact) = try_remove_suffix(base, SUFFIX_COMPACT);
            if base != "json" {
                return InvalidParameterSnafu {
                    reason: format!("Invalid clickhouse format: {base}"),
                }
                .fail();
            } else {
                if !json.is_compact && suffixes.headers != 0 {
                    return InvalidParameterSnafu {
                        reason: format!("Invalid clickhouse format: {base}"),
                    }
                    .fail();
                }
                if json.is_eachrow {
                    base = "ndjson"
                }
                suffixes.json = Some(json);
            }
        }

        // Default is `tsv`
        let fmt = ResponseFormat::parse(base).unwrap_or(ResponseFormat::Tsv);

        Ok(ClickhouseFormatType { fmt, suffixes })
    }
}

/// ClickHouse HTTP request parameters
// accept all clickhouse params, so they do not go to settings.
#[derive(Serialize, Deserialize, Debug)]
pub struct StatementHandlerParams {
    query: Option<String>,
    #[allow(unused)]
    query_id: Option<String>,
    database: Option<String>,
    default_format: Option<String>,
    compress: Option<u8>,
    #[allow(unused)]
    decompress: Option<u8>,
    #[allow(unused)]
    buffer_size: Option<usize>,
    #[allow(unused)]
    max_result_bytes: Option<usize>,
    #[allow(unused)]
    wait_end_of_query: Option<u8>,
    #[allow(unused)]
    session_id: Option<String>,
    #[allow(unused)]
    session_check: Option<u8>,
    #[allow(unused)]
    session_timeout: Option<u64>,
    // in secs
    #[allow(unused)]
    with_stacktrace: Option<u8>,
    #[serde(flatten)]
    settings: HashMap<String, String>,
}

impl StatementHandlerParams {
    pub fn compress(&self) -> bool {
        self.compress.unwrap_or(0u8) == 1u8
    }

    pub fn query(&self) -> String {
        self.query.clone().unwrap_or_default()
    }
}

/// Helper macro which try to evaluate the expression and return its results.
/// If the evaluation fails, return a `HttpResponse` early.
macro_rules! try_call_return_response {
    ($handle: expr) => {
        match $handle {
            Ok(res) => res,
            Err(err) => {
                let msg = err.to_string();
                todo!();
            }
        }
    };
}

/// Handler to execute clickhouse SQL
#[axum_macros::debug_handler]
pub async fn clickhouse_ping_handler() -> String {
    "OK.\n".to_string()
}

/// Handler to execute clickhouse SQL
#[axum_macros::debug_handler]
#[tracing::instrument(skip_all, fields(protocol = "http", request_type = "clickhouse"))]
pub async fn sql(
    State(state): State<ApiState>,
    Query(params): Query<StatementHandlerParams>,
    Extension(mut query_ctx): Extension<QueryContext>,
    headers: HeaderMap,
) -> HttpResponse {
    let start = Instant::now();
    let sql_handler = &state.sql_handler;
    if let Some(db) = &params.database {
        let (catalog, schema) = parse_catalog_and_schema_from_db_string(db);
        query_ctx.set_current_catalog(&catalog);
        query_ctx.set_current_schema(&schema);
    }

    query_ctx.set_channel(Channel::Http);

    let query_ctx = Arc::new(query_ctx);
    let db = query_ctx.get_db_string();

    let _timer = crate::metrics::METRIC_HTTP_SQL_ELAPSED
        .with_label_values(&[db.as_str()])
        .start_timer();

    let default_format = try_call_return_response!(get_default_format(&params, &headers));
    let sql = params.query();

    let result = if let Some((status, msg)) =
        crate::http::handler::validate_schema(sql_handler.clone(), query_ctx.clone()).await
    {
        Err((status, msg))
    } else {
        Ok(sql_handler.do_query(&sql, query_ctx.clone()).await)
    };

    let outputs = match result {
        Err((status, msg)) => {
            return HttpResponse::Error(
                ErrorResponse::from_error_message(status, msg)
                    .with_execution_time(start.elapsed().as_millis() as u64),
            );
        }
        Ok(outputs) => outputs,
    };

    println!("{:?}", default_format);

    let mut resp = match default_format.fmt {
        ResponseFormat::Csv => CsvResponse::csv_from_output(outputs).await,
        ResponseFormat::Tsv => {
            let resp = TsvResponse::tsv_from_output(outputs).await;
            println!("resp: {:?}", resp);
            resp
        },
        ResponseFormat::Json => JsonResponse::from_output(outputs).await,
        _ => todo!(),
    };

    resp.with_execution_time(start.elapsed().as_millis() as u64)
}

fn get_default_format(
    params: &StatementHandlerParams,
    headers: &HeaderMap,
) -> Result<ClickhouseFormatType> {
    let name = match &params.default_format {
        None => match headers.get("X-CLICKHOUSE-FORMAT") {
            None => "TSV",
            Some(_) => {
                return InvalidParameterSnafu {
                    reason: "value of X-CLICKHOUSE-FORMAT is not string",
                }
                .fail()
            }
        },
        Some(s) => s,
    };
    ClickhouseFormatType::parse_clickhouse_format(name)
}

fn get_format_with_default(
    format: Option<String>,
    default_format: ClickhouseFormatType,
) -> Result<ClickhouseFormatType> {
    match format {
        None => Ok(default_format),
        Some(name) => ClickhouseFormatType::parse_clickhouse_format(&name),
    }
}
