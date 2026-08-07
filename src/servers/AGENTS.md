# servers — Agent & Contributor Guide

Navigation map for `src/servers`. Repo-wide invariants:
[`.agents/architecture-invariants.md`](../../.agents/architecture-invariants.md).

`servers` owns network listeners and protocol translation. Database behavior is
provided through handler traits, mostly implemented by `frontend`.

## Module map

| Area | Path | Entry point |
| --- | --- | --- |
| Lifecycle | `src/servers/src/server.rs` | Shared `Server` trait |
| Handler boundary | `src/servers/src/query_handler.rs`, `src/servers/src/query_handler/` | Protocol-independent handler traits |
| gRPC / Flight | `src/servers/src/grpc.rs`, `src/servers/src/grpc/` | gRPC services, auth, cancellation, builders |
| HTTP | `src/servers/src/http.rs`, `src/servers/src/http/` | Routes, middleware, protocol endpoints, output formats |
| SQL protocols | `src/servers/src/mysql.rs`, `src/servers/src/mysql/`, `src/servers/src/postgres.rs`, `src/servers/src/postgres/` | MySQL/PostgreSQL servers and type conversion |
| Observability protocols | `src/servers/src/prom_remote_write/`, `src/servers/src/prom_store.rs`, `src/servers/src/prometheus.rs`, `src/servers/src/otlp/`, `src/servers/src/otel_arrow.rs` | Prometheus and OpenTelemetry conversion |
| Log / metric ingest | `src/servers/src/influxdb.rs`, `src/servers/src/elasticsearch.rs`, `src/servers/src/opentsdb/`, `src/servers/src/http/loki.rs`, `src/servers/src/http/splunk.rs`, `src/servers/src/http/jaeger.rs` | Line-protocol and log ingest endpoints |
| Row building / pipeline | `src/servers/src/row_writer.rs`, `src/servers/src/prom_row_builder.rs`, `src/servers/src/pipeline.rs` | Shared conversion into insert requests |
| Resources / TLS | `src/servers/src/request_memory_limiter.rs`, `src/servers/src/tls.rs`, `src/servers/src/addrs.rs` | Memory admission, TLS, listener addresses |

## Change coupling

- Handler trait changes require matching frontend and mock implementations.
- gRPC wire changes start in `greptime-proto`; update builders and handlers here
  after bumping it.
- Auth or `QueryContext` changes must cover HTTP, gRPC, MySQL, and PostgreSQL
  entry points.
- New protocols or externally visible routes also require frontend service and
  configuration wiring.

## Testing

```bash
cargo nextest run -p servers
```

Keep protocol translation here and permissions/database behavior in frontend.
