# Observability

## Structured application logs

The API and worker emit structured logs with event names, request or job
correlation fields where available, and safe error categories. Prompt bodies,
provider credentials, and response content are not log fields. Keep the
container log destination under the deployment's access, retention, and backup
controls. LLM prompt and response audit artifacts use the separate encrypted
artifact store and its audited content-read endpoint.

## Prometheus scrape endpoint

Set `METRICS_ENABLED=true` to expose `GET /metrics` in Prometheus text format.
It is enabled by default for local development. Set it to `false` to return
404. The route requires the `metrics` capability, which is granted to the
configured local `operator` and `admin` roles. When audit storage is available,
protected API request start and completion events are written to the audit log
for each scrape. If the start event cannot be persisted, the read-only metrics
scrape continues so it can report database unavailability; that condition is
recorded as a structured warning, and the completion event is still attempted.
Other protected API requests continue to fail closed when their start event
cannot be written.

The current local role configuration is not a hosted identity provider. Keep
the API bound to a trusted interface and restrict scrape access at the network
boundary. Do not expose this endpoint publicly until hosted authentication and
deployment network policy are approved and implemented.

Available metric families:

| Metric | Type | Meaning |
|---|---|---|
| `counterstrike_http_requests_total` | Counter | Completed requests by method, route template, and status. |
| `counterstrike_http_request_duration_seconds` | Histogram | Request latency by the same bounded labels. |
| `counterstrike_database_up` | Gauge | `1` when the database aggregate snapshot succeeds; otherwise `0`. |
| `counterstrike_jobs` | Gauge | Persisted job count by bounded status. |
| `counterstrike_llm_calls` | Gauge | Persisted LLM call count by bounded outcome. |
| `counterstrike_llm_tokens` | Gauge | Persisted input/output token totals by outcome. |
| `counterstrike_llm_cost_known_usd` | Gauge | Persisted known USD cost by outcome; excludes unknown and non-USD cost. |

HTTP metrics use Starlette route templates instead of raw paths. Database
metrics do not include request IDs, job or call IDs, actor names, model names,
advisory identifiers, asset identifiers, prompt versions, or prompt/response
content. The database-backed metrics are aggregate snapshots; they are not a
substitute for the detailed filtered LLM usage and audit APIs. Token and
known-cost gauges reflect persisted LLM call records, and can change if records
are removed under an approved retention policy.

## Scrape configuration example

For a local Prometheus instance that can reach the API:

```yaml
scrape_configs:
  - job_name: counterstrike
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:8000"]
```

The API must run with a local identity authorized for `metrics`. This example
does not configure authentication or make the endpoint safe for remote
exposure. Production scrape authentication, durable time-series storage,
alerting rules, and retention remain deployment decisions tracked under
`OPS-02` and `OPS-06`.
