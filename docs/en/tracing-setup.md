# Tracing Setup (OpenTelemetry)

floria emits OTLP gRPC spans when `metrics.opentracing.enabled=true`
in `floria.kdl`. Spans are exported to any OTLP-compatible collector
— this doc shows the three most common targets (Jaeger, Tempo,
Datadog) via the upstream `otel/opentelemetry-collector-contrib`
container.

## Gateway-side config

```kdl
metrics {
  opentracing {
    enabled true
    endpoint "http://otel-collector:4317"
    service_name "floria"
    sample_rate 0.1      # 10% trace sampling
    timeout_seconds 10
  }
}
```

`sample_rate` is a TraceIdRatioBased sampler — pick a value that fits
your provider RPS and trace storage budget. Production deployments
typically run between 0.01 and 0.1.

## Collector — Jaeger

```yaml
receivers:
  otlp:
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }
exporters:
  otlp/jaeger:
    endpoint: jaeger-collector.observability.svc.cluster.local:4317
    tls: { insecure: true }
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp/jaeger]
```

## Collector — Grafana Tempo

```yaml
receivers:
  otlp:
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }
exporters:
  otlp/tempo:
    endpoint: tempo.observability.svc.cluster.local:4317
    tls: { insecure: true }
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp/tempo]
```

## Collector — Datadog

```yaml
receivers:
  otlp:
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }
processors:
  batch:
    timeout: 5s
exporters:
  datadog:
    api:
      site: datadoghq.com
      key: ${env:DD_API_KEY}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [datadog]
```

## Useful span attributes

floria attaches these to every `/notify` span:

| Attribute | Value |
|-----------|-------|
| `http.method` | `POST` |
| `http.target` | `/_arkret/edge/push/notify` |
| `floria.request_id` | per-request UUID |
| `floria.origin_service_did` | resolved origin DID |
| `floria.app_id` | target app id |
| `floria.realm_id` | realm scope (always present) |
| `floria.circle_id` | circle scope (when set; respects detailed-labels toggle) |
| `floria.dispatch_outcome` | `accepted` / `rejected` / `retryable` / `failed` |

Provider dispatch is a child span named `pushkin.dispatch` with the
provider name and the same dispatch outcome.
