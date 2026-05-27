# Kubernetes Deployment

Reference deployment shapes for running floria on Kubernetes. floria
itself is a stateless gateway, but every interesting deployment relies
on at least one stateful peer (Redis for dedup / nonce / retry queue,
and optionally PostgreSQL for the dead-letter overlay), so the
manifests below show the StatefulSet pattern that anchors them.

## Topology

```
+----------------+        +-----------------+        +---------------+
| floria (Deploy)| -----> | redis (StatefulSet, HA) | <----+ chime / |
+----------------+        +-----------------+        |   sodmin    |
        |                                            +---------------+
        v
+----------------+
| Apple/Google/  |
|   WebPush      |
+----------------+
```

floria is deployed as a `Deployment` (3+ replicas) sitting in front of
a Redis HA pair (or a managed Redis like ElastiCache / Memorystore /
Upstash) plus an optional PostgreSQL instance for the
dead-letter overlay.

## Redis HA — StatefulSet

The simplest HA topology that floria fully supports is Redis with one
primary and one replica behind a single VIP/Sentinel. Operators using
clustered Redis can also point `redis_url` at the cluster — floria's
nonce / dedup / rate-limit / retry-queue clients all use stable hash
tags so a clustered deployment co-locates per-subject keys.

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: floria-redis
spec:
  serviceName: floria-redis
  replicas: 2
  selector:
    matchLabels: { app: floria-redis }
  template:
    metadata:
      labels: { app: floria-redis }
    spec:
      containers:
        - name: redis
          image: redis:7.4-alpine
          args: ["--maxmemory", "512mb", "--maxmemory-policy", "volatile-lru"]
          ports: [{ containerPort: 6379 }]
          volumeMounts:
            - { name: data, mountPath: /data }
  volumeClaimTemplates:
    - metadata: { name: data }
      spec:
        accessModes: [ReadWriteOnce]
        resources: { requests: { storage: 1Gi } }
```

## floria Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: floria
spec:
  replicas: 3
  selector:
    matchLabels: { app: floria }
  template:
    metadata:
      labels: { app: floria }
    spec:
      serviceAccountName: floria
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        readOnlyRootFilesystem: true
      containers:
        - name: floria
          image: floria:local        # build locally; do NOT push
          env:
            - { name: FLORIA_CONF, value: /etc/floria/floria.kdl }
            - { name: RUST_LOG, value: info }
          ports:
            - { name: http,    containerPort: 5000 }
            - { name: metrics, containerPort: 8000 }
          # The default Dockerfile HEALTHCHECK is a TCP probe. The
          # Kubernetes probes below add the HTTP /ready and /healthz
          # endpoints that floria publishes — keep both layers so a
          # half-broken process is taken out of rotation.
          readinessProbe:
            httpGet: { path: /ready,  port: http }
            initialDelaySeconds: 5
            periodSeconds: 5
            failureThreshold: 3
          livenessProbe:
            httpGet: { path: /healthz, port: http }
            initialDelaySeconds: 15
            periodSeconds: 15
            failureThreshold: 5
          startupProbe:
            tcpSocket: { port: http }
            failureThreshold: 30
            periodSeconds: 2
          volumeMounts:
            - { name: config, mountPath: /etc/floria, readOnly: true }
      volumes:
        - name: config
          secret:
            secretName: floria-config
            defaultMode: 0400
```

## Probe semantics

| Probe        | Endpoint  | Purpose |
|--------------|-----------|---------|
| `startupProbe`   | TCP `:5000`        | Wait until the listener is bound |
| `readinessProbe` | HTTP `/ready`      | Returns 200 only when Redis + audit sinks are reachable |
| `livenessProbe`  | HTTP `/healthz`    | Returns 200 while the tokio runtime is responsive |

Use the readiness probe — NOT the liveness probe — to gate rollouts.
A flaky Redis must temporarily remove the pod from service rather than
restart-loop it (which would erase in-memory dedup, nonce store, and
retry queue caches faster than they can refill).

## Rolling restart

`rollout restart deployment/floria` is safe — the retry queue worker
flushes its in-flight batch before the SIGTERM grace window ends, and
the dedup cache is rebuilt from Redis on first request. Keep
`terminationGracePeriodSeconds` at least 2x your retry queue
`poll_interval_ms` so an in-flight batch can complete.
