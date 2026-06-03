# Minimal Floria Example

This directory contains the smallest end-to-end shape demo for starting floria
with one push provider config and sending one canonical `ck.push.notify`
request.

Files:

- `minimal.kdl`: minimal KDL config with one FCM HTTP v1 pushkin entry
- `minimal.notify.request.json`: canonical `/_cokret/edge/push/notify` request body
- `compose.yml`: Docker Compose example for a fuller local deployment
- `reverse-proxy/`: nginx and Caddy samples for TLS termination + mTLS trust root chain (see [`docs/en/reverse-proxy.md`](../docs/en/reverse-proxy.md))

Run locally:

```sh
FLORIA_CONF=examples/minimal.kdl cargo run
```

Send the example request from another shell:

```sh
curl -X POST http://127.0.0.1:5000/_cokret/edge/push/notify \
  -H "content-type: application/json" \
  --data @examples/minimal.notify.request.json
```

Notes:

- Replace `project_id` and `service_account_file` in `minimal.kdl` with real
  Firebase HTTP v1 credentials before expecting provider delivery success.
- Replace `push_key` in `minimal.notify.request.json` with a real device token.
- The JSON file is meant to demonstrate the active `ck.push.notify` contract
  shape even before real credentials are wired up.
