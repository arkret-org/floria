# 反向代理与 TLS 信任根

floria 设计为始终运行在 TLS 终结的反向代理之后。Gateway 自身不监听
`:443`，也不校验客户端证书链 —— 它依赖代理完成以下三件事：

1. 为 `push.example.com` 终结 TLS。
2. 用固化的**信任根链**（允许 tenant 接入的 CA 合集）校验调用方
   客户端证书。
3. 把解析后的证书字段以 HTTP header 的形式转发给 floria，由
   `notify_auth` 与服务主体绑定。

这种分层把链验证集中在一个被审计良好的组件（nginx / Caddy / Envoy /
云 LB），让 floria 保持纯 HTTP server。代价是代理和 gateway 必须就
header 名称、格式以及**信任池权威源**保持一致。

## floria 绑定的 header

| Header | 默认配置键 | 期望值 |
|---|---|---|
| `X-Client-Certificate-Verified` | `notify_auth.mtls_verified_header` | 链验证通过时取 `1`、`true`、`yes`、`success`、`verified` 任一；其它情况 floria fail-closed |
| `X-Client-Certificate-SHA256` | `notify_auth.mtls_fingerprint_header` | 客户端证书 SHA-256 指纹的小写十六进制（是否带 `:` 分隔符均可） |
| `X-Client-Certificate-Subject` | `notify_auth.mtls_subject_dn_header` | 证书 Subject DN（RFC 2253 / RFC 4514 形式） |
| `X-Client-Certificate-SAN` | `notify_auth.mtls_subject_alt_names_header` | 逗号分隔的 SAN 列表（例如 `DNS:sync.example.com,URI:did:web:sync.example.com`） |

Subject DN 在 gateway 侧做空白合并 + 大小写不敏感比较；SAN 做精确
逗号切分 + 大小写不敏感匹配。

## 信任根的归属

反向代理持有信任根链。floria 的逐 principal 配置
（`mtls_cert_fingerprints`、`mtls_subject_dn`、
`mtls_subject_alt_names`）是第二道关卡 —— 它锁定单个服务主体允许使用
的具体证书，但无法在 CA 被攻陷时自动止损。把代理的信任池视作一类
密钥：固化到已知路径，并按 provider 凭据的方式轮换（参考
[credential-rotation.md](./credential-rotation.md)）；不要把系统
CA bundle 直接当成信任池。

## 参考配置

参考样例位于
[examples/reverse-proxy/](../../examples/reverse-proxy/)：

- [`nginx.conf.sample`](../../examples/reverse-proxy/nginx.conf.sample) ——
  nginx 使用 `ssl_client_certificate` + `ssl_verify_client
  optional_no_ca`，转发 4 条 mTLS header，并清除调用方伪造的旧值。
- [`Caddyfile.sample`](../../examples/reverse-proxy/Caddyfile.sample) ——
  Caddy 使用 `client_auth.trust_pool` 与 `mode require_and_verify`，
  用 `{tls_client_*}` placeholder 填充 header。

两份样例都把 `/health` 和 `/ready` 当作匿名探针处理，并清除调用方
伪造的 mTLS header，使上游调用者无法伪造一份"已验证"的 mTLS 上下文。

## 运维提示

- **健康探针**：`/health` 与 `/ready` 必须能在没有客户端证书的情况
  下访问。floria 在这两个端点不查询 `notify_auth`，因此代理应直接放行
  并不要转发 mTLS header。
- **SAN 提取**：nginx 通过 `$ssl_client_s_dn` 暴露 Subject DN，但
  不会原生地把 SAN 列表拼成单个字符串。请用 `njs`、`lua` 或上游过滤
  器把 SAN 列表拼接为逗号分隔后再转发。
- **production_mode 联动**：开启
  `http.notify_auth.production_mode = true` 后，每一个 principal 都
  必须通过 HTTP Message Signature **或** mTLS 完成认证，并且配置中
  的明文 notify bearer token 会被拒绝。配合本代理方案后，绕过代理的
  请求即使到达 gateway 也无法伪造已验证的 mTLS 上下文 —— 因为指纹、
  DN、SAN 都不会与 principal allowlist 匹配。
- **自定义 header 名**：若代理使用非默认 header 名，请在 floria 配
  置 `http.notify_auth.mtls_verified_header` /
  `mtls_fingerprint_header` / `mtls_subject_dn_header` /
  `mtls_subject_alt_names_header` 中同步覆盖。
- **直连 TLS 终结**：不支持。若必须由 floria 自身终结 TLS，请把它部
  署在 localhost-only 的代理之后（例如 `127.0.0.1` 的 nginx），使代
  理语义依然成立。
