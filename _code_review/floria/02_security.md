# floria 安全审计报告（02_security）

> 被审项目：`D:/Works/contrix-dev/floria`（push 推送网关）
> 协议锚点：`D:/Works/contrix-dev/contrix-spec/spec/v1` + `_code_review/_reference/spec_digest.md`
> 审查维度：安全漏洞与需加强项（仅防御性审查）

## 审查范围

实际通读 / 检索的文件（均为主 `src/` 树，排除 `.claude/worktrees/`、`target/`）：

- `src/auth.rs`（全文 1516 行：HTTP Message Signature 校验、mTLS profile、bearer、nonce 防重放、query-string auth 拒绝、URL 凭据脱敏）
- `src/nonce_store.rs`（全文：内存 / Redis nonce store、fail-open/closed 策略）
- `src/egress.rs`（全文：SSRF 出站 URL/IP 校验）
- `src/config.rs`（通读 1-1628，含 `NotifyAuthConfig`/`NotifyServicePrincipalConfig`/`NotifyRetryQueueConfig`/`StorageConfig`/各 Redis 后端配置与 `production_mode` 校验；1629-2907 为 JSON-schema 输出与测试，抽样检索）
- `src/media.rs`（全文：CXP-0010 媒体 token 绑定、TTL/issuer/focus 守卫、participant_binding canonical bytes）
- `src/audit.rs`（HTTP/JSONL audit sink，offset 100-188）
- `src/retry_queue.rs`（AEAD 封装 `seal`/`open`、nonce 生成、deadletter PG overlay，40-154、724-735）
- `src/rate_limit.rs`（内存 / Redis 限流、fail-open/closed、并发闸门，60-389）
- `src/pushkin/custom.rs`（自定义 webhook provider：URL 校验、HMAC、HTTP client，80-355）
- `src/pushkin/webpush.rs`（VAPID、allowed_endpoints、egress 校验，125-164、280-489）
- `src/service/internal.rs`（全文：内部端点 bearer 鉴权）
- `src/service/notify.rs`（plaintext 守卫 / blind-profile gate 检索，37-912）
- `src/observability.rs`（`unsafe` 使用点 270-288）
- `Cargo.toml`（reqwest 0.13.2 / isahc 1.7.2 / web-push 0.11 / sentry 0.48 等出站依赖）

复验命令（在 `floria/` 下执行）：
```
rg -n "candidate == token|eq_ignore_ascii_case" src/auth.rs
rg -n "to_socket_addrs|validate_resolved_ip|blocked_ipv4|blocked_ipv6" src/egress.rs
rg -n "allow_plaintext_metadata: true|<anonymous>" src/auth.rs
rg -n "bind_bearer_to_origin_did" src/auth.rs src/config.rs
rg -n "RedisFailurePolicy|failing open|Permissive" src/nonce_store.rs src/rate_limit.rs
rg -n "unsafe" src/
```

**覆盖说明（优先级）**：优先覆盖了鉴权/签名/防重放（`auth.rs`/`nonce_store.rs`）、SSRF 出站（`egress.rs` 及各 provider 调用点）、密钥/凭据处理（`config.rs`/`retry_queue.rs`/`media.rs`）、fail-open 策略（Redis 后端）。**未逐行覆盖**：`pushkin/{apns,fcm,huawei,xiaomi,oppo,vivo,honor,jpush,android}.rs` 各厂商签名细节仅做出站/redirect 抽样（已确认均 `validate_http_url_for_egress` + `reqwest_support.rs` 统一 client）、`broadcast.rs`/`circuit_breaker.rs`/`deactivation.rs`/`push_contact_cache.rs` 业务逻辑、`config.rs` 1629-2907 的 schema 生成、全部 `#[cfg(test)]` 块。

## 结论摘要

floria 的安全工程化程度较高：HTTP Message Signature 强制覆盖关键组件 + content-digest 重算 + nonce 防重放、SSRF 黑名单 + 默认拒绝私网、mTLS 多维绑定、`production_mode` 收紧弱凭据、SQL 标识符白名单、URL 凭据脱敏、media 签名 helper fail-closed、内部端点未配置即 503。未发现 P0/P1 级可直接利用的认证绕过或密钥明文落盘。

记录 **5** 条需加强项：最高级别 **P2**。其中 2 条 P2（bearer 比较非恒定时间；SSRF DNS-rebinding TOCTOU），1 条 P2/P3 边界（Redis 防重放/限流默认 fail-open），2 条 P3（匿名调用默认 plaintext-eligible;`bind_bearer_to_origin_did` 默认关闭的多租户隔离缺口）。均为纵深防御/加固类，非可直接利用的高危绕过。

---

## 问题 1：bearer / nonce-fingerprint 凭据比较非恒定时间（timing 侧信道）

**严重级别**：P2

**证据**：
- `src/auth.rs:988-996` — `bearer_state` 用 `candidates.iter().any(|candidate| candidate == token)` 做明文 bearer 比较，`String == &str` 是短路逐字节比较，非恒定时间。
- `src/auth.rs:1014-1020` — `bearer_token_hash_matches` 用 `bearer_token_sha256_hex(token).eq_ignore_ascii_case(candidate)`；`eq_ignore_ascii_case` 同样短路，非恒定时间。
- 对照：项目已依赖 `subtle`（`Cargo.lock` 命中），但 `src/` 内未使用恒定时间比较（`rg -n "ct_eq|ConstantTimeEq|subtle" src/` 无结果）。
- 该比较用于 `/notify` 网关级 bearer（`auth.rs:322`）、per-principal bearer（`auth.rs:278-309`）、`/api/v1/internal/*` 内部 bearer（`service/internal.rs:63-67`）。

**影响**：明文 bearer 路径下，攻击者理论上可通过测量响应时间逐字节恢复服务令牌；hash 路径因比较的是攻击者已知输入的 SHA-256，泄露价值低。实际可利用性受网络抖动、salvo/tokio 调度噪声压制，且 `production_mode` 已禁用明文 bearer（`config.rs:678-682` 拒绝 principal 明文 `bearer_tokens`、`config.rs:701-705` 拒绝网关级 `bearer_tokens`），仅在非 production 部署的明文 bearer 上有窗口，故定 P2。

**建议**：对令牌比较改用恒定时间比较（`subtle::ConstantTimeEq` 或先 SHA-256 再 `ct_eq`）。最简做法：始终把候选与输入都 SHA-256 后用 `subtle` 比较，统一明文/hash 两条路径。

**复验结论**：已重新打开 `auth.rs:988-996`、`1014-1020` 核对，比较运算符与方法名属实；已确认 `src/` 无恒定时间比较使用。属实保留。

---

## 问题 2：SSRF 出站校验存在 DNS-rebinding TOCTOU（校验时解析与连接时解析分离）

**严重级别**：P2

**证据**：
- `src/egress.rs:40-46` — `validate_url_for_egress` 对主机名调用 `(host, port).to_socket_addrs()` 解析并逐个 `validate_resolved_ip`。
- `src/egress.rs:11-15` — `validate_http_url_for_egress` 只返回 `Url`（字符串/主机名），**不返回已解析的 IP**。
- 调用点把该 `Url`（仍含主机名）交给 reqwest/isahc：`src/pushkin/custom.rs:221`→`257`（`self.client.post(parsed_url)`）、`src/audit.rs:134`→`136`、`src/pushkin/webpush.rs:469-481`。reqwest/isahc 在连接时会**再次**做 DNS 解析，与 egress.rs 的解析是两次独立查询。

**影响**：攻击者控制的 DNS（自定义 pushkin URL、webpush endpoint、可配置的 audit endpoint 等出站目标）可在校验解析时返回公网 IP、连接解析时返回 `169.254.169.254` / `127.0.0.1` / 内网地址（DNS rebinding），绕过 `blocked_ipv4`/`blocked_ipv6` 黑名单访问云元数据/内网。缓解因素：自定义 pushkin URL 与 webpush allowed_endpoints 来自运维配置（`config.rs` / app config），非完全任意外部输入；redirect 已禁用（`custom.rs:339`、reqwest audit `audit.rs:117`、isahc 默认不跟随）。但 webpush `endpoint` 来自设备注册数据（`webpush.rs:298-309` `device.data_string("endpoint")`），攻击面更接近外部可控，故定 P2。

**建议**：消除 TOCTOU——`validate_*_for_egress` 解析后将**已校验的 IP** 固定下来并强制连接到该 IP（reqwest `resolve()` / `ClientBuilder::resolve_to_addrs`，isahc `dns_resolver` / 固定地址），或使用自定义连接器在 connect 钩子内对最终 socket addr 复检黑名单。补充黑名单缺口：当前 `blocked_ipv6` 未覆盖 NAT64 `64:ff9b::/96`、`64:ff9b:1::/48` 与 6to4 `2002::/16`（可经其封装内网 IPv4），建议一并补上或改用成熟的 `ip-network`/`ipnet` + IANA 特殊用途地址表。

**复验结论**：已重新打开 `egress.rs:11-46`、`custom.rs:221`/`257`、`webpush.rs:469-481`、`audit.rs:134-136` 核对：egress 返回主机名 `Url` 而非锁定 IP，连接由 reqwest/isahc 独立完成。TOCTOU 路径属实。IPv6 NAT64/6to4 缺口经核对 `blocked_ipv6`（`egress.rs:84-92`）确认未覆盖。属实保留。

---

## 问题 3：Redis 防重放 / 限流默认 fail-open（可用性 vs 安全的默认偏向）

**严重级别**：P2

**证据**：
- `src/nonce_store.rs:43-48` — `RedisFailurePolicy` 默认 `#[default] Permissive`。
- `src/nonce_store.rs:189-221` — Redis 连接失败 / `SET NX` 失败时，非 strict 模式 `return NonceCheck::Fresh`（fail-open，签名重放保护被静默旁路，仅 `created/expires` 窗口兜底），并有 `failing open` 警告日志。
- `src/config.rs:768` — `NotifyNonceStoreConfig` 默认 `redis_failure_policy: "permissive"`。
- 限流同构：`src/rate_limit.rs:86`（`redis` 构造默认 `Permissive`）、`src/config.rs:981`（`NotifyRateLimitConfig` 默认 `"permissive"`），`rate_limit.rs:381-389` 连接失败时非 strict 不拒绝。
- `production_mode` 校验（`config.rs:656-707`）**未**强制 nonce/限流为 strict。

**影响**：Redis 抖动 / 不可达期间，跨副本签名重放保护与限流双双失效——攻击者可在签名有效期窗口内重放 `/notify`、或在限流退化时放大请求。该行为有文档说明（`nonce_store.rs:16-19`），且 strict 选项已实现，属"默认偏可用性"的取舍而非缺陷，但生产网关默认值偏弱，定 P2。

**建议**：在 `production_mode=true` 时，若配置了 Redis nonce/限流后端，强制（或启动告警要求）`redis_failure_policy=strict`，使防重放/限流默认 fail-closed；至少在文档与样例配置中将生产推荐值标为 strict。

**复验结论**：已重新打开 `nonce_store.rs:43-48`/`189-221`、`rate_limit.rs:86`/`381-389`、`config.rs:768`/`981` 核对，默认 Permissive 与 fail-open 分支属实，`production_mode` 未联动强制 strict 经 `config.rs:656-707` 核对确认。属实保留。

---

## 问题 4：匿名调用（auth 关闭）默认被标记为 plaintext-eligible，明文元数据守卫被旁路

**严重级别**：P3

**证据**：
- `src/auth.rs:54-70` — `auth.enabled()==false` 且非 `production_mode` 时，返回 `AuthenticatedNotifyCaller { origin_service_did: "<anonymous>", allow_plaintext_metadata: true }`。
- `src/service/notify.rs:709-816` — blind-profile 的明文守卫（`reject` plaintext `content.title/body`、DID 字面量等）全部以 `if !caller.allow_plaintext_metadata { ... }` 为条件；当 `allow_plaintext_metadata=true` 时整组守卫被跳过（`notify.rs:715`、`753`、`787`）。
- 注释（`auth.rs:26-35`）确认这是为兼容现有开发环境的刻意行为。

**影响**：在 auth 未配置的部署中，任何匿名调用方都被视为 visible_notification profile，可向 provider 推送携带明文标题/正文/DID 等身份元数据，绕过 `cx.profile.push_gateway.*` 的盲化约束（spec_digest §对 plaintext-eligible service kind 的收敛）。缓解：`production_mode` 直接拒绝匿名（`auth.rs:54-65`），故仅影响 dev/未加固部署；属纵深防御缺口，定 P3。

**建议**：将匿名 fallback 的 `allow_plaintext_metadata` 改为 `false`（默认盲化），让开发环境也走盲化路径；确需明文的开发场景用显式配置开启，而非以"匿名即可明文"为默认。

**复验结论**：已重新打开 `auth.rs:54-70` 与 `notify.rs:709-816` 核对，匿名默认 `allow_plaintext_metadata:true` 与守卫的条件旁路属实。属实保留。

---

## 问题 5：`bind_bearer_to_origin_did` 默认关闭——网关级 bearer 可经 origin-DID 头冒充任意租户

**严重级别**：P3

**证据**：
- `src/config.rs:738` — `NotifyAuthConfig` 默认 `bind_bearer_to_origin_did: false`。
- `src/auth.rs:254-320` — 仅当该开关为 true 时，bearer 才被绑定到声明的 `origin_service_did` 对应的 principal；否则走 `auth.rs:322-382` 的网关级 bearer 路径：校验 `auth.bearer_tokens` 通过后，`origin_service_did` 完全取自请求头 `X-Contrix-Origin-Service-DID`（`auth.rs:348-377`），并据此决定 `allow_plaintext_metadata`（`auth.rs:374-377`）。
- `trusted_service_dids` 为空时（默认）`auth.rs:354` 的 allowlist 检查被跳过，任意 origin DID 均被接受。

**影响**：在仅配置网关级 bearer（未开 `bind_bearer_to_origin_did`、未配 `trusted_service_dids`、非 production_mode）的部署中，持有该共享 bearer 的任意调用方可通过伪造 `X-Contrix-Origin-Service-DID` 声明为任意租户/服务身份，污染审计归因，并在该 DID 命中 `plaintext_metadata_service_dids` 时获得明文权限。代码注释（`config.rs:556-562`、`auth.rs:248-253`）已识别此风险并提供开关；`production_mode` 也禁用网关级 bearer fallback（`config.rs:701-705`、`auth.rs:169-180`）。属默认值偏弱的多租户隔离缺口，定 P3。

**建议**：默认开启 `bind_bearer_to_origin_did`，或在存在多个 `service_principals` / 配置了 `plaintext_metadata_service_dids` 时启动期强制要求开启；同时在网关级 bearer 路径默认要求非空 `trusted_service_dids` allowlist。

**复验结论**：已重新打开 `config.rs:738`/`556-562`、`auth.rs:248-382` 核对，默认关闭、origin DID 取自请求头、空 allowlist 跳过检查均属实。属实保留。

---

## 一并核对为"非问题"的项（避免误报，简记）

- **retry_queue AEAD**：`retry_queue.rs:68-72` 每次 `seal` 用 `rand::thread_rng().fill_bytes` 生成 96-bit 随机 nonce（非固定 nonce），ChaCha20-Poly1305 + AAD，nonce 拼在密文前。随机 nonce 无明显复用风险；CSPRNG 来源合理。未记为问题。
- **media 签名 helper**：`media.rs:261-270`、`378-386`、`440-454` 的 `sign*` 在 v1 proxy 模式下一律 `Err(...)` fail-closed，不会静默发出未签名 token；canonical bytes 按 sorted-key 生成（`media.rs:399-433`）。符合预期。
- **HTTP Message Signature**：`auth.rs:664-694` 强制覆盖 method/target-uri/authority/content-digest/origin-did/dest-did 六组件 + created/expires 双向 skew 校验 + content-digest 对原始 body 重算（`auth.rs:701`/`792-828`，锁定 sha-256），并接 nonce 防重放（`auth.rs:99-101`）。未发现可绕过点。
- **SQL 注入**：表名经 `SqlTableName::parse` 白名单（`config.rs:446-453`、`retry_queue.rs:140-141`）；postgres URL 经 `validate_postgres_url`。未发现注入面。
- **query-string 鉴权**：`auth.rs:197-228` 显式拒绝 `access_token/token/signature/...` 出现在 query。符合预期。
- **`unsafe`**：仅 `observability.rs:283` 测试代码内 `std::env::remove_var`（`#[cfg(test)]`），生产路径无 `unsafe`。未记为问题。
- **版本漂移（v2+）**：本次覆盖范围内未见 `v2`/`v3` 自定义版本命名；media/profile 均为 `.v1`。无 v2+ 违规记录。
