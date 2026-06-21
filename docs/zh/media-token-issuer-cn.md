# 媒体 Token 签发者角色（v1 决策）

> 对应英文：参见 `soland/docs/architecture/media-token-issuer.md` 与
> `floria/docs/en/runbook.md`。

## 决策摘要

在 Cokret v1 中，`ck.self.call.media.exchange.issue_token` 的**规范签发者**是
**soland**。当前 floria 二进制不在公开 router 或 describe 响应中暴露
`/rtc/token` 本地签发面；如果部署层未来在 floria 前后接入代理，也只能作为
**透明代理**把请求交给 soland，并将 soland 返回的字节原样回传给客户端。

| 角色 | soland | floria |
|---|---|---|
| 签发 `MediaTokenResponse` | **是（唯一）** | 否（仅代理） |
| 持有签发密钥 | **是** | 否 |
| 签 `participant_binding` | **是** | 否 |
| 签 `service_signature` | **是** | 否 |
| 轮换 `issuer_kid` | **是** | 否 |
| 对外暴露 `POST /rtc/token` | 是（直连） | 否（当前二进制未挂路由；未来若接入也只能透明代理） |

## 为什么 floria 在 v1 中只代理

1. **签发密钥的最小化暴露面**。媒体 token 的签发密钥是高敏资产；将其留
   在 soland（一台 reducer 服务）而不下放到推送网关，能让密钥的攻击面
   收敛到一个治理边界更紧的服务上。
2. **kid 轮换的单点权威**。轮换 `service_signature.kid` 是一个需要严格
   时序的运维操作；让一个权威节点负责轮换，避免多节点 kid 视图不一致
   造成的 `token_issuer_unauthorised` 故障。
3. **canonical bytes 一致性**。`participant_binding` 的规范字节由 SDK
   + soland 共同维护；floria 只保留 fail-closed 的本地 scaffold，并用排序
   map 固定字段顺序，避免未来签名路径落地前发生序列化漂移。
4. **审计明确性**。所有签发都源自 soland，审计日志只需要在一处采集。

## floria 代理的不变量

- **字节不可变**。floria 必须按字节转发 soland 返回的 token；任何中间
  改写都是 bug。
- **不缓存**。每张 token 单次签发，缓存会破坏 `(realm, call, actor,
  device, focus)` 唯一性约束。
- **不见明文**。floria 的请求日志对 `participant_binding` 字段做脱敏，
  仅记录长度和 `issuer_kid`。

## 何时这条决策可能在未来版本变化

`ck.profile.media_service_binding.v1` 的发展路径上保留了一个未来选项：
在受控的部署里（如 soland 与 floria 同主同时部署，且签发密钥已落在
floria 的 KMS 内），允许 floria 作为副签发者承担流量。**这不是 v1 行
为**；v1 中任何 floria 直签 token 的代码路径都按 bug 处理。当前 floria
没有本地 media-token 签发模块，也没有公开 HTTP/API 能力。

## 排错快查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| floria 日志出现“minting token locally” | 走到了不该走的本地签发分支 | 立 bug；按 v1 该路径应不存在 |
| soland 返回 `token_issuer_unauthorised` 但 floria 看起来正常 | 不是 floria 的问题 —— soland 端的 issuer-key 与 realm 绑定不一致；联系 soland 运维 |
| floria 把 `participant_binding` 写进了非脱敏日志 | 日志库配置漂移 | 修日志字段过滤，确认不再写明文 |
