# xncfbox

`xncfbox` 是独立于 `xnvgatebox` 的单 Worker 部署包。

它提供：

- `/health`：健康检查
- `/admin`：管理页
- `/check?proxy=sstp://...`：受保护的 SSTP 节点检查
- `/sub?token=...`：受保护的 VLESS 订阅
- `/?sstp=...&globalproxy=1`：TCP-only VLESS over WebSocket 数据面

数据面只连接已经写入 KV manifest、并由 GitHub Actions 验证过的 VPN Gate SSTP 节点。支持 TCP/IPv4；不支持 UDP、IPv6 或任意目标地址转发。

## 部署

1. 复制 `wrangler.toml.example` 为 `wrangler.toml`。
2. 创建一个新的 KV Namespace，只给 `xncfbox` 使用。
3. 用 `wrangler secret put` 设置 `VLESS_UUID`、`ADMIN_TOKEN`、`SUB_TOKEN` 和 `CHECKER_TOKEN`。
4. 在本目录执行 `npx wrangler deploy`。
5. 将 Worker 的 HTTPS 地址填入仓库变量 `XNCFBOX_WORKER_URL`。

示例：

```sh
npx wrangler secret put VLESS_UUID
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put SUB_TOKEN
npx wrangler secret put CHECKER_TOKEN
```

GitHub Actions 使用同一个 Worker 完成节点检查和数据面验收，再把无凭证 manifest 原子写入 KV。它不会读取或写入 `xnvgatebox` 的 KV、变量或订阅。
