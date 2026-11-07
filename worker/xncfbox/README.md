# xncfbox

`xncfbox` 是独立于 `xnvgatebox` 的单 Worker 部署包。

当前部署地址：`https://xncfbox.waynee.workers.dev`。运行时使用独立的 `XNCFBOX_MANIFEST` KV Namespace。

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

GitHub Actions 使用本目录内的独立刷新脚本读取公开 VPN Gate CSV，再通过同一个 Worker 做两次 SSTP 检查，最后调用受保护的 `/api/manifest` 将无凭证 manifest 原子写入专用 KV。Actions 不需要 Cloudflare API Token；它不会导入 `src/`、调用 VPS 脚本，也不会读取或写入 `xnvgatebox` 的 KV、变量或订阅。

仓库只需配置三个 `xncfbox` Secrets：`XNCFBOX_WORKER_URL`、`XNCFBOX_CHECKER_TOKEN`、`XNCFBOX_ADMIN_TOKEN`。

刷新工具只依赖 Python 标准库：

```sh
python3 worker/xncfbox/refresh.py
python3 worker/xncfbox/publish_manifest.py
```
