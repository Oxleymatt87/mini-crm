# oxley-mcp-server

Model Context Protocol (MCP) server for Oxley Tire's finance/CRM data.

It speaks MCP over HTTP (JSON-RPC 2.0, single POST endpoint) and exposes the
read-only endpoints of [`qbo-refresh-worker`](../qbo-refresh-worker) as MCP
tools, so an MCP client (e.g. Claude) can query QBO + Plaid data through one
server. No secrets live here — the upstream worker owns the QBO/Plaid tokens.

Deployed at `https://oxley-mcp-server.moxley.workers.dev` on Cloudflare account
`e450a418975ed9b1212f52452bb1b5d5`.

## Endpoints

| Method | Path       | Description                                      |
|--------|------------|--------------------------------------------------|
| GET    | `/status`  | Health/info JSON (server name, protocol, tools). |
| POST   | `/`        | JSON-RPC 2.0 MCP requests.                        |

MCP methods handled: `initialize`, `notifications/initialized`, `ping`,
`tools/list`, `tools/call`.

## Tools

`dashboard_summary`, `overdue_invoices`, `chase_transactions` (`days`),
`bank_transactions`, `profit_loss` (`start_date`, `end_date`),
`expenses_detail` (`start_date`, `end_date`), `top_customers` (`year`),
`payments_by_customer`, `dad_dashboard` (HTML), `chase_report` (HTML),
`qbo_token_status` (token health from the `QBO_TOKENS` KV — presence, length,
and expiry only; never the secret values).

Write/side-effecting upstream endpoints (`/new-prospect`, `/plaid-link-token`,
`/plaid-exchange`) are intentionally **not** exposed, since this endpoint is
unauthenticated.

## Config

`UPSTREAM_BASE` (in `wrangler.toml` `[vars]`) — base URL of `qbo-refresh-worker`.
Defaults to `https://qbo-refresh-worker.moxley.workers.dev`.

## Deploy

```sh
export CLOUDFLARE_API_TOKEN=...   # Workers Scripts:Edit on the account
npx wrangler deploy
```

## Smoke test

```sh
curl -s https://oxley-mcp-server.moxley.workers.dev/status | jq .

# list tools
curl -s -X POST https://oxley-mcp-server.moxley.workers.dev/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .

# call a tool
curl -s -X POST https://oxley-mcp-server.moxley.workers.dev/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"overdue_invoices","arguments":{}}}' | jq .
```
