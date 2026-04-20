# claude-proxy

Thin Cloudflare Worker in front of `https://api.anthropic.com/v1/messages`.

- **Vision requests** (any `messages[].content` block with `type: "image"`)
  → system prompt omitted, `max_tokens: 1024`
- **Chat requests** (everything else)
  → Oxley Tire sales copilot system prompt injected, `max_tokens: 500`

Deployed at `https://claude-proxy.moxley.workers.dev` on Cloudflare account
`e450a418975ed9b1212f52452bb1b5d5`.

## Deploy

```sh
# one-time
npm install
npx wrangler login   # or:  export CLOUDFLARE_API_TOKEN=...

# every deploy
npx wrangler deploy
```

Secrets (set once per account):

```sh
npx wrangler secret put ANTHROPIC_API_KEY
# optional — overrides the hardcoded Oxley sales copilot prompt:
npx wrangler secret put SALES_SYSTEM_PROMPT
```

## Smoke test

```sh
curl -sS -X POST https://claude-proxy.moxley.workers.dev \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"Say OK in one word."}]}' \
  | jq .
```

Expected: JSON with `content[0].text` containing "OK", and response header
`x-claude-proxy-mode: chat`. For vision, pass an `image` block; the header
flips to `vision` and the upstream call drops `system`.
