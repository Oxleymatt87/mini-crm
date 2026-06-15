// oxley-mcp-server — Model Context Protocol server for Oxley Tire's finance/CRM data.
//
// Exposes the read-only endpoints of `qbo-refresh-worker` as MCP tools so an
// MCP client (e.g. Claude) can query QBO + Plaid data through a single server.
//
// Transport: MCP over HTTP using JSON-RPC 2.0 (the "Streamable HTTP" style —
// a single POST endpoint). Methods handled: initialize, notifications/initialized,
// ping, tools/list, tools/call.
//
// Endpoints:
//   GET  /status   → health/info JSON (used by smoke test)
//   POST /         → JSON-RPC 2.0 MCP requests
//
// Config (env / wrangler.toml [vars]):
//   UPSTREAM_BASE  — base URL of qbo-refresh-worker
//                    (default https://qbo-refresh-worker.moxley.workers.dev)
//
// No secrets are stored here; the upstream worker owns the QBO/Plaid tokens.

const DEFAULT_UPSTREAM = 'https://qbo-refresh-worker.moxley.workers.dev';
const PROTOCOL_VERSION = '2025-06-18';
const SERVER_INFO = { name: 'oxley-mcp-server', version: '1.0.0' };

// Each tool maps to an upstream qbo-refresh-worker endpoint. `query` builds the
// querystring from the validated MCP arguments.
const TOOLS = [
  {
    name: 'dashboard_summary',
    description: 'QuickBooks Online summary: AR totals, balances, and headline numbers.',
    path: '/dashboard-summary',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'overdue_invoices',
    description: 'All overdue accounts-receivable invoices from QuickBooks Online.',
    path: '/overdue-invoices',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'chase_transactions',
    description: 'Live Chase bank transactions via Plaid, auto-categorized.',
    path: '/chase-transactions',
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'integer', minimum: 1, maximum: 730, description: 'Lookback window in days (default 90).' },
      },
      additionalProperties: false,
    },
    query: (a) => (a.days != null ? { days: String(a.days) } : {}),
  },
  {
    name: 'bank_transactions',
    description: 'Posted bank transactions as recorded in QuickBooks Online.',
    path: '/bank-transactions',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'profit_loss',
    description: 'QuickBooks Online Profit & Loss report for a date range.',
    path: '/profit-loss',
    inputSchema: {
      type: 'object',
      properties: {
        start_date: { type: 'string', description: 'YYYY-MM-DD start of range.' },
        end_date: { type: 'string', description: 'YYYY-MM-DD end of range.' },
      },
      additionalProperties: false,
    },
    query: (a) => pick(a, ['start_date', 'end_date']),
  },
  {
    name: 'expenses_detail',
    description: 'Detailed bills and purchases from QuickBooks Online for a date range.',
    path: '/expenses-detail',
    inputSchema: {
      type: 'object',
      properties: {
        start_date: { type: 'string', description: 'YYYY-MM-DD start of range.' },
        end_date: { type: 'string', description: 'YYYY-MM-DD end of range.' },
      },
      additionalProperties: false,
    },
    query: (a) => pick(a, ['start_date', 'end_date']),
  },
  {
    name: 'top_customers',
    description: 'Top customers by revenue from QuickBooks Online.',
    path: '/top-customers',
    inputSchema: {
      type: 'object',
      properties: {
        year: { type: 'integer', description: 'Calendar year, e.g. 2026.' },
      },
      additionalProperties: false,
    },
    query: (a) => (a.year != null ? { year: String(a.year) } : {}),
  },
  {
    name: 'payments_by_customer',
    description: 'Payments grouped by customer and payment method, with diagnostics for unmatched deposits.',
    path: '/payments-by-customer',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'dad_dashboard',
    description: 'Live combined dashboard (HTML): AR, balances, invoices, and recent Chase transactions.',
    path: '/dad',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'chase_report',
    description: 'Chase spending report (HTML dashboard with CSV export) built from live Plaid data.',
    path: '/chase-report',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'qbo_token_status',
    description: 'Health of the stored QBO/Plaid OAuth tokens: which keys are present, their value lengths, and the QBO access-token expiry. Never returns the secret token values.',
    kv: true,
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

const TOOLS_BY_NAME = Object.fromEntries(TOOLS.map((t) => [t.name, t]));

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return preflight();

    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/status') {
      return cors(json({
        status: 'ok',
        server: SERVER_INFO,
        protocolVersion: PROTOCOL_VERSION,
        upstream: upstreamBase(env),
        tools: TOOLS.map((t) => t.name),
      }));
    }

    if (request.method !== 'POST') {
      return cors(text('method not allowed — POST JSON-RPC to /, or GET /status', 405));
    }

    let msg;
    try {
      msg = await request.json();
    } catch {
      return cors(json(rpcError(null, -32700, 'Parse error: invalid JSON')));
    }

    // JSON-RPC batches are arrays; handle each and drop null (notification) results.
    if (Array.isArray(msg)) {
      const out = [];
      for (const m of msg) {
        const r = await handleRpc(m, env);
        if (r !== null) out.push(r);
      }
      return cors(out.length ? json(out) : new Response(null, { status: 202 }));
    }

    const result = await handleRpc(msg, env);
    return cors(result === null ? new Response(null, { status: 202 }) : json(result));
  },
};

async function handleRpc(msg, env) {
  const id = msg?.id ?? null;
  const method = msg?.method;

  if (msg?.jsonrpc !== '2.0' || typeof method !== 'string') {
    return rpcError(id, -32600, 'Invalid Request');
  }

  switch (method) {
    case 'initialize':
      return rpcResult(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });

    // Notifications carry no id and expect no response.
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null;

    case 'ping':
      return rpcResult(id, {});

    case 'tools/list':
      return rpcResult(id, {
        tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
      });

    case 'tools/call':
      return toolCall(id, msg?.params, env);

    default:
      return rpcError(id, -32601, `Method not found: ${method}`);
  }
}

async function toolCall(id, params, env) {
  const tool = TOOLS_BY_NAME[params?.name];
  if (!tool) return rpcError(id, -32602, `Unknown tool: ${params?.name}`);

  if (tool.kv) return tokenStatus(id, env);

  const args = params?.arguments && typeof params.arguments === 'object' ? params.arguments : {};
  const qs = tool.query ? tool.query(args) : {};
  const target = new URL(tool.path, upstreamBase(env));
  for (const [k, v] of Object.entries(qs)) target.searchParams.set(k, v);

  try {
    // Prefer the service binding (QBO) — a Worker cannot subrequest another
    // *.workers.dev URL on the same account (CF error 1042). Fall back to a
    // direct fetch (e.g. local dev / Node) when the binding isn't present.
    const reqInit = { headers: { accept: 'application/json' } };
    const upstream = env && env.QBO && typeof env.QBO.fetch === 'function'
      ? await env.QBO.fetch(target.toString(), reqInit)
      : await fetch(target.toString(), reqInit);
    const bodyText = await upstream.text();
    return rpcResult(id, {
      content: [{ type: 'text', text: bodyText }],
      isError: !upstream.ok,
    });
  } catch (e) {
    return rpcResult(id, {
      content: [{ type: 'text', text: `Upstream fetch failed: ${e?.message || e}` }],
      isError: true,
    });
  }
}

// Report token health from the QBO_TOKENS KV without ever returning secret
// values — only presence, length, and the (non-secret) expiry timestamp.
async function tokenStatus(id, env) {
  if (!env || !env.QBO_TOKENS || typeof env.QBO_TOKENS.list !== 'function') {
    return rpcResult(id, { content: [{ type: 'text', text: 'QBO_TOKENS KV binding not configured.' }], isError: true });
  }
  try {
    const { keys } = await env.QBO_TOKENS.list();
    const report = [];
    for (const k of keys) {
      const v = await env.QBO_TOKENS.get(k.name);
      const entry = { key: k.name, present: v != null, length: v ? v.length : 0 };
      if (k.name === 'expires_at' && v) {
        const n = Number(v);
        const ms = n < 1e12 ? n * 1000 : n; // tolerate seconds or milliseconds
        const d = new Date(ms);
        if (!isNaN(d.getTime())) {
          entry.value = v;
          entry.expiresAtISO = d.toISOString();
          entry.expired = d.getTime() < Date.now();
        }
      }
      report.push(entry);
    }
    return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify({ namespace: 'QBO_TOKENS', tokens: report }, null, 2) }] });
  } catch (e) {
    return rpcResult(id, { content: [{ type: 'text', text: `KV read failed: ${e?.message || e}` }], isError: true });
  }
}

function upstreamBase(env) {
  return (env && env.UPSTREAM_BASE) || DEFAULT_UPSTREAM;
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj[k] != null) out[k] = String(obj[k]);
  return out;
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function preflight() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

function cors(resp) {
  for (const [k, v] of Object.entries(corsHeaders())) resp.headers.set(k, v);
  return resp;
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    'access-control-allow-headers': 'content-type, mcp-protocol-version',
    'access-control-max-age': '86400',
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });
}

function text(s, status = 200) {
  return new Response(s, { status, headers: { 'content-type': 'text/plain' } });
}
