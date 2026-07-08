// oxley-mcp-server — Model Context Protocol server for Oxley Tire Inc.
//
// Exposes (1) the read-only finance/CRM endpoints of `qbo-refresh-worker` and
// (2) a canonical CONTEXT tool that hands any MCP client Matt's full current
// state — stack, deployed workers, where creds live, prospects, suppliers,
// open threads — so every session loads the truth instead of stale memory.
//
// Transport: MCP over HTTP, JSON-RPC 2.0 ("Streamable HTTP" single POST).
// Methods: initialize, notifications/initialized, ping, tools/list, tools/call.
//
// Endpoints:
//   GET  /status   → health/info JSON
//   POST /         → JSON-RPC 2.0 MCP requests
//
// No secrets live in this file. Credential *values* stay in Cloudflare KV on the
// owning workers; CONTEXT only ever names WHERE creds live, never the values.

const DEFAULT_UPSTREAM = 'https://qbo-refresh-worker.moxley.workers.dev';
const PROTOCOL_VERSION = '2025-06-18';
const SERVER_INFO = { name: 'oxley-mcp-server', version: '1.1.0' };

// === Canonical context. Edit these strings + redeploy to update the truth. ===
const CONTEXT = {
  identity: `Matt Oxley — sole owner/operator of Oxley Tire Inc. (S-corp), a wholesale commercial truck tire business on the SE Texas Hwy 90 corridor (Lumberton/Beaumont). One-man operation: drives the territory daily, runs everything mobile-first from a Samsung Galaxy S26 Ultra via Termux + Claude, with a laptop for desktop-only tasks. Customers are oilfield, trucking, and construction fleets. Comm style: direct, profanity-comfortable, zero tolerance for hedging/repetition/indirect answers — wants the full briefing, not the public-safe version. When in doubt, do the work and use available creds/tools rather than handing back a checklist.`,

  infrastructure: `Cloudflare account e450a418975ed9b1212f52452bb1b5d5, subdomain moxley.workers.dev.
WORKERS (all live):
- qbo-refresh-worker — QBO OAuth refresh + Plaid (live Chase) + Firestore CRM + Apify prospect scraping; serves /dad dashboard; hourly cron "0 * * * *". Uses the AB8 QBO app (Client ID starts AB8BtZApa...), NOT ABQ. Bindings: QBO_CLIENT_ID, QBO_CLIENT_SECRET, REALM_ID, QBO_TOKENS KV (9e61d4d0d02a476692cfa71c1002908b), SHEETS_API_KEY. Deploy: multipart curl PUT from Termux; main_module must equal the file part name (qbo_worker_clean.js); metadata MUST list ALL bindings or they wipe; qboApiCall returns parsed JSON (never .json() it again); SQL WHERE needs encodeURIComponent.
- oxley-mcp-server — THIS server. MCP tools for finance/CRM (proxied to qbo-refresh-worker via the QBO service binding — a Worker cannot subrequest another *.workers.dev on the same account, CF error 1042) plus this oxley_context tool. Bindings: QBO (service → qbo-refresh-worker), QBO_TOKENS KV.
- claude-proxy — Anthropic API proxy that powers the map's AI chat.
- email-tracker — self-hosted email open-tracking. DEPLOYED + VERIFIED. KV EMAIL_OPENS (439559706aa6453d97e37e82e536f1d2), VIEW_KEY oxley-track-9931. Routes /new?id=X, /px?id=X&t=unix, /opens?id=X&key=VIEW_KEY. Filters machine prefetch (Apple MPP 17.x, scanner UAs, opens <8s after send) from real human opens. Built to avoid Mailsuite's full-mailbox scope.
- oxley-send — Gmail tracked sending. DEPLOYED + WORKING; Gmail OAuth is COMPLETE, do NOT redo. Scope gmail.send only (no mailbox read). OAuth Web client "Matt" in the Inventory project, consent screen Internal (oxleytireinc.com), redirect https://oxley-send.moxley.workers.dev/callback. Creds + refresh token in KV (gmail:refresh, google:client_id, google:client_secret) so the deploy carries no secrets. SEND_KEY oxley-send-2026. Tracked-send pad: https://oxley-send.moxley.workers.dev/compose?key=oxley-send-2026 (sends as moxley@oxleytireinc.com, auto-stamps the email-tracker pixel).
- oxley-beams — 3D "beam map": 372 SE-TX fleet yards as tire-burn-colored beams over Google Photorealistic 3D tiles; tap a beam for full card (owner/Ask-for, phone, Call/Directions/SAFER/Street View/Photos/Take-Me-There), live GPS ◉ YOU marker, distance-sorted nearest-yards list, Lead/Visited/Sold/Dead status + notes. Notes/status persist in KV OXLEY_BEAM_NOTES (07bde4cf73034c9dba16cd08f5170f7b) bound as env.NOTES; routes POST/GET /note, GET /notes (CORS *). URL oxley-beams.moxley.workers.dev. Uses the Google Maps API key in the Inventory project (Places New + Geocoding + Map Tiles / Photorealistic 3D Tiles).
- oxley-globe — Cesium 3D globe of the whole territory (Google Photorealistic 3D tiles + real sky/atmosphere), same beams + tap-for-card, +/− zoom buttons + ⌖ Beaumont reset. Notes sync to the SAME OXLEY_BEAM_NOTES KV via oxley-beams (cross-map). Flat-screen but SMOOTH navigation — the KEEPER for viewing on phone or as a headset panel. URL oxley-globe.moxley.workers.dev.
- oxley-xr — true WebXR immersive "war room" (three.js + 3d-tiles-renderer@0.4.28 + Google tiles). Real head-tracked VR on the Galaxy XR, but hand-tracking nav (grab-spin/raise-zoom/two-hand-scale) is unpolished and hard to tune blind. PARKED as a demo, NOT a daily tool. URL oxley-xr.moxley.workers.dev.
FIREBASE project inventory-setup-b3f20: CRM territory map /map.html (550+ pins, satellite, industry icons, voice, Claude chat via claude-proxy, route mode, filters); Fleet Command sales page /fleet-command.html ($199/mo dispatch-map product). Gemini API key in the Inventory project (AI Studio, billing Tier 1). Tire inventory app at oxley-tire-inventory.tiiny.site.
DEPLOY CONSTRAINTS: Wrangler does NOT work on Termux ARM64 — deploy workers by multipart curl PUT. Firebase deploys via npx firebase-tools from ~/oxley-inventory. Claude Code can push to GitHub (Oxleymatt87/mini-crm) but cannot deploy. Laptop has Claude Desktop with Browser Use. CF API token lives in Termux ~/.bashrc as $CF_TOKEN. RULE: credential values never go in memory/context/this file — pointers only; sessions read live from KV.`,

  sales: `Territory: SE Texas Hwy 90 corridor. Strategy: cold-call walk-ins on fleet operators (oilfield/trucking/construction).
TOP PROSPECTS:
- LSJ Trucking — 5020 Fannett Rd, 41+ trucks, owner Lesley Juman. Consistent #1 prospect.
- Curtis & Son — 84 trucks, Liberty TX. Largest all-time account (~$342K). First Fleet Command target.
- CTW / Buddy (ctwtexas@outlook.com) — first Fleet Command beta candidate.
Competitive intel: STM Beaumont (Store 458) is the primary competing Hixih/Roadone TBR channel in the area.
Fleet Command: $199/mo dispatch-map SaaS, live at inventory-setup-b3f20.web.app/fleet-command.html.
Outreach workflow: send tracked via the oxley-send pad or the "Oxley Tracker" Gmail add-on; use a per-prospect tracking ID (e.g. charles-13849, lsj-fannett, curtis-fleet); check opens at email-tracker /opens?id=...&key=oxley-track-9931.`,

  financials: `Chase business line of credit: real-time DECLINE (cited recent CC payments + low checking deposits), 90-day reapply window, reference 894624.1, target $100K / floor $50K. Master PDF package (tax returns, bank statements) assembled. Rejected multiple predatory MCA/broker offers.
QBO problems: cash-basis accounting distorts net income (inflated paper profit vs a thin checking balance); payment-processing fees recorded inconsistently across three accounts. Likely QBO bug — the "customer pays fee" toggle shows enabled but fails to render convenience fees on payment links, so months of fees were absorbed; escalate to QBO support demanding a fix AND a credit backed by their own system logs.
AR: demand letter sent to Charles Beaty (Invoice #13849, 68+ days past due as of June 2026; 3098 FM 2460, Bon Wier TX 75928). JP-court small claims is the next step if unpaid.
Live numbers available through THIS server's QBO tools (dashboard_summary, overdue_invoices, profit_loss, chase_transactions, payments_by_customer, etc.).`,

  suppliers: `- CTW / Jason — Round Rock; best friend; preferred pricing source.
- BZO Wheels — primary distributor; inflated cost history; TireGuru portal scraper build pending (login creds / server assignment unconfirmed).
- Jinyu / Eileen — container supplier; outstanding balance history.
- Amulet / Andrew — broken-exclusivity dispute; documented text evidence; unresolved pending capital.
- IV Tire (Victor / Kyle) — mutual-balance situation, net in Matt's favor; leverage + deadline messaging drafted.
- Stocking research: Royal Black beats Zenna for TBR (construction quality; Zenna carries documented liability exposure).`,

  personal: `- Wife Katie teaches cosmetology at Lamar University, Beaumont.
- Father: longtime Southern Tire Mart veteran, exiting that role; potential limited helper/resource. Matt founded Oxley as a wholesale-focused competitor after leaving his father's business.
- Health: works with Dr. Pickard (CHRISTUS Trinity Clinic) + Defy Medical; interests in fitness, body recomposition, wellness optimization.
- Devices: Galaxy S26 Ultra (primary, Termux + Claude), laptop for desktop tools, Galaxy XR headset (spatial-computing experiments), a converted 40-ft container office.
- Vehicle: 2021 Chevy Silverado 2500HD (4dr ext cab, LT, 6.6L V8 gas) — AC fix is an ECV swap at home; candidate part UAC EX10523C (~$52.79 RockAuto).`,

  current: `IN-FLIGHT / OPEN THREADS (as of 2026-06-30):
- 3D MAP SUITE built 2026-06-30: oxley-beams + oxley-globe (Cesium) are KEEPERS; oxley-xr (WebXR VR) is PARKED — no single tool yet does true-VR + custom data + smooth nav (Google native immersive Maps won't ingest custom data; Cesium has no real WebXR; three.js WebXR has no built-in map camera). Beams + globe share OXLEY_BEAM_NOTES KV so notes sync across both.
- INFRA HYGIENE (root cause of "breaks next session"): (1) deploy fragility — multipart curl PUT silently wipes bindings if not all re-listed; (2) context drift — THIS doc wasn't updated when new workers shipped, so fresh sessions didn't know they existed and rebuilt/broke them. FIX PATH: move workers into GitHub w/ wrangler.jsonc (bindings declared in code, can't wipe) + GitHub Actions CI (wrangler runs on GH x86 runners, not Termux ARM64). INTERIM RULE every session: reconcile this doc vs live Cloudflare via the Cloudflare MCP, and WRITE BACK (redeploy oxley-mcp-server) whenever infra changes — safe deploy = fetch current bindings first, keep_bindings preserves secret_text, verify oxley_context + a finance tool after.
- email-tracker + oxley-send: BOTH deployed and working. oxley-send Gmail OAuth is DONE — do not redo it.
- Gmail compose add-on "Oxley Tracker" (Apps Script: Code.gs + appsscript.json) built to stamp the tracking pixel inside real Gmail compose (one tap; only edits the draft — no send/read scope). Deploy method undecided: clasp from Termux vs souping up the oxley-send pad with a baked-in signature + reply-to-thread. Matt prefers tracking inside actual Gmail.
- This MCP server: oxley_context tool added so every session loads current state.
- Map known issues still open: search bar doesn't filter pins (needs input event listener), GPS blue dot not working, pin notes don't persist (need Firestore). Next priorities: fix search, add GPS, wire notes to Firestore, last-contact-date pin coloring, revenue heat map from QBO.
- Security: the Google client secret (GOCSPX-...) was pasted in chat earlier and lives in KV; rotation is recommended (Google allows two secrets so zero downtime) — Matt declined. A GitHub token and a Cloudflare token were also exposed in chat history.
- Charles Beaty AR: demand letter sent; JP small-claims is the next step if still unpaid.`,
};

const CONTEXT_ORDER = ['identity', 'infrastructure', 'sales', 'financials', 'suppliers', 'personal', 'current'];

// Each finance tool maps to an upstream qbo-refresh-worker endpoint.
const TOOLS = [
  {
    name: 'oxley_context',
    description: "Matt Oxley's canonical, always-current business + infrastructure context for Oxley Tire Inc. CALL THIS FIRST at the start of any conversation to load Matt's real state — his Cloudflare/Firebase/QuickBooks stack, every deployed worker and its URL, where credentials live, active sales prospects, supplier relationships, the financial picture, and open in-flight threads. This is the source of truth; prefer it over older or summarized memory. Pass `section` to load one slice, or omit for everything.",
    context: true,
    inputSchema: {
      type: 'object',
      properties: {
        section: {
          type: 'string',
          enum: ['all', 'identity', 'infrastructure', 'sales', 'financials', 'suppliers', 'personal', 'current'],
          description: 'Which slice to load. Default "all".',
        },
      },
      additionalProperties: false,
    },
  },
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
        protocolVersion: msg?.params?.protocolVersion || PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });

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

  const args = params?.arguments && typeof params.arguments === 'object' ? params.arguments : {};

  if (tool.context) return contextResult(id, args);
  if (tool.kv) return tokenStatus(id, env);

  const qs = tool.query ? tool.query(args) : {};
  const target = new URL(tool.path, upstreamBase(env));
  for (const [k, v] of Object.entries(qs)) target.searchParams.set(k, v);

  try {
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

// Return the canonical context, whole or by section.
function contextResult(id, args) {
  const requested = (args && typeof args.section === 'string') ? args.section.toLowerCase() : 'all';
  let body;
  if (requested !== 'all' && CONTEXT[requested]) {
    body = `## ${requested.toUpperCase()}\n${CONTEXT[requested]}`;
  } else {
    body = CONTEXT_ORDER.map((k) => `## ${k.toUpperCase()}\n${CONTEXT[k]}`).join('\n\n');
  }
  const stamp = `Oxley Tire — canonical context (served live by oxley-mcp-server v${SERVER_INFO.version}).\n\n`;
  return rpcResult(id, { content: [{ type: 'text', text: stamp + body }] });
}

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
        const ms = n < 1e12 ? n * 1000 : n;
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
