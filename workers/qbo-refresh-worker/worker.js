// qbo-refresh-worker
// Cloudflare Worker that proxies QuickBooks Online for the Oxley CRM.
//
// Routes:
//   GET /sales-data                          → recent invoices (last 90 days)
//   GET /profit-loss?start_date=&end_date=   → QBO Reports API ProfitAndLoss
//   GET /top-customers?year=YYYY             → invoice totals aggregated by customer
//
// Token storage: KV namespace `QBO_TOKENS` keyed by "tokens" holds the rotating
// access_token + refresh_token. On first deploy, set QBO_INITIAL_REFRESH_TOKEN
// as a secret; the worker will mint an access token on the first request.

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400'
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const url = new URL(request.url);
    try {
      switch (url.pathname) {
        case '/sales-data':
          return json(await getSalesData(env), 200);
        case '/profit-loss':
          return json(await getProfitLoss(env, url.searchParams), 200);
        case '/top-customers':
          return json(await getTopCustomers(env, url.searchParams), 200);
        case '/health':
          return json({ ok: true, ts: Date.now() }, 200);
        default:
          return json({ error: 'not_found', path: url.pathname }, 404);
      }
    } catch (err) {
      const status = err.status || 500;
      return json({ error: err.message || 'internal_error', detail: err.detail || null }, status);
    }
  }
};

// ─── Token management ──────────────────────────────────────────────────────

async function getAccessToken(env) {
  const stored = await env.QBO_TOKENS.get('tokens', { type: 'json' });
  const refreshToken = (stored && stored.refresh_token) || env.QBO_INITIAL_REFRESH_TOKEN;
  if (!refreshToken) throw httpError(500, 'qbo_refresh_token_missing');

  if (stored && stored.access_token && stored.expires_at && stored.expires_at - 60_000 > Date.now()) {
    return stored.access_token;
  }
  return await refreshAccessToken(env, refreshToken);
}

async function refreshAccessToken(env, refreshToken) {
  const clientId = env.QBO_CLIENT_ID;
  const clientSecret = env.QBO_CLIENT_SECRET;
  if (!clientId || !clientSecret) throw httpError(500, 'qbo_client_credentials_missing');

  const resp = await fetch(`${env.QBO_OAUTH_BASE}/oauth2/v1/tokens/bearer`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'Authorization': 'Basic ' + btoa(`${clientId}:${clientSecret}`)
    },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken }).toString()
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw httpError(resp.status, 'qbo_refresh_failed', body);
  }
  const data = await resp.json();
  const tokens = {
    access_token: data.access_token,
    refresh_token: data.refresh_token || refreshToken,
    expires_at: Date.now() + (data.expires_in || 3600) * 1000
  };
  await env.QBO_TOKENS.put('tokens', JSON.stringify(tokens));
  return tokens.access_token;
}

async function qboFetch(env, path, { retried = false } = {}) {
  const token = await getAccessToken(env);
  const resp = await fetch(`${env.QBO_BASE}/v3/company/${env.QBO_REALM_ID}${path}`, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
  });
  if (resp.status === 401 && !retried) {
    const stored = await env.QBO_TOKENS.get('tokens', { type: 'json' });
    if (stored && stored.refresh_token) {
      await refreshAccessToken(env, stored.refresh_token);
    }
    return qboFetch(env, path, { retried: true });
  }
  if (!resp.ok) {
    const body = await resp.text();
    throw httpError(resp.status, 'qbo_api_error', body);
  }
  return resp.json();
}

// ─── Endpoints ─────────────────────────────────────────────────────────────

async function getSalesData(env) {
  const since = new Date(Date.now() - 90 * 86400_000).toISOString().slice(0, 10);
  const invoices = await queryAllInvoices(env, `WHERE TxnDate >= '${since}'`);
  return { invoices, count: invoices.length, since };
}

async function getProfitLoss(env, params) {
  const start = params.get('start_date');
  const end = params.get('end_date');
  if (!start || !end) throw httpError(400, 'missing_dates', 'start_date and end_date are required (YYYY-MM-DD)');
  if (!isIsoDate(start) || !isIsoDate(end)) throw httpError(400, 'bad_date_format', 'use YYYY-MM-DD');

  const qs = new URLSearchParams({
    start_date: start,
    end_date: end,
    accounting_method: 'Accrual',
    minorversion: '70'
  });
  const report = await qboFetch(env, `/reports/ProfitAndLoss?${qs.toString()}`);
  return {
    start_date: start,
    end_date: end,
    report,
    summary: summarizePnL(report)
  };
}

async function getTopCustomers(env, params) {
  const year = parseInt(params.get('year') || '', 10);
  if (!year || year < 2000 || year > 2100) throw httpError(400, 'bad_year', 'year must be a 4-digit calendar year');
  const start = `${year}-01-01`;
  const end = `${year}-12-31`;

  const invoices = await queryAllInvoices(env, `WHERE TxnDate >= '${start}' AND TxnDate <= '${end}'`);
  const byCustomer = new Map();
  for (const inv of invoices) {
    const ref = inv.CustomerRef || {};
    const id = String(ref.value || '');
    if (!id) continue;
    let row = byCustomer.get(id);
    if (!row) {
      row = { customer_id: id, name: ref.name || '(unnamed)', total: 0, invoice_count: 0, balance: 0 };
      byCustomer.set(id, row);
    }
    row.total += Number(inv.TotalAmt || 0);
    row.balance += Number(inv.Balance || 0);
    row.invoice_count += 1;
  }
  const top = Array.from(byCustomer.values())
    .sort((a, b) => b.total - a.total)
    .slice(0, 100);
  return { year, customer_count: byCustomer.size, invoice_count: invoices.length, customers: top };
}

// ─── QBO helpers ───────────────────────────────────────────────────────────

async function queryAllInvoices(env, whereClause) {
  const PAGE = 500;
  const out = [];
  let start = 1;
  while (true) {
    const sql = `SELECT * FROM Invoice ${whereClause} STARTPOSITION ${start} MAXRESULTS ${PAGE}`;
    const resp = await qboFetch(env, `/query?query=${encodeURIComponent(sql)}&minorversion=70`);
    const page = (resp.QueryResponse && resp.QueryResponse.Invoice) || [];
    out.push(...page);
    if (page.length < PAGE) break;
    start += PAGE;
    if (start > 20_000) break;
  }
  return out;
}

function summarizePnL(report) {
  const find = (rows, label) => {
    if (!rows) return 0;
    for (const row of rows) {
      if (row.Summary && row.Summary.ColData) {
        const head = (row.Summary.ColData[0] && row.Summary.ColData[0].value) || '';
        if (head.toLowerCase() === label.toLowerCase()) {
          const cell = row.Summary.ColData[row.Summary.ColData.length - 1];
          return Number((cell && cell.value) || 0);
        }
      }
      if (row.Rows && row.Rows.Row) {
        const inner = find(row.Rows.Row, label);
        if (inner) return inner;
      }
    }
    return 0;
  };
  const rows = report && report.Rows && report.Rows.Row;
  return {
    total_income: find(rows, 'Total Income'),
    total_expenses: find(rows, 'Total Expenses'),
    net_income: find(rows, 'Net Income'),
    gross_profit: find(rows, 'Gross Profit')
  };
}

// ─── Utilities ─────────────────────────────────────────────────────────────

function isIsoDate(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

function httpError(status, message, detail) {
  const e = new Error(message);
  e.status = status;
  e.detail = detail;
  return e;
}
