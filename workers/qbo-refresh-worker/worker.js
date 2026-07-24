/**
 * Sales Command Center + QBO MCP Server
 *
 * Existing features preserved:
 *   - QBO OAuth token refresh (scheduled + on-demand)
 *   - Web dashboard (/, /dashboard)
 *   - NL query (/query), /customers, /sales-data, /token-status
 *
 * New MCP endpoint (/mcp):
 *   - JSON-RPC 2.0 over HTTP (streamable HTTP transport)
 *   - Universal QBO tools: qbo_query, qbo_get, qbo_create, qbo_update,
 *     qbo_delete, qbo_batch, qbo_report, qbo_append_invoice_lines
 *   - Bearer token auth via MCP_AUTH_TOKEN env secret
 */

const REALM_ID = '9130357532009796';
const SHEET_ID = '1EghclLR5lUwHRsEVvmmNrHZQcyKvLGP0JCQHyJKOoEY';
const QBO_API_BASE = 'https://quickbooks.api.intuit.com/v3/company';
const GOOGLE_SHEETS_API = 'https://sheets.googleapis.com/v4/spreadsheets';
const QBO_MINOR_VERSION = '73';
const MCP_PROTOCOL_VERSION = '2025-06-18';

const HTML_INTERFACE = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sales Command Center</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; color: white; margin-bottom: 40px; }
        .header h1 { font-size: 48px; font-weight: 700; margin-bottom: 10px; }
        .header p { font-size: 18px; opacity: 0.9; }
        .card { background: white; border-radius: 16px; padding: 30px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); margin-bottom: 30px; }
        .input-group { display: flex; gap: 10px; margin-bottom: 20px; }
        #queryInput { flex: 1; padding: 15px 20px; font-size: 16px; border: 2px solid #e0e0e0; border-radius: 8px; outline: none; }
        #queryInput:focus { border-color: #667eea; }
        .btn { padding: 15px 30px; font-size: 16px; font-weight: 600; border: none; border-radius: 8px; cursor: pointer; transition: all 0.3s; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; transform: translateY(-2px); }
        .btn-primary:disabled { background: #ccc; cursor: not-allowed; }
        .preset-buttons { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .btn-preset { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: left; border-radius: 8px; border: none; cursor: pointer; transition: all 0.3s; }
        .btn-preset:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4); }
        .btn-preset h3 { font-size: 16px; margin-bottom: 5px; }
        .btn-preset p { font-size: 13px; opacity: 0.9; }
        .status-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .status-item { text-align: center; }
        .status-item .label { font-size: 13px; color: #666; margin-bottom: 5px; }
        .status-item .value { font-size: 24px; font-weight: 700; color: #333; }
        .status-item .value.good { color: #10b981; }
        .status-item .value.warning { color: #f59e0b; }
        .status-item .value.bad { color: #ef4444; }
        .loading { text-align: center; padding: 40px; }
        .spinner { border: 4px solid #f3f4f6; border-top: 4px solid #667eea; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .success { background: #d1fae5; color: #065f46; padding: 15px; border-radius: 8px; margin-top: 15px; }
        .error { background: #fee2e2; color: #dc2626; padding: 15px; border-radius: 8px; margin-top: 15px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 20px; }
        table th { background: #333; color: white; padding: 12px; text-align: left; font-weight: 600; }
        table td { padding: 12px; border-bottom: 1px solid #e5e7eb; }
        table tr:hover { background: #f3f4f6; }
        .sheet-link { display: inline-block; color: #667eea; text-decoration: none; font-weight: 600; margin-top: 10px; }
        @media (max-width: 768px) { .header h1 { font-size: 32px; } .input-group { flex-direction: column; } .preset-buttons { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Sales Command Center</h1>
            <p>QuickBooks Analytics Dashboard</p>
        </div>
        <div class="card">
            <div class="status-section">
                <h2 style="margin-bottom: 15px;">System Status</h2>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="label">Access Token</div>
                        <div class="value" id="tokenStatus">-</div>
                    </div>
                    <div class="status-item">
                        <div class="label">Token Expires In</div>
                        <div class="value" id="tokenExpiry">-</div>
                    </div>
                    <div class="status-item">
                        <div class="label">Last Query</div>
                        <div class="value" id="lastQuery">Never</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="card">
            <h2 style="margin-bottom: 15px;">💬 Ask a Question</h2>
            <div class="input-group">
                <input type="text" id="queryInput" placeholder="e.g., Show me top customers in Houston with over $100k in sales this year" onkeypress="if(event.key==='Enter') runQuery()">
                <button class="btn btn-primary" onclick="runQuery()" id="queryBtn">Run Query</button>
            </div>
            <h2 style="margin: 30px 0 15px 0;">⚡ Quick Queries</h2>
            <div class="preset-buttons">
                <button class="btn-preset" onclick="runPreset('Top 10 declining customers year over year and QTD vs previous year')">
                    <h3>📉 Declining Customers</h3>
                    <p>YoY & QTD comparison</p>
                </button>
                <button class="btn-preset" onclick="runPreset('Show me highest gross profit by ZIP code')">
                    <h3>📍 GP by ZIP</h3>
                    <p>Geographic profit analysis</p>
                </button>
                <button class="btn-preset" onclick="runPreset('Show me top 30 most sold products')">
                    <h3>🏆 Top Products</h3>
                    <p>Best sellers by quantity</p>
                </button>
                <button class="btn-preset" onclick="runPreset('Show me top 30% gross profit customers for YTD, MTD, and QTD')">
                    <h3>💰 Top GP Customers</h3>
                    <p>YTD, MTD, QTD breakdown</p>
                </button>
            </div>
        </div>
        <div class="card" id="resultsCard" style="display: none;">
            <div id="resultsContent"></div>
        </div>
    </div>
    <script>
        const SHEET_ID = '${SHEET_ID}';
        window.addEventListener('DOMContentLoaded', checkTokenStatus);
        async function checkTokenStatus() {
            try {
                const response = await fetch('/token-status');
                const data = await response.json();
                const tokenStatus = document.getElementById('tokenStatus');
                const tokenExpiry = document.getElementById('tokenExpiry');
                if (data.hasAccessToken) {
                    tokenStatus.textContent = '✓ Valid';
                    tokenStatus.classList.add('good');
                    if (data.expiresInMinutes) {
                        tokenExpiry.textContent = data.expiresInMinutes + ' min';
                        tokenExpiry.classList.add(data.expiresInMinutes < 5 ? 'warning' : 'good');
                    }
                } else {
                    tokenStatus.textContent = '✗ Invalid';
                    tokenStatus.classList.add('bad');
                    tokenExpiry.textContent = 'Expired';
                    tokenExpiry.classList.add('bad');
                }
            } catch (e) { console.error(e); }
        }
        async function runQuery() {
            const query = document.getElementById('queryInput').value.trim();
            if (!query) { alert('Please enter a question'); return; }
            await executeQuery(query);
        }
        async function runPreset(query) {
            document.getElementById('queryInput').value = query;
            await executeQuery(query);
        }
        async function executeQuery(query) {
            const btn = document.getElementById('queryBtn');
            const resultsCard = document.getElementById('resultsCard');
            const resultsContent = document.getElementById('resultsContent');
            btn.disabled = true;
            btn.textContent = 'Processing...';
            resultsCard.style.display = 'block';
            resultsContent.innerHTML = '<div class="loading"><div class="spinner"></div><p>Fetching data from QuickBooks...</p></div>';
            try {
                const response = await fetch('/query', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query })
                });
                const data = await response.json();
                if (data.error) throw new Error(data.error);
                if (!data.results || data.results.length === 0) {
                    resultsContent.innerHTML = '<p>No results found.</p>';
                    return;
                }
                const headers = Object.keys(data.results[0]);
                let html = '<div class="success">✓ Results written to Google Sheets<br><a href="https://docs.google.com/spreadsheets/d/' + SHEET_ID + '" target="_blank" class="sheet-link">Open Sheet →</a></div>';
                html += '<table><thead><tr>' + headers.map(h => '<th>' + h + '</th>').join('') + '</tr></thead><tbody>';
                html += data.results.map(row => '<tr>' + headers.map(h => '<td>' + (row[h] || '-') + '</td>').join('') + '</tr>').join('');
                html += '</tbody></table>';
                resultsContent.innerHTML = html;
                document.getElementById('lastQuery').textContent = 'Just now';
            } catch (error) {
                resultsContent.innerHTML = '<div class="error"><strong>Error:</strong> ' + error.message + '</div>';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Run Query';
            }
        }
    </script>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      if (url.pathname === '/mcp') {
        return await handleMcp(request, env, corsHeaders);
      }

      if (url.pathname === '/' || url.pathname === '/dashboard') {
        return new Response(HTML_INTERFACE, {
          headers: { 'Content-Type': 'text/html' }
        });
      }

      if (url.pathname === '/api') {
        return new Response(JSON.stringify({
          name: 'Sales Command Center API + QBO MCP',
          status: '✅ Auto-refresh enabled (every 50 min)',
          endpoints: {
            '/': 'Web dashboard',
            '/api': 'API info',
            '/mcp': 'MCP server (POST JSON-RPC, requires Bearer auth)',
            '/token-status': 'Check token status',
            '/customers': 'List customers',
            '/sales-data': 'Sales summary',
            '/query': 'Natural language query (POST)',
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (url.pathname === '/token-status') {
        const tokens = await getTokens(env);
        return new Response(JSON.stringify({
          hasAccessToken: !!tokens.access_token,
          hasRefreshToken: !!tokens.refresh_token,
          expiresIn: tokens.expires_in,
          expiresInMinutes: tokens.expires_in ? Math.floor(tokens.expires_in / 60) : null
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (url.pathname === '/query') {
        const qParam = url.searchParams.get('q');
        if (qParam) {
          return await handleDirectQboQuery(qParam, env, corsHeaders);
        }
        if (request.method === 'POST') {
          return await handleQuery(request, env, corsHeaders);
        }
        return new Response(JSON.stringify({ error: 'Pass ?q= with a QBO SQL query, e.g. ?q=SELECT * FROM Invoice MAXRESULTS 50' }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (url.pathname === '/customers') {
        return await fetchCustomers(env, corsHeaders);
      }

      if (url.pathname === '/sales-data') {
        return await fetchSalesData(env, corsHeaders);
      }

      if (url.pathname === '/dashboard-summary') {
        return await handleDashboardSummary(env, corsHeaders);
      }

      if (url.pathname === '/overdue-invoices') {
        return await handleOverdueInvoices(env, corsHeaders);
      }

      if (url.pathname === '/bank-transactions') {
        return await handleBankTransactions(env, corsHeaders);
      }

      if (url.pathname === '/profit-loss') {
        return await handleProfitLoss(url, env, corsHeaders);
      }

      if (url.pathname === '/top-customers') {
        return await handleTopCustomers(url, env, corsHeaders);
      }

      if (url.pathname === '/expenses-detail') {
        return await handleExpensesDetail(url, env, corsHeaders);
      }

      if (url.pathname === '/payments-by-customer') {
        return await handlePaymentsByCustomer(env, corsHeaders);
      }

      if (url.pathname === '/chase-transactions') {
        return await handleChaseTransactions(url, env, corsHeaders);
      }

      if (url.pathname === '/chase-report') {
        return await handleChaseReport(url, env, corsHeaders);
      }

      if (url.pathname === '/dad') {
        return await handleDad(url, env, corsHeaders);
      }

      if (url.pathname === '/new-prospect' && request.method === 'POST') {
        return await handleNewProspect(request, env, corsHeaders);
      }

      return new Response('Not Found', { status: 404 });

    } catch (error) {
      return new Response(JSON.stringify({
        error: error.message,
        stack: error.stack
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  },

  async scheduled(event, env, ctx) {
    console.log('Running scheduled token refresh');
    await refreshAccessToken(env);
  }
};

async function handleMcp(request, env, corsHeaders) {
  if (request.method === 'GET') {
    return new Response(JSON.stringify({
      server: 'oxley-qbo-mcp',
      protocol: MCP_PROTOCOL_VERSION,
      transport: 'streamable-http',
      auth: 'Bearer token required on POST'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const authHeader = request.headers.get('Authorization') || '';
  if (!env.MCP_AUTH_TOKEN) {
    return mcpError(null, -32001, 'Server misconfigured: MCP_AUTH_TOKEN not set', corsHeaders, 500);
  }
  if (authHeader !== `Bearer ${env.MCP_AUTH_TOKEN}`) {
    return mcpError(null, -32001, 'Unauthorized', corsHeaders, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return mcpError(null, -32700, 'Parse error', corsHeaders, 400);
  }

  if (Array.isArray(body)) {
    const responses = [];
    for (const msg of body) {
      const r = await dispatchMcp(msg, env);
      if (r) responses.push(r);
    }
    return new Response(JSON.stringify(responses), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const response = await dispatchMcp(body, env);
  if (response === null) {
    return new Response(null, { status: 202, headers: corsHeaders });
  }

  return new Response(JSON.stringify(response), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

function mcpError(id, code, message, corsHeaders, httpStatus = 200) {
  return new Response(JSON.stringify({
    jsonrpc: '2.0',
    id,
    error: { code, message }
  }), {
    status: httpStatus,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function dispatchMcp(req, env) {
  const { id, method, params } = req;
  const isNotification = id === undefined || id === null;

  try {
    let result;
    switch (method) {
      case 'initialize':
        result = {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'oxley-qbo-mcp', version: '1.0.0' }
        };
        break;
      case 'notifications/initialized':
      case 'notifications/cancelled':
        return null;
      case 'tools/list':
        result = { tools: TOOL_DEFINITIONS };
        break;
      case 'tools/call':
        result = await callTool(params?.name, params?.arguments || {}, env);
        break;
      case 'ping':
        result = {};
        break;
      default:
        if (isNotification) return null;
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
    }
    if (isNotification) return null;
    return { jsonrpc: '2.0', id, result };
  } catch (err) {
    if (isNotification) return null;
    return {
      jsonrpc: '2.0',
      id,
      result: {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true
      }
    };
  }
}

const TOOL_DEFINITIONS = [
  {
    name: 'qbo_query',
    description: `Run a QBO SQL-style SELECT against any entity. Examples: "SELECT * FROM Customer WHERE DisplayName LIKE '%JWT%'", "SELECT Id, DocNumber, TotalAmt FROM Invoice MAXRESULTS 1000".`,
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] }
  },
  {
    name: 'qbo_get',
    description: 'Fetch a single entity by its QBO Id. Returns the full entity including SyncToken needed for updates.',
    inputSchema: { type: 'object', properties: { entity: { type: 'string' }, id: { type: 'string' } }, required: ['entity', 'id'] }
  },
  {
    name: 'qbo_create',
    description: 'Create a new entity. Pass the full entity JSON as data.',
    inputSchema: { type: 'object', properties: { entity: { type: 'string' }, data: { type: 'object' } }, required: ['entity', 'data'] }
  },
  {
    name: 'qbo_update',
    description: 'Update an existing entity. Data MUST include Id and SyncToken. Include sparse:true for partial update.',
    inputSchema: { type: 'object', properties: { entity: { type: 'string' }, data: { type: 'object' } }, required: ['entity', 'data'] }
  },
  {
    name: 'qbo_delete',
    description: 'Delete or void an entity by Id and current SyncToken.',
    inputSchema: { type: 'object', properties: { entity: { type: 'string' }, id: { type: 'string' }, syncToken: { type: 'string' } }, required: ['entity', 'id', 'syncToken'] }
  },
  {
    name: 'qbo_batch',
    description: 'Execute up to 30 operations in one round-trip.',
    inputSchema: { type: 'object', properties: { BatchItemRequest: { type: 'array', items: { type: 'object' } } }, required: ['BatchItemRequest'] }
  },
  {
    name: 'qbo_report',
    description: 'Run a QBO report: ProfitAndLoss, BalanceSheet, AgedReceivables, CustomerSales, ItemSales, etc.',
    inputSchema: { type: 'object', properties: { report: { type: 'string' }, params: { type: 'object' } }, required: ['report'] }
  },
  {
    name: 'qbo_append_invoice_lines',
    description: 'Append new line items to an existing invoice. Handles GET-merge-PUT automatically.',
    inputSchema: {
      type: 'object',
      properties: {
        invoice_id: { type: 'string' },
        lines: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              item_id: { type: 'string' },
              item_name: { type: 'string' },
              description: { type: 'string' },
              quantity: { type: 'number' },
              unit_price: { type: 'number' },
              amount: { type: 'number' }
            }
          }
        }
      },
      required: ['invoice_id', 'lines']
    }
  },
  {
    name: 'qbo_find_items',
    description: 'Quick item lookup by name fragment.',
    inputSchema: { type: 'object', properties: { name_like: { type: 'string' }, limit: { type: 'number' } }, required: ['name_like'] }
  },
  {
    name: 'qbo_find_customers',
    description: 'Quick customer lookup by name fragment.',
    inputSchema: { type: 'object', properties: { name_like: { type: 'string' }, limit: { type: 'number' } }, required: ['name_like'] }
  }
];

async function callTool(name, args, env) {
  let data;
  switch (name) {
    case 'qbo_query':
      data = await qboRequest(`query?query=${encodeURIComponent(args.query)}`, env);
      break;
    case 'qbo_get':
      data = await qboRequest(`${args.entity.toLowerCase()}/${args.id}`, env);
      break;
    case 'qbo_create':
      data = await qboRequest(args.entity.toLowerCase(), env, 'POST', args.data);
      break;
    case 'qbo_update':
      data = await qboRequest(`${args.entity.toLowerCase()}?operation=update`, env, 'POST', args.data);
      break;
    case 'qbo_delete':
      data = await qboRequest(`${args.entity.toLowerCase()}?operation=delete`, env, 'POST', { Id: args.id, SyncToken: args.syncToken });
      break;
    case 'qbo_batch':
      data = await qboRequest('batch', env, 'POST', { BatchItemRequest: args.BatchItemRequest });
      break;
    case 'qbo_report': {
      const qs = args.params && Object.keys(args.params).length ? '?' + new URLSearchParams(args.params).toString() : '';
      data = await qboRequest(`reports/${args.report}${qs}`, env);
      break;
    }
    case 'qbo_append_invoice_lines':
      data = await appendInvoiceLines(args.invoice_id, args.lines, env);
      break;
    case 'qbo_find_items': {
      const limit = args.limit || 20;
      const safe = String(args.name_like).replace(/'/g, "''");
      const q = `SELECT Id, Name, UnitPrice, Type, IncomeAccountRef, ExpenseAccountRef FROM Item WHERE Name LIKE '%${safe}%' MAXRESULTS ${limit}`;
      data = await qboRequest(`query?query=${encodeURIComponent(q)}`, env);
      break;
    }
    case 'qbo_find_customers': {
      const limit = args.limit || 20;
      const safe = String(args.name_like).replace(/'/g, "''");
      const q = `SELECT Id, DisplayName, CompanyName, Balance, PrimaryEmailAddr, PrimaryPhone FROM Customer WHERE DisplayName LIKE '%${safe}%' MAXRESULTS ${limit}`;
      data = await qboRequest(`query?query=${encodeURIComponent(q)}`, env);
      break;
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

async function appendInvoiceLines(invoiceId, newLines, env) {
  const current = await qboRequest(`invoice/${invoiceId}`, env);
  const invoice = current.Invoice;
  if (!invoice) throw new Error(`Invoice ${invoiceId} not found`);

  const itemMatches = {};
  for (const line of newLines) {
    if (!line.item_id && line.item_name) {
      const safe = String(line.item_name).replace(/'/g, "''");
      const q = `SELECT Id, Name FROM Item WHERE Name LIKE '%${safe}%' MAXRESULTS 5`;
      const res = await qboRequest(`query?query=${encodeURIComponent(q)}`, env);
      const items = res.QueryResponse?.Item || [];
      if (items.length === 0) throw new Error(`No item found matching "${line.item_name}"`);
      line.item_id = items[0].Id;
      itemMatches[line.item_name] = { id: items[0].Id, matched_name: items[0].Name, alternates: items.slice(1).map(i => i.Name) };
    }
  }

  const existingLines = (invoice.Line || []).filter(l => l.DetailType !== 'SubTotalLineDetail');

  const appended = newLines.map(l => {
    const qty = l.quantity ?? 1;
    const unit = l.unit_price ?? 0;
    const amount = l.amount ?? (qty * unit);
    const line = {
      DetailType: 'SalesItemLineDetail',
      Amount: Number(amount.toFixed(2)),
      SalesItemLineDetail: { ItemRef: { value: String(l.item_id) }, Qty: qty, UnitPrice: unit }
    };
    if (l.description) line.Description = l.description;
    return line;
  });

  const payload = { Id: invoice.Id, SyncToken: invoice.SyncToken, sparse: true, Line: [...existingLines, ...appended] };
  const updated = await qboRequest('invoice?operation=update', env, 'POST', payload);

  return {
    invoice_id: invoiceId,
    doc_number: updated.Invoice?.DocNumber,
    lines_added: appended.length,
    previous_total: invoice.TotalAmt,
    new_total: updated.Invoice?.TotalAmt,
    customer: updated.Invoice?.CustomerRef?.name,
    item_matches: itemMatches
  };
}

async function qboRequest(path, env, method = 'GET', body = null) {
  let tokens = await getTokens(env);
  if (!tokens.expires_in || tokens.expires_in < 300) {
    tokens = await refreshAccessToken(env);
  }
  const sep = path.includes('?') ? '&' : '?';
  const url = `${QBO_API_BASE}/${REALM_ID}/${path}${sep}minorversion=${QBO_MINOR_VERSION}`;
  const opts = { method, headers: { 'Authorization': `Bearer ${tokens.access_token}`, 'Accept': 'application/json' } };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const response = await fetch(url, opts);
  const text = await response.text();
  if (!response.ok) throw new Error(`QBO ${method} ${path} → ${response.status}: ${text}`);
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

async function qboApiCall(endpoint, env) { return qboRequest(endpoint, env); }

async function getTokens(env) {
  const accessToken = await env.QBO_TOKENS.get('access_token');
  const refreshToken = await env.QBO_TOKENS.get('refresh_token');
  const expiresAt = await env.QBO_TOKENS.get('expires_at');
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = expiresAt ? parseInt(expiresAt) - now : null;
  return { access_token: accessToken, refresh_token: refreshToken, expires_in: expiresIn };
}

async function refreshAccessToken(env) {
  const tokens = await getTokens(env);
  if (!tokens.refresh_token) throw new Error('No refresh token available');
  const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + btoa(`${env.QBO_CLIENT_ID}:${env.QBO_CLIENT_SECRET}`)
    },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token })
  });
  if (!response.ok) throw new Error(`Token refresh failed: ${response.status} ${await response.text()}`);
  const data = await response.json();
  const now = Math.floor(Date.now() / 1000);
  await env.QBO_TOKENS.put('access_token', data.access_token);
  await env.QBO_TOKENS.put('refresh_token', data.refresh_token);
  await env.QBO_TOKENS.put('expires_at', (now + data.expires_in).toString());
  return { access_token: data.access_token, refresh_token: data.refresh_token, expires_in: data.expires_in };
}

async function handleDashboardSummary(env, corsHeaders) {
  const [invoicesRes, customersRes] = await Promise.all([
    qboRequest('query?query=SELECT Id, TotalAmt, Balance, DueDate, TxnDate, CustomerRef FROM Invoice MAXRESULTS 1000', env),
    qboRequest('query?query=SELECT Id, DisplayName, Balance FROM Customer MAXRESULTS 1000', env),
  ]);
  const invoices = invoicesRes.QueryResponse?.Invoice || [];
  const customers = customersRes.QueryResponse?.Customer || [];
  const today = new Date().toISOString().slice(0, 10);
  let totalAR = 0, overdueAR = 0, overdueCount = 0;
  for (const inv of invoices) {
    const bal = parseFloat(inv.Balance || 0);
    if (bal > 0) {
      totalAR += bal;
      if (inv.DueDate && inv.DueDate < today) { overdueAR += bal; overdueCount++; }
    }
  }
  const totalCustomers = customers.length;
  const activeCustomers = customers.filter(c => parseFloat(c.Balance || 0) > 0).length;
  return new Response(JSON.stringify({
    totalAR: totalAR.toFixed(2),
    overdueAR: overdueAR.toFixed(2),
    overdueCount,
    totalCustomers,
    activeCustomers,
    openInvoices: invoices.filter(i => parseFloat(i.Balance || 0) > 0).length,
    asOf: today,
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function handleOverdueInvoices(env, corsHeaders) {
  const res = await qboRequest('query?query=SELECT Id, DocNumber, TxnDate, DueDate, TotalAmt, Balance, CustomerRef FROM Invoice MAXRESULTS 1000', env);
  const today = new Date().toISOString().slice(0, 10);
  const overdue = (res.QueryResponse?.Invoice || [])
    .filter(inv => parseFloat(inv.Balance || 0) > 0 && inv.DueDate && inv.DueDate < today)
    .sort((a, b) => a.DueDate.localeCompare(b.DueDate));
  return new Response(JSON.stringify({ count: overdue.length, invoices: overdue }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleBankTransactions(env, corsHeaders) {
  const [purchasesRes, depositsRes] = await Promise.all([
    qboRequest('query?query=SELECT Id, TxnDate, TotalAmt, PaymentType, EntityRef, PrivateNote FROM Purchase ORDERBY TxnDate DESC MAXRESULTS 500', env),
    qboRequest('query?query=SELECT Id, TxnDate, TotalAmt, PrivateNote FROM Deposit ORDERBY TxnDate DESC MAXRESULTS 500', env),
  ]);
  const purchases = (purchasesRes.QueryResponse?.Purchase || []).map(t => ({
    id: t.Id, date: t.TxnDate, type: 'Purchase', amount: -Math.abs(parseFloat(t.TotalAmt || 0)),
    payee: t.EntityRef?.name || '', memo: t.PrivateNote || '', paymentType: t.PaymentType || '',
  }));
  const deposits = (depositsRes.QueryResponse?.Deposit || []).map(t => ({
    id: t.Id, date: t.TxnDate, type: 'Deposit', amount: parseFloat(t.TotalAmt || 0),
    payee: '', memo: t.PrivateNote || '', paymentType: '',
  }));
  const all = [...purchases, ...deposits].sort((a, b) => b.date.localeCompare(a.date));
  return new Response(JSON.stringify({ count: all.length, transactions: all }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleProfitLoss(url, env, corsHeaders) {
  const start = url.searchParams.get('start_date') || `${new Date().getFullYear()}-01-01`;
  const end = url.searchParams.get('end_date') || new Date().toISOString().slice(0, 10);
  const data = await qboRequest(`reports/ProfitAndLoss?start_date=${start}&end_date=${end}`, env);
  return new Response(JSON.stringify(data), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function handleTopCustomers(url, env, corsHeaders) {
  const year = url.searchParams.get('year') || new Date().getFullYear();
  const start = `${year}-01-01`;
  const end = `${year}-12-31`;
  const res = await qboRequest(`query?query=SELECT Id, DocNumber, TxnDate, TotalAmt, CustomerRef FROM Invoice MAXRESULTS 1000`, env);
  const invoices = res.QueryResponse?.Invoice || [];
  const byCustomer = {};
  for (const inv of invoices) {
    if (!inv.TxnDate || inv.TxnDate < start || inv.TxnDate > end) continue;
    const id = inv.CustomerRef?.value;
    if (!id) continue;
    if (!byCustomer[id]) byCustomer[id] = { id, name: inv.CustomerRef.name, total: 0, invoiceCount: 0 };
    byCustomer[id].total += parseFloat(inv.TotalAmt || 0);
    byCustomer[id].invoiceCount++;
  }
  const sorted = Object.values(byCustomer).sort((a, b) => b.total - a.total);
  return new Response(JSON.stringify({ year, count: sorted.length, customers: sorted }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleExpensesDetail(url, env, corsHeaders) {
  const start = url.searchParams.get('start_date') || `${new Date().getFullYear()}-01-01`;
  const end = url.searchParams.get('end_date') || new Date().toISOString().slice(0, 10);
  const [purchasesRes, billsRes] = await Promise.all([
    qboRequest('query?query=SELECT Id, TxnDate, TotalAmt, EntityRef, PrivateNote, PaymentType FROM Purchase ORDERBY TxnDate DESC MAXRESULTS 1000', env),
    qboRequest('query?query=SELECT Id, TxnDate, TotalAmt, VendorRef, PrivateNote, DueDate FROM Bill ORDERBY TxnDate DESC MAXRESULTS 1000', env),
  ]);
  const purchases = (purchasesRes.QueryResponse?.Purchase || [])
    .filter(t => t.TxnDate >= start && t.TxnDate <= end)
    .map(t => ({ id: t.Id, date: t.TxnDate, type: 'Purchase', amount: parseFloat(t.TotalAmt || 0), vendor: t.EntityRef?.name || '', memo: t.PrivateNote || '' }));
  const bills = (billsRes.QueryResponse?.Bill || [])
    .filter(t => t.TxnDate >= start && t.TxnDate <= end)
    .map(t => ({ id: t.Id, date: t.TxnDate, type: 'Bill', amount: parseFloat(t.TotalAmt || 0), vendor: t.VendorRef?.name || '', memo: t.PrivateNote || '', dueDate: t.DueDate || '' }));
  const all = [...purchases, ...bills].sort((a, b) => b.date.localeCompare(a.date));
  const total = all.reduce((s, t) => s + t.amount, 0);
  return new Response(JSON.stringify({ start, end, count: all.length, total: total.toFixed(2), expenses: all }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handlePaymentsByCustomer(env, corsHeaders) {
  const res = await qboRequest('query?query=SELECT Id, TxnDate, TotalAmt, CustomerRef, PaymentMethodRef, PrivateNote FROM Payment ORDERBY TxnDate DESC MAXRESULTS 1000', env);
  const payments = res.QueryResponse?.Payment || [];
  const byCustomer = {};
  for (const p of payments) {
    const id = p.CustomerRef?.value || 'unknown';
    if (!byCustomer[id]) byCustomer[id] = { id, name: p.CustomerRef?.name || 'Unknown', totalPaid: 0, payments: [] };
    const amt = parseFloat(p.TotalAmt || 0);
    byCustomer[id].totalPaid += amt;
    byCustomer[id].payments.push({ id: p.Id, date: p.TxnDate, amount: amt, method: p.PaymentMethodRef?.name || '', memo: p.PrivateNote || '' });
  }
  const sorted = Object.values(byCustomer).sort((a, b) => b.totalPaid - a.totalPaid);
  return new Response(JSON.stringify({ count: sorted.length, customers: sorted }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function plaidRequest(path, body, env) {
  const plaidToken = await env.QBO_TOKENS.get('plaid_access_token');
  if (!plaidToken) throw new Error('No Plaid access token in KV');
  const resp = await fetch(`https://production.plaid.com${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'PLAID-CLIENT-ID': env.PLAID_CLIENT_ID, 'PLAID-SECRET': env.PLAID_SECRET },
    body: JSON.stringify({ access_token: plaidToken, ...body }),
  });
  if (!resp.ok) throw new Error(`Plaid ${path} → ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

async function handleChaseTransactions(url, env, corsHeaders) {
  const days = parseInt(url.searchParams.get('days') || '90');
  const end = new Date().toISOString().slice(0, 10);
  const startDate = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  const data = await plaidRequest('/transactions/get', { start_date: startDate, end_date: end, options: { count: 500 } }, env);
  const txns = (data.transactions || []).map(t => ({
    id: t.transaction_id, date: t.date,
    amount: t.amount, name: t.name, merchantName: t.merchant_name || t.name,
    category: (t.category || []).join(' > '),
    pending: t.pending,
  }));
  return new Response(JSON.stringify({ days, count: txns.length, transactions: txns }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleChaseReport(url, env, corsHeaders) {
  const days = parseInt(url.searchParams.get('days') || '30');
  const end = new Date().toISOString().slice(0, 10);
  const startDate = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  const data = await plaidRequest('/transactions/get', { start_date: startDate, end_date: end, options: { count: 500 } }, env);
  const txns = data.transactions || [];
  const byCategory = {};
  for (const t of txns) {
    const cat = (t.category || ['Uncategorized'])[0];
    if (!byCategory[cat]) byCategory[cat] = { category: cat, total: 0, count: 0 };
    byCategory[cat].total += Math.abs(t.amount);
    byCategory[cat].count++;
  }
  const cats = Object.values(byCategory).sort((a, b) => b.total - a.total);
  const grandTotal = cats.reduce((s, c) => s + c.total, 0);
  const rows = txns.sort((a, b) => b.date.localeCompare(a.date))
    .map(t => `<tr><td>${t.date}</td><td>${t.merchant_name || t.name}</td><td>${(t.category||[]).join(' > ')}</td><td style="text-align:right">$${Math.abs(t.amount).toFixed(2)}</td></tr>`)
    .join('');
  const catRows = cats.map(c => `<tr><td>${c.category}</td><td style="text-align:right">${c.count}</td><td style="text-align:right">$${c.total.toFixed(2)}</td><td style="text-align:right">${(c.total/grandTotal*100).toFixed(1)}%</td></tr>`).join('');
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Chase Report</title>
<style>body{font-family:sans-serif;padding:20px;max-width:1100px;margin:0 auto}h1,h2{color:#333}table{width:100%;border-collapse:collapse;margin-bottom:30px}th{background:#333;color:#fff;padding:10px;text-align:left}td{padding:8px;border-bottom:1px solid #eee}tr:hover{background:#f9f9f9}.total{font-weight:bold;font-size:1.2em;margin-bottom:10px}</style></head>
<body><h1>Chase Spending Report</h1><p>${startDate} → ${end}</p>
<div class="total">Total: $${grandTotal.toFixed(2)} across ${txns.length} transactions</div>
<h2>By Category</h2><table><thead><tr><th>Category</th><th>Count</th><th>Total</th><th>%</th></tr></thead><tbody>${catRows}</tbody></table>
<h2>Transactions</h2><table><thead><tr><th>Date</th><th>Merchant</th><th>Category</th><th>Amount</th></tr></thead><tbody>${rows}</tbody></table>
</body></html>`;
  return new Response(html, { headers: { ...corsHeaders, 'Content-Type': 'text/html' } });
}

async function handleDad(url, env, corsHeaders) {
  const [summary, overdueRes, chaseRes] = await Promise.all([
    handleDashboardSummary(env, { 'Content-Type': 'application/json' }).then(r => r.json()),
    handleOverdueInvoices(env, { 'Content-Type': 'application/json' }).then(r => r.json()).catch(() => ({ invoices: [] })),
    handleChaseTransactions(url, env, { 'Content-Type': 'application/json' }).then(r => r.json()).catch(() => ({ transactions: [] })),
  ]);
  const overdueRows = (overdueRes.invoices || []).slice(0, 20)
    .map(inv => `<tr><td>${inv.DueDate}</td><td>${inv.CustomerRef?.name || ''}</td><td>#${inv.DocNumber}</td><td style="text-align:right;color:#c00">$${parseFloat(inv.Balance).toFixed(2)}</td></tr>`)
    .join('');
  const chaseRows = (chaseRes.transactions || []).slice(0, 30)
    .map(t => `<tr><td>${t.date}</td><td>${t.merchantName || t.name}</td><td>${t.category}</td><td style="text-align:right">$${Math.abs(t.amount).toFixed(2)}</td></tr>`)
    .join('');
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Oxley Dashboard</title>
<style>body{font-family:-apple-system,sans-serif;background:#f0f2f5;padding:20px;margin:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin-bottom:25px}.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,.08)}.stat-label{font-size:13px;color:#888;margin-bottom:6px}.stat-value{font-size:28px;font-weight:700;color:#1a1a2e}.stat-value.red{color:#dc2626}.section{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,.08);margin-bottom:20px}h1{color:#1a1a2e;margin-bottom:20px}h2{color:#333;margin-bottom:15px;font-size:18px}table{width:100%;border-collapse:collapse}th{background:#f8f9fa;padding:10px;text-align:left;font-size:13px;color:#555;border-bottom:2px solid #e5e7eb}td{padding:10px;font-size:14px;border-bottom:1px solid #f0f0f0}</style></head>
<body><h1>🚛 Oxley Tire Dashboard</h1>
<div class="grid">
  <div class="card"><div class="stat-label">Total AR</div><div class="stat-value">$${Number(summary.totalAR).toLocaleString()}</div></div>
  <div class="card"><div class="stat-label">Overdue AR</div><div class="stat-value red">$${Number(summary.overdueAR).toLocaleString()}</div></div>
  <div class="card"><div class="stat-label">Overdue Invoices</div><div class="stat-value red">${summary.overdueCount}</div></div>
  <div class="card"><div class="stat-label">Open Invoices</div><div class="stat-value">${summary.openInvoices}</div></div>
  <div class="card"><div class="stat-label">Active Customers</div><div class="stat-value">${summary.activeCustomers}</div></div>
</div>
<div class="section"><h2>⚠️ Overdue Invoices</h2><table><thead><tr><th>Due Date</th><th>Customer</th><th>Invoice</th><th>Balance</th></tr></thead><tbody>${overdueRows || '<tr><td colspan="4" style="color:#888">No overdue invoices</td></tr>'}</tbody></table></div>
<div class="section"><h2>🏦 Recent Chase Transactions</h2><table><thead><tr><th>Date</th><th>Merchant</th><th>Category</th><th>Amount</th></tr></thead><tbody>${chaseRows || '<tr><td colspan="4" style="color:#888">No transactions or Plaid not connected</td></tr>'}</tbody></table></div>
<p style="color:#aaa;font-size:12px;text-align:right">As of ${summary.asOf}</p></body></html>`;
  return new Response(html, { headers: { ...corsHeaders, 'Content-Type': 'text/html' } });
}

async function handleNewProspect(request, env, corsHeaders) {
  try {
    const body = await request.json();
    return new Response(JSON.stringify({ ok: true, received: body }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

async function fetchCustomers(env, corsHeaders) {
  const data = await qboRequest('query?query=SELECT * FROM Customer MAXRESULTS 1000', env);
  return new Response(JSON.stringify({ count: data.QueryResponse.Customer?.length || 0, customers: data.QueryResponse.Customer || [] }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchSalesData(env, corsHeaders) {
  const invoices = await qboRequest('query?query=SELECT * FROM Invoice MAXRESULTS 1000', env);
  return new Response(JSON.stringify({ count: invoices.QueryResponse.Invoice?.length || 0, invoices: invoices.QueryResponse.Invoice || [] }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function handleDirectQboQuery(sql, env, corsHeaders) {
  const data = await qboRequest(`query?query=${encodeURIComponent(sql)}`, env);
  const qr = data.QueryResponse || {};
  const entityKey = Object.keys(qr).find(k => k !== 'startPosition' && k !== 'maxResults' && k !== 'totalCount');
  const rows = entityKey ? (Array.isArray(qr[entityKey]) ? qr[entityKey] : [qr[entityKey]]) : [];
  return new Response(JSON.stringify({
    query: sql,
    entity: entityKey || null,
    count: rows.length,
    results: rows
  }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleQuery(request, env, corsHeaders) {
  const { query } = await request.json();
  if (!query) return new Response(JSON.stringify({ error: 'Query required' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  const queryType = parseQuery(query);
  let results;
  switch (queryType.type) {
    case 'declining_customers': results = await getDecliningCustomers(env); break;
    case 'gp_by_zip': results = await getGPByZip(env); break;
    case 'top_products': results = await getTopProducts(env, queryType.limit || 30); break;
    case 'top_gp_customers': results = await getTopGPCustomers(env, queryType.percentile || 30); break;
    default: results = await genericQuery(query, env);
  }
  await writeToSheets(env, query, results);
  return new Response(JSON.stringify({ query, type: queryType.type, resultCount: results.length, results, sheetUrl: `https://docs.google.com/spreadsheets/d/${SHEET_ID}` }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

function parseQuery(query) {
  const lower = query.toLowerCase();
  if (lower.includes('declining') || lower.includes('yoy') || lower.includes('qtd')) return { type: 'declining_customers' };
  if (lower.includes('gp') && (lower.includes('zip') || lower.includes('location'))) return { type: 'gp_by_zip' };
  if (lower.includes('product') || lower.includes('item')) { const match = lower.match(/top (\d+)/); return { type: 'top_products', limit: match ? parseInt(match[1]) : 30 }; }
  if (lower.includes('gp') && lower.includes('customer')) { const match = lower.match(/(\d+)%/); return { type: 'top_gp_customers', percentile: match ? parseInt(match[1]) : 30 }; }
  return { type: 'generic', query };
}

async function getDecliningCustomers(env) {
  const invoices = await qboRequest('query?query=SELECT * FROM Invoice MAXRESULTS 1000', env);
  const allInvoices = invoices.QueryResponse.Invoice || [];
  const now = new Date();
  const currentYear = now.getFullYear();
  const currentQuarter = Math.floor(now.getMonth() / 3) + 1;
  const quarterStart = new Date(currentYear, (currentQuarter - 1) * 3, 1);
  const lastYearQuarterStart = new Date(currentYear - 1, (currentQuarter - 1) * 3, 1);
  const lastYearQuarterEnd = new Date(currentYear - 1, currentQuarter * 3, 0);
  const customerSales = {};
  allInvoices.forEach(inv => {
    const invDate = new Date(inv.TxnDate);
    const customerId = inv.CustomerRef?.value;
    const customerName = inv.CustomerRef?.name || 'Unknown';
    const amount = parseFloat(inv.TotalAmt || 0);
    if (!customerId) return;
    if (!customerSales[customerId]) customerSales[customerId] = { name: customerName, currentYearTotal: 0, lastYearTotal: 0, currentQTD: 0, lastYearQTD: 0 };
    if (invDate.getFullYear() === currentYear) customerSales[customerId].currentYearTotal += amount;
    if (invDate.getFullYear() === currentYear - 1) customerSales[customerId].lastYearTotal += amount;
    if (invDate >= quarterStart) customerSales[customerId].currentQTD += amount;
    if (invDate >= lastYearQuarterStart && invDate <= lastYearQuarterEnd) customerSales[customerId].lastYearQTD += amount;
  });
  return Object.entries(customerSales).map(([id, data]) => ({
    customerId: id, customerName: data.name,
    currentYearSales: data.currentYearTotal, lastYearSales: data.lastYearTotal,
    yoyChange: data.currentYearTotal - data.lastYearTotal,
    yoyChangePercent: data.lastYearTotal > 0 ? ((data.currentYearTotal - data.lastYearTotal) / data.lastYearTotal * 100).toFixed(2) : 0,
    currentQTD: data.currentQTD, lastYearQTD: data.lastYearQTD,
    qtdChange: data.currentQTD - data.lastYearQTD,
    qtdChangePercent: data.lastYearQTD > 0 ? ((data.currentQTD - data.lastYearQTD) / data.lastYearQTD * 100).toFixed(2) : 0
  })).filter(c => c.yoyChange < 0 || c.qtdChange < 0).sort((a, b) => a.yoyChange - b.yoyChange).slice(0, 10);
}

async function getGPByZip(env) {
  const customers = await qboRequest('query?query=SELECT * FROM Customer MAXRESULTS 1000', env);
  const invoices = await qboRequest('query?query=SELECT * FROM Invoice MAXRESULTS 5000', env);
  const allCustomers = customers.QueryResponse.Customer || [];
  const allInvoices = invoices.QueryResponse.Invoice || [];
  const customerZips = {};
  allCustomers.forEach(c => { if (c.BillAddr?.PostalCode) customerZips[c.Id] = c.BillAddr.PostalCode.substring(0, 5); });
  const zipSales = {};
  allInvoices.forEach(inv => {
    const customerId = inv.CustomerRef?.value;
    const zip = customerZips[customerId];
    if (!zip) return;
    const total = parseFloat(inv.TotalAmt || 0);
    const gp = total * 0.30;
    if (!zipSales[zip]) zipSales[zip] = { zip, totalSales: 0, grossProfit: 0, invoiceCount: 0 };
    zipSales[zip].totalSales += total;
    zipSales[zip].grossProfit += gp;
    zipSales[zip].invoiceCount += 1;
  });
  return Object.values(zipSales).sort((a, b) => b.grossProfit - a.grossProfit).slice(0, 20);
}

async function getTopProducts(env, limit = 30) {
  const invoices = await qboRequest('query?query=SELECT * FROM Invoice MAXRESULTS 5000', env);
  const allInvoices = invoices.QueryResponse.Invoice || [];
  const productSales = {};
  allInvoices.forEach(inv => {
    (inv.Line || []).forEach(line => {
      if (line.DetailType !== 'SalesItemLineDetail') return;
      const itemRef = line.SalesItemLineDetail?.ItemRef;
      if (!itemRef) return;
      const itemId = itemRef.value;
      if (!productSales[itemId]) productSales[itemId] = { itemId, itemName: itemRef.name, totalQty: 0, totalRevenue: 0, invoiceCount: 0 };
      productSales[itemId].totalQty += parseFloat(line.SalesItemLineDetail.Qty || 0);
      productSales[itemId].totalRevenue += parseFloat(line.Amount || 0);
      productSales[itemId].invoiceCount += 1;
    });
  });
  return Object.values(productSales).sort((a, b) => b.totalQty - a.totalQty).slice(0, limit);
}

async function getTopGPCustomers(env, percentile = 30) {
  const invoices = await qboRequest('query?query=SELECT * FROM Invoice MAXRESULTS 5000', env);
  const allInvoices = invoices.QueryResponse.Invoice || [];
  const now = new Date();
  const currentYear = now.getFullYear();
  const currentMonth = now.getMonth();
  const currentQuarter = Math.floor(currentMonth / 3) + 1;
  const ytdStart = new Date(currentYear, 0, 1);
  const mtdStart = new Date(currentYear, currentMonth, 1);
  const qtdStart = new Date(currentYear, (currentQuarter - 1) * 3, 1);
  const customerGP = {};
  allInvoices.forEach(inv => {
    const invDate = new Date(inv.TxnDate);
    const customerId = inv.CustomerRef?.value;
    if (!customerId) return;
    const gp = parseFloat(inv.TotalAmt || 0) * 0.30;
    if (!customerGP[customerId]) customerGP[customerId] = { customerId, customerName: inv.CustomerRef?.name || 'Unknown', ytdGP: 0, mtdGP: 0, qtdGP: 0 };
    if (invDate >= ytdStart) customerGP[customerId].ytdGP += gp;
    if (invDate >= mtdStart) customerGP[customerId].mtdGP += gp;
    if (invDate >= qtdStart) customerGP[customerId].qtdGP += gp;
  });
  const sorted = Object.values(customerGP).sort((a, b) => b.ytdGP - a.ytdGP);
  return sorted.slice(0, Math.ceil(sorted.length * (percentile / 100)));
}

async function genericQuery(query, env) {
  const invoices = await qboRequest('query?query=SELECT * FROM Invoice MAXRESULTS 100', env);
  return invoices.QueryResponse.Invoice || [];
}

async function writeToSheets(env, query, results) {
  if (!results || results.length === 0) return;
  const serviceAccount = JSON.parse(env.SHEETS_API_KEY);
  const token = await getGoogleAccessToken(serviceAccount);
  const headers = Object.keys(results[0]);
  const rows = results.map(row => headers.map(h => row[h] || ''));
  await fetch(`${GOOGLE_SHEETS_API}/${SHEET_ID}/values/Sheet1!A1:Z10000:clear`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
  });
  const values = [[`Query: ${query}`], [`Generated: ${new Date().toLocaleString()}`], [], headers, ...rows];
  await fetch(`${GOOGLE_SHEETS_API}/${SHEET_ID}/values/Sheet1!A1:append?valueInputOption=RAW`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values })
  });
}

async function getGoogleAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const claim = { iss: serviceAccount.client_email, scope: 'https://www.googleapis.com/auth/spreadsheets', aud: 'https://oauth2.googleapis.com/token', exp: now + 3600, iat: now };
  const jwt = await signJWT(claim, serviceAccount.private_key);
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt })
  });
  const data = await response.json();
  return data.access_token;
}

async function signJWT(payload, privateKey) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const message = `${encodedHeader}.${encodedPayload}`;
  const pemKey = privateKey.replace(/\\n/g, '\n');
  const keyData = pemKey.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').replace(/\s/g, '');
  const binaryKey = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey('pkcs8', binaryKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, new TextEncoder().encode(message));
  return `${message}.${base64UrlEncode(signature)}`;
}

function base64UrlEncode(data) {
  let str;
  if (typeof data === 'string') str = btoa(unescape(encodeURIComponent(data)));
  else str = btoa(String.fromCharCode(...new Uint8Array(data)));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
