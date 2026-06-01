export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    try {
      if (url.pathname === '/' || url.pathname === '/dashboard') {
        return new Response(JSON.stringify({status:"ok",worker:"qbo-refresh-worker"}), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      if (url.pathname === '/api') {
        return new Response(JSON.stringify({
          name: 'Sales Command Center API',
          status: '✅ Auto-refresh enabled (every 50 min)',
          endpoints: {
            '/': 'Web dashboard',
            '/api': 'API info',
            '/token-status': 'Check token status',
            '/customers': 'List customers',
            '/sales-data': 'Sales summary',
            '/query': 'Natural language query (POST)',
            '/profit-loss': 'P&L report',
            '/top-customers': 'Top customers',
            '/bank-transactions': 'Recent bank transactions',
            '/overdue-invoices': 'Overdue invoices list',
            '/dashboard-summary': 'Full dashboard summary',
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
      
      if (url.pathname === '/query' && request.method === 'POST') {
        return await handleQuery(request, env, corsHeaders);
      }
      
      if (url.pathname === '/customers') {
        return await fetchCustomers(env, corsHeaders);
      }
      
      if (url.pathname === '/sales-data') {
        return await fetchSalesData(env, corsHeaders);
      }

      if (url.pathname === '/profit-loss') {
        const start = url.searchParams.get('start_date') || '2026-01-01';
        const end = url.searchParams.get('end_date') || new Date().toISOString().split('T')[0];
        return await fetchProfitLoss(env, corsHeaders, start, end);
      }

      if (url.pathname === '/top-customers') {
        const year = url.searchParams.get('year') || '2026';
        return await fetchTopCustomers(env, corsHeaders, year);
      }

      if (url.pathname === '/bank-transactions') {
        const limit = parseInt(url.searchParams.get('limit') || '100');
        return await fetchBankTransactions(env, corsHeaders, limit);
      }

      if (url.pathname === '/overdue-invoices') {
        return await fetchOverdueInvoices(env, corsHeaders);
      }

      if (url.pathname === '/dashboard-summary') {
        return await fetchDashboardSummary(env, corsHeaders);
      }



      if (url.pathname === '/expenses-detail') {
        const start = url.searchParams.get('start_date') || '2026-01-01';
        const end = url.searchParams.get('end_date') || new Date().toISOString().split('T')[0];
        return await fetchExpensesDetail(env, corsHeaders, start, end);
      }


      // Plaid Link page
      if (url.pathname === '/connect-chase') {
        const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connect Chase — Oxley Tire</title>
<style>
  body { background: #0a0a0a; color: #e8e8e8; font-family: 'Arial', sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .box { background: #111; border: 1px solid #222; border-top: 2px solid #e8a020; padding: 40px; max-width: 400px; width: 90%; text-align: center; }
  h1 { font-size: 24px; color: #e8a020; margin-bottom: 8px; letter-spacing: 2px; }
  p { color: #888; font-size: 14px; margin-bottom: 24px; }
  button { background: #e8a020; color: #000; border: none; padding: 16px 32px; font-size: 16px; font-weight: 700; cursor: pointer; width: 100%; letter-spacing: 1px; }
  button:hover { background: #f0b030; }
  button:disabled { background: #444; color: #666; cursor: not-allowed; }
  #status { margin-top: 16px; font-size: 13px; color: #888; min-height: 20px; }
  #status.success { color: #27ae60; }
  #status.error { color: #c0392b; }
</style>
</head>
<body>
<div class="box">
  <h1>OXLEY TIRE</h1>
  <p>Connect your Chase accounts to enable live transaction tracking. This is a one-time setup.</p>
  <button id="connect-btn" onclick="startLink()">CONNECT CHASE</button>
  <div id="status"></div>
</div>
<script src="https://cdn.plaid.com/link/v2/stable/link-initialize.js"></script>
<script>
async function startLink() {
  const btn = document.getElementById('connect-btn');
  const status = document.getElementById('status');
  btn.disabled = true;
  status.textContent = 'Initializing...';
  status.className = '';

  try {
    const res = await fetch('https://qbo-refresh-worker.moxley.workers.dev/plaid-link-token', { method: 'POST' });
    const data = await res.json();
    if (!data.link_token) throw new Error(data.error || 'Failed to get link token');

    const handler = Plaid.create({
      token: data.link_token,
      onSuccess: async (public_token, metadata) => {
        status.textContent = 'Exchanging token...';
        const exchangeRes = await fetch('https://qbo-refresh-worker.moxley.workers.dev/plaid-exchange', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ public_token, metadata })
        });
        const exchangeData = await exchangeRes.json();
        if (exchangeData.success) {
          status.textContent = '✅ Chase connected! Accounts: ' + exchangeData.accounts.join(', ');
          status.className = 'success';
          btn.textContent = 'CONNECTED';
        } else {
          throw new Error(exchangeData.error || 'Exchange failed');
        }
      },
      onExit: (err, metadata) => {
        btn.disabled = false;
        if (err) {
          status.textContent = 'Error: ' + (err.display_message || err.error_message || err.error_code || JSON.stringify(err));
          status.className = 'error';
          console.log('Plaid exit error:', JSON.stringify(err), JSON.stringify(metadata));
        } else {
          status.textContent = 'Cancelled.';
        }
      }
    });
    handler.open();
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
    status.className = 'error';
    btn.disabled = false;
  }
}
</script>
</body>
</html>
PYEOF
echo "Done"`;
        return new Response(html, {
          headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      // Create Plaid link token
      if (url.pathname === '/plaid-link-token' && request.method === 'POST') {
        return await createPlaidLinkToken(env, corsHeaders);
      }

      // Exchange public token for access token
      if (url.pathname === '/plaid-exchange' && request.method === 'POST') {
        return await exchangePlaidToken(request, env, corsHeaders);
      }

      // Get Chase transactions from Plaid
      if (url.pathname === '/chase-transactions') {
        const days = parseInt(url.searchParams.get('days') || '90');
        return await getChaseTransactions(env, corsHeaders, days);
      }

      if (url.pathname === '/dad') {
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oxley Tire — Command Center</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0a0a;
    --surface: #111111;
    --border: #222222;
    --accent: #e8a020;
    --accent2: #c0392b;
    --green: #27ae60;
    --text: #e8e8e8;
    --muted: #666666;
    --mono: 'IBM Plex Mono', monospace;
    --sans: 'IBM Plex Sans', sans-serif;
    --display: 'Bebas Neue', sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 0;
  }

  header {
    background: var(--surface);
    border-bottom: 2px solid var(--accent);
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    font-family: var(--display);
    font-size: 28px;
    letter-spacing: 2px;
    color: var(--accent);
    line-height: 1;
  }

  .logo span {
    color: var(--text);
    font-size: 13px;
    font-family: var(--mono);
    display: block;
    letter-spacing: 3px;
    margin-top: 2px;
  }

  #last-updated {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    text-align: right;
  }

  #refresh-btn {
    background: var(--accent);
    color: #000;
    border: none;
    padding: 8px 16px;
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    letter-spacing: 1px;
    margin-top: 4px;
    display: block;
    width: 100%;
  }

  #refresh-btn:hover { background: #f0b030; }
  #refresh-btn:active { background: #c8881a; }

  .main { padding: 16px; max-width: 900px; margin: 0 auto; }

  /* Loading */
  #loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 80px 20px;
    gap: 16px;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .loading-text {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--muted);
    letter-spacing: 2px;
  }

  /* Summary Cards */
  .summary-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 20px;
  }

  @media (min-width: 600px) {
    .summary-grid { grid-template-columns: repeat(3, 1fr); }
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 16px;
    position: relative;
    overflow: hidden;
  }

  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
  }

  .card.red::before { background: var(--accent2); }
  .card.green::before { background: var(--green); }

  .card-label {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .card-value {
    font-family: var(--display);
    font-size: 32px;
    line-height: 1;
    letter-spacing: 1px;
  }

  .card-value.red { color: var(--accent2); }
  .card-value.green { color: var(--green); }
  .card-value.amber { color: var(--accent); }

  .card-sub {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-top: 4px;
  }

  /* Section */
  .section {
    margin-bottom: 24px;
  }

  .section-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .section-title {
    font-family: var(--display);
    font-size: 22px;
    letter-spacing: 2px;
    color: var(--accent);
  }

  .badge {
    background: var(--accent2);
    color: #fff;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 2px;
  }

  .badge.green { background: var(--green); }
  .badge.amber { background: var(--accent); color: #000; }

  /* Invoice rows */
  .invoice-list { display: flex; flex-direction: column; gap: 6px; }

  .invoice-row {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent2);
    padding: 12px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }

  .invoice-row:hover { background: #181818; border-color: var(--accent); }

  .invoice-row.urgent { border-left-color: var(--accent2); }
  .invoice-row.warn { border-left-color: var(--accent); }
  .invoice-row.ok { border-left-color: #444; }

  .inv-customer {
    font-weight: 600;
    font-size: 14px;
    flex: 1;
    min-width: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .inv-meta {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-top: 2px;
  }

  .inv-amount {
    font-family: var(--mono);
    font-size: 15px;
    font-weight: 600;
    color: var(--accent2);
    white-space: nowrap;
  }

  .inv-days {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    text-align: right;
    white-space: nowrap;
  }

  .inv-days.hot { color: var(--accent2); font-weight: 600; }
  .inv-days.warm { color: var(--accent); }

  /* Transactions */
  .txn-list { display: flex; flex-direction: column; gap: 4px; }

  .txn-row {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 10px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .txn-type {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    padding: 2px 6px;
    border-radius: 2px;
    white-space: nowrap;
  }

  .txn-type.deposit { background: rgba(39,174,96,0.15); color: var(--green); }
  .txn-type.expense { background: rgba(192,57,43,0.15); color: var(--accent2); }

  .txn-desc {
    flex: 1;
    min-width: 0;
    font-size: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .txn-sub {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
  }

  .txn-amount {
    font-family: var(--mono);
    font-size: 14px;
    font-weight: 600;
    white-space: nowrap;
  }

  .txn-amount.pos { color: var(--green); }
  .txn-amount.neg { color: var(--accent2); }

  .txn-date {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    white-space: nowrap;
  }

  /* Instructions box */
  .instructions {
    background: #0f1a0f;
    border: 1px solid var(--green);
    border-left: 3px solid var(--green);
    padding: 16px;
    margin-bottom: 24px;
  }

  .instructions h3 {
    font-family: var(--display);
    font-size: 18px;
    color: var(--green);
    letter-spacing: 2px;
    margin-bottom: 10px;
  }

  .instructions p {
    font-size: 13px;
    line-height: 1.7;
    color: #aaa;
    margin-bottom: 6px;
  }

  .instructions strong { color: var(--text); }

  /* Error */
  .error-box {
    background: #1a0a0a;
    border: 1px solid var(--accent2);
    padding: 20px;
    text-align: center;
    font-family: var(--mono);
    font-size: 13px;
    color: var(--accent2);
  }

  /* Show more */
  .show-more {
    text-align: center;
    margin-top: 10px;
  }

  .show-more button {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 12px;
    padding: 8px 20px;
    cursor: pointer;
    letter-spacing: 1px;
  }

  .show-more button:hover { border-color: var(--accent); color: var(--accent); }

  #content { display: none; }
</style>
</head>
<body>

<header>
  <div class="logo">
    OXLEY TIRE
    <span>COMMAND CENTER</span>
  </div>
  <div id="last-updated">
    <div id="update-time">Loading...</div>
    <button id="refresh-btn" onclick="loadData()">↻ REFRESH</button>
  </div>
</header>

<div class="main">

  <div id="loading">
    <div class="spinner"></div>
    <div class="loading-text">PULLING LIVE DATA...</div>
  </div>

  <div id="error" style="display:none">
    <div class="error-box">Failed to load data. Check connection and try refreshing.</div>
  </div>

  <div id="content">

    <!-- Summary -->
    <div class="summary-grid" id="summary-cards"></div>

    <!-- Overdue Invoices -->
    <div class="section">
      <div class="section-header">
        <div class="section-title">OVERDUE INVOICES</div>
        <div class="badge" id="overdue-badge">—</div>
      </div>
      <div class="invoice-list" id="invoice-list"></div>
      <div class="show-more" id="invoice-more" style="display:none">
        <button onclick="showAllInvoices()">SHOW ALL OVERDUE</button>
      </div>
    </div>

    <!-- Recent Deposits -->
    <div class="section">
      <div class="section-header">
        <div class="section-title">RECENT DEPOSITS</div>
        <div class="badge green">MONEY IN</div>
      </div>
      <div class="txn-list" id="deposit-list"></div>
    </div>

    <!-- Recent Expenses -->
    <div class="section">
      <div class="section-header">
        <div class="section-title">RECENT EXPENSES</div>
        <div class="badge amber">MONEY OUT</div>
      </div>
      <div class="txn-list" id="expense-list"></div>
    </div>

  </div>
</div>

<script>
const WORKER = 'https://qbo-refresh-worker.moxley.workers.dev';
let allInvoices = [];
let showingAll = false;

function fmt(n) {
  return '$' + Math.abs(n).toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
}

function fmtDate(d) {
  if (!d) return '';
  const parts = d.split('-');
  return \`\${parts[1]}/\${parts[2]}/\${parts[0].slice(2)}\`;
}

async function loadData() {
  document.getElementById('loading').style.display = 'flex';
  document.getElementById('content').style.display = 'none';
  document.getElementById('error').style.display = 'none';
  document.getElementById('refresh-btn').textContent = '↻ LOADING...';

  try {
    const [summaryRes, txnRes] = await Promise.all([
      fetch(WORKER + '/dashboard-summary'),
      fetch(WORKER + '/chase-transactions?days=90')
    ]);

    const summary = await summaryRes.json();
    const txns = await txnRes.json();

    renderSummary(summary, txns);
    renderInvoices(summary.topOverdueAccounts || []);
    renderTransactions(txns.transactions || []);

    document.getElementById('update-time').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    document.getElementById('refresh-btn').textContent = '↻ REFRESH';
    document.getElementById('loading').style.display = 'none';
    document.getElementById('content').style.display = 'block';

  } catch(e) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('error').style.display = 'block';
    document.getElementById('refresh-btn').textContent = '↻ REFRESH';
    console.error(e);
  }
}

function renderSummary(data, txnData) {
  const s = data.summary;
  const accounts = txnData?.accounts || [];
  const checking = accounts.find(a => a.mask === '2236');
  const cc = accounts.find(a => a.mask === '8784');
  const cards = [
    { label: 'OVERDUE AR', value: fmt(s.totalOverdue), sub: s.overdueCount + ' invoices', cls: 'red' },
    { label: 'CHECKING 2236', value: checking ? fmt(checking.balance) : '--', sub: checking ? fmt(checking.available) + ' available' : 'Live Chase', cls: 'green' },
    { label: 'CC BALANCE 8784', value: cc ? fmt(cc.balance) : '--', sub: cc ? fmt(cc.available) + ' available' : 'Live Chase', cls: 'red' },
    { label: 'MTD REVENUE', value: fmt(s.monthRevenue), sub: 'This month QBO', cls: 'green' },
    { label: 'MTD NET', value: fmt(s.netThisMonth), sub: s.netThisMonth >= 0 ? 'Profitable' : 'In the red', cls: s.netThisMonth >= 0 ? 'green' : 'red' },
    { label: 'AS OF', value: fmtDate(data.asOf), sub: 'Live data', cls: '' },
  ];

  document.getElementById('summary-cards').innerHTML = cards.map(c => \`
    <div class="card \${c.cls}">
      <div class="card-label">\${c.label}</div>
      <div class="card-value \${c.cls}">\${c.value}</div>
      <div class="card-sub">\${c.sub}</div>
    </div>
  \`).join('');
}

function renderInvoices(invoices) {
  allInvoices = invoices;
  document.getElementById('overdue-badge').textContent = invoices.length + ' accounts';
  renderInvoiceRows(invoices.slice(0, 15));
  if (invoices.length > 15) {
    document.getElementById('invoice-more').style.display = 'block';
  }
}

function renderInvoiceRows(invoices) {
  document.getElementById('invoice-list').innerHTML = invoices.map(inv => {
    const urgency = inv.daysOverdue > 60 ? 'urgent' : inv.daysOverdue > 30 ? 'warn' : 'ok';
    const daysCls = inv.daysOverdue > 60 ? 'hot' : inv.daysOverdue > 30 ? 'warm' : '';
    return \`
      <div class="invoice-row \${urgency}">
        <div>
          <div class="inv-customer">\${inv.customer}</div>
          <div class="inv-meta">INV #\${inv.invoiceNum} · Due \${fmtDate(inv.dueDate)}</div>
        </div>
        <div style="text-align:right">
          <div class="inv-amount">\${fmt(inv.balance)}</div>
          <div class="inv-days \${daysCls}">\${inv.daysOverdue}d overdue</div>
        </div>
      </div>
    \`;
  }).join('');
}

function showAllInvoices() {
  showingAll = true;
  renderInvoiceRows(allInvoices);
  document.getElementById('invoice-more').style.display = 'none';
}

function renderTransactions(txns) {
  const deposits = txns.filter(t => t.type === 'DEPOSIT');
  const expenses = txns.filter(t => t.type === 'EXPENSE');

  document.getElementById('deposit-list').innerHTML = deposits.length ? deposits.map(t => \`
    <div class="txn-row">
      <span class="txn-type deposit">DEPOSIT</span>
      <div class="txn-desc">
        <div>\${t.account || 'Bank Deposit'}</div>
        <div class="txn-sub">\${t.memo || '—'}</div>
      </div>
      <div style="text-align:right">
        <div class="txn-amount pos">\${fmt(t.amount)}</div>
        <div class="txn-date">\${fmtDate(t.date)}</div>
      </div>
    </div>
  \`).join('') : '<div style="color:var(--muted);font-size:13px;padding:12px">No recent deposits found.</div>';

  document.getElementById('expense-list').innerHTML = expenses.length ? expenses.map(t => \`
    <div class="txn-row">
      <span class="txn-type expense">EXPENSE</span>
      <div class="txn-desc">
        <div>\${t.entity || t.account || 'Expense'}</div>
        <div class="txn-sub">\${t.account || ''}</div>
      </div>
      <div style="text-align:right">
        <div class="txn-amount neg">\${fmt(t.amount)}</div>
        <div class="txn-date">\${fmtDate(t.date)}</div>
      </div>
    </div>
  \`).join('') : '<div style="color:var(--muted);font-size:13px;padding:12px">No recent expenses found.</div>';
}

loadData();
</script>
</body>
</html>
`;
        return new Response(html, {
          headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' }
        });
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
  return data;
}

async function qboApiCall(endpoint, env) {
  let tokens = await getTokens(env);
  if (!tokens.expires_in || tokens.expires_in < 300) {
    tokens = await refreshAccessToken(env);
  }
  
  const fullUrl = endpoint.startsWith('https://') 
    ? endpoint 
    : `${QBO_API_BASE}/${REALM_ID}/${endpoint}`;

  const response = await fetch(fullUrl, {
    headers: {
      'Authorization': `Bearer ${tokens.access_token}`,
      'Accept': 'application/json'
    }
  });
  
  if (!response.ok) throw new Error(`QBO API error: ${response.status} ${await response.text()}`);
  return await response.json();
}

async function fetchCustomers(env, corsHeaders) {
  const data = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Customer MAXRESULTS 1000'), env);
  return new Response(JSON.stringify({
    count: data.QueryResponse.Customer?.length || 0,
    customers: data.QueryResponse.Customer || []
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchSalesData(env, corsHeaders) {
  const invoices = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
  return new Response(JSON.stringify({
    count: invoices.QueryResponse.Invoice?.length || 0,
    invoices: invoices.QueryResponse.Invoice || []
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchBankTransactions(env, corsHeaders, limit = 100) {
  // Pull purchases (expenses/payments out)
  const purchaseQuery = encodeURIComponent(`SELECT * FROM Purchase MAXRESULTS ${limit}`);
  const depositQuery = encodeURIComponent(`SELECT * FROM Deposit MAXRESULTS ${limit}`);

  const [purchaseData, depositData] = await Promise.all([
    qboApiCall(`query?query=${purchaseQuery}`, env),
    qboApiCall(`query?query=${depositQuery}`, env)
  ]);

  const purchases = (purchaseData.QueryResponse.Purchase || []).map(p => ({
    type: 'EXPENSE',
    date: p.TxnDate,
    amount: -Math.abs(parseFloat(p.TotalAmt || 0)),
    memo: p.PrivateNote || p.PaymentMethodRef?.name || '',
    account: p.AccountRef?.name || '',
    entity: p.EntityRef?.name || p.VendorRef?.name || '',
    id: p.Id
  }));

  const deposits = (depositData.QueryResponse.Deposit || []).map(d => ({
    type: 'DEPOSIT',
    date: d.TxnDate,
    amount: parseFloat(d.TotalAmt || 0),
    memo: d.PrivateNote || '',
    account: d.DepositToAccountRef?.name || '',
    entity: '',
    id: d.Id
  }));

  const all = [...purchases, ...deposits]
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  return new Response(JSON.stringify({
    count: all.length,
    transactions: all
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchOverdueInvoices(env, corsHeaders) {
  const today = new Date().toISOString().split('T')[0];
  const query = encodeURIComponent(`SELECT * FROM Invoice WHERE DueDate < '${today}' AND Balance > '0' MAXRESULTS 500`);
  const data = await qboApiCall(`query?query=${query}`, env);
  const invoices = data.QueryResponse.Invoice || [];

  const overdue = invoices.map(inv => ({
    id: inv.Id,
    invoiceNum: inv.DocNumber,
    customer: inv.CustomerRef?.name || 'Unknown',
    amount: parseFloat(inv.TotalAmt || 0),
    balance: parseFloat(inv.Balance || 0),
    dueDate: inv.DueDate,
    txnDate: inv.TxnDate,
    daysOverdue: Math.floor((new Date() - new Date(inv.DueDate)) / (1000 * 60 * 60 * 24)),
    email: inv.BillEmail?.Address || ''
  })).sort((a, b) => b.daysOverdue - a.daysOverdue);

  const totalOverdue = overdue.reduce((sum, inv) => sum + inv.balance, 0);

  return new Response(JSON.stringify({
    count: overdue.length,
    totalOverdue: Math.round(totalOverdue * 100) / 100,
    invoices: overdue
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchDashboardSummary(env, corsHeaders) {
  const today = new Date().toISOString().split('T')[0];
  const firstOfYear = '2026-01-01';
  const firstOfMonth = today.substring(0, 7) + '-01';

  const [
    overdueData,
    invoiceData,
    purchaseData,
    depositData
  ] = await Promise.all([
    qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Invoice WHERE DueDate < '${today}' AND Balance > '0' MAXRESULTS 500`)}`, env),
    qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Invoice WHERE TxnDate >= '${firstOfMonth}' MAXRESULTS 500`)}`, env),
    qboApiCall(`query?query=${encodeURIComponent('SELECT * FROM Purchase MAXRESULTS 50')}`, env),
    qboApiCall(`query?query=${encodeURIComponent('SELECT * FROM Deposit MAXRESULTS 50')}`, env)
  ]);

  const overdueInvoices = overdueData.QueryResponse.Invoice || [];
  const monthInvoices = invoiceData.QueryResponse.Invoice || [];
  const purchases = purchaseData.QueryResponse.Purchase || [];
  const deposits = depositData.QueryResponse.Deposit || [];

  const totalOverdue = overdueInvoices.reduce((s, i) => s + parseFloat(i.Balance || 0), 0);
  const monthRevenue = monthInvoices.reduce((s, i) => s + parseFloat(i.TotalAmt || 0), 0);
  const monthExpenses = purchases.reduce((s, p) => s + parseFloat(p.TotalAmt || 0), 0);

  // Top overdue by balance
  const topOverdue = overdueInvoices
    .sort((a, b) => parseFloat(b.Balance) - parseFloat(a.Balance))
    
    .map(inv => ({
      customer: inv.CustomerRef?.name,
      balance: parseFloat(inv.Balance || 0),
      daysOverdue: Math.floor((new Date() - new Date(inv.DueDate)) / 86400000),
      dueDate: inv.DueDate,
      invoiceNum: inv.DocNumber
    }));

  // Recent deposits
  const recentDeposits = deposits
    .sort((a, b) => new Date(b.TxnDate) - new Date(a.TxnDate))
    
    .map(d => ({
      date: d.TxnDate,
      amount: parseFloat(d.TotalAmt || 0),
      account: d.DepositToAccountRef?.name || ''
    }));

  // Recent expenses
  const recentExpenses = purchases
    .sort((a, b) => new Date(b.TxnDate) - new Date(a.TxnDate))
    
    .map(p => ({
      date: p.TxnDate,
      amount: parseFloat(p.TotalAmt || 0),
      vendor: p.EntityRef?.name || p.VendorRef?.name || '',
      account: p.AccountRef?.name || ''
    }));

  return new Response(JSON.stringify({
    asOf: today,
    summary: {
      totalOverdue: Math.round(totalOverdue * 100) / 100,
      overdueCount: overdueInvoices.length,
      monthRevenue: Math.round(monthRevenue * 100) / 100,
      monthExpenses: Math.round(monthExpenses * 100) / 100,
      netThisMonth: Math.round((monthRevenue - monthExpenses) * 100) / 100
    },
    topOverdueAccounts: topOverdue,
    recentDeposits,
    recentExpenses
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchProfitLoss(env, corsHeaders, startDate, endDate) {
  const realmId = REALM_ID;
  const url = `${QBO_API_BASE}/${realmId}/reports/ProfitAndLoss?start_date=${startDate}&end_date=${endDate}&minorversion=65`;
  const data = await qboApiCall(url, env);
  return new Response(JSON.stringify(data), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function fetchTopCustomers(env, corsHeaders, year) {
  const query = `SELECT * FROM Invoice WHERE TxnDate >= '${year}-01-01' AND TxnDate <= '${year}-12-31' MAXRESULTS 1000`;
  const data = await qboApiCall(`query?query=${encodeURIComponent(query)}`, env);
  const invoices = data?.QueryResponse?.Invoice || [];
  const custs = {};
  for (const inv of invoices) {
    const name = inv.CustomerRef?.name || 'Unknown';
    custs[name] = (custs[name] || 0) + parseFloat(inv.TotalAmt || 0);
  }
  const sorted = Object.entries(custs).sort((a, b) => b[1] - a[1]).slice(0, 25).map(([name, total]) => ({ name, total: Math.round(total * 100) / 100 }));
  return new Response(JSON.stringify({ year, customers: sorted }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
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
  const invoices = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
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
  return Object.entries(customerSales).map(([id, data]) => ({ customerId: id, customerName: data.name, currentYearSales: data.currentYearTotal, lastYearSales: data.lastYearTotal, yoyChange: data.currentYearTotal - data.lastYearTotal, yoyChangePercent: data.lastYearTotal > 0 ? ((data.currentYearTotal - data.lastYearTotal) / data.lastYearTotal * 100).toFixed(2) : 0, currentQTD: data.currentQTD, lastYearQTD: data.lastYearQTD, qtdChange: data.currentQTD - data.lastYearQTD, qtdChangePercent: data.lastYearQTD > 0 ? ((data.currentQTD - data.lastYearQTD) / data.lastYearQTD * 100).toFixed(2) : 0 })).filter(c => c.yoyChange < 0 || c.qtdChange < 0).sort((a, b) => a.yoyChange - b.yoyChange).slice(0, 10);
}

async function getGPByZip(env) {
  const customers = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Customer MAXRESULTS 1000'), env);
  const invoices = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
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
  const invoices = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
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
  const invoices = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
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
    const customerName = inv.CustomerRef?.name || 'Unknown';
    const gp = parseFloat(inv.TotalAmt || 0) * 0.30;
    if (!customerId) return;
    if (!customerGP[customerId]) customerGP[customerId] = { customerId, customerName, ytdGP: 0, mtdGP: 0, qtdGP: 0 };
    if (invDate >= ytdStart) customerGP[customerId].ytdGP += gp;
    if (invDate >= mtdStart) customerGP[customerId].mtdGP += gp;
    if (invDate >= qtdStart) customerGP[customerId].qtdGP += gp;
  });
  const sorted = Object.values(customerGP).sort((a, b) => b.ytdGP - a.ytdGP);
  return sorted.slice(0, Math.ceil(sorted.length * (percentile / 100)));
}

async function genericQuery(query, env) {
  const invoices = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 100'), env);
  return invoices.QueryResponse.Invoice || [];
}

async function fetchExpensesDetail(env, corsHeaders, startDate, endDate) {
  // Pull Bills, BillPayments, and Purchases in parallel
  const [billData, billPayData, purchaseData] = await Promise.all([
    qboApiCall('query?query=' + encodeURIComponent(`SELECT * FROM Bill WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 1000`), env),
    qboApiCall('query?query=' + encodeURIComponent(`SELECT * FROM BillPayment WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 1000`), env),
    qboApiCall('query?query=' + encodeURIComponent(`SELECT * FROM Purchase WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 1000`), env)
  ]);

  const bills = (billData.QueryResponse.Bill || []).map(b => ({
    type: 'BILL',
    id: b.Id,
    date: b.TxnDate,
    dueDate: b.DueDate,
    vendor: b.VendorRef?.name || 'Unknown',
    amount: parseFloat(b.TotalAmt || 0),
    balance: parseFloat(b.Balance || 0),
    paid: parseFloat(b.TotalAmt || 0) - parseFloat(b.Balance || 0),
    memo: b.PrivateNote || '',
    lineItems: (b.Line || []).filter(l => l.DetailType === 'AccountBasedExpenseLineDetail' || l.DetailType === 'ItemBasedExpenseLineDetail').map(l => ({
      description: l.Description || l.AccountBasedExpenseLineDetail?.AccountRef?.name || l.ItemBasedExpenseLineDetail?.ItemRef?.name || '',
      amount: parseFloat(l.Amount || 0),
      account: l.AccountBasedExpenseLineDetail?.AccountRef?.name || l.ItemBasedExpenseLineDetail?.ItemRef?.name || ''
    }))
  }));

  const billPayments = (billPayData.QueryResponse.BillPayment || []).map(bp => ({
    type: 'BILL_PAYMENT',
    id: bp.Id,
    date: bp.TxnDate,
    vendor: bp.VendorRef?.name || 'Unknown',
    amount: parseFloat(bp.TotalAmt || 0),
    paymentMethod: bp.PayType || '',
    checkNum: bp.CheckPayment?.PrintStatus || '',
    bankAccount: bp.CheckPayment?.BankAccountRef?.name || bp.CreditCardPayment?.CCAccountRef?.name || '',
    memo: bp.PrivateNote || ''
  }));

  const purchases = (purchaseData.QueryResponse.Purchase || [])
    .filter(p => !(p.PrivateNote || '').includes('QuickBooks Payments'))
    .map(p => ({
      type: 'PURCHASE',
      id: p.Id,
      date: p.TxnDate,
      vendor: p.EntityRef?.name || p.VendorRef?.name || 'Unknown',
      amount: parseFloat(p.TotalAmt || 0),
      account: p.AccountRef?.name || '',
      paymentMethod: p.PaymentType || '',
      memo: p.PrivateNote || '',
      lineItems: (p.Line || []).filter(l => l.DetailType === 'AccountBasedExpenseLineDetail' || l.DetailType === 'ItemBasedExpenseLineDetail').map(l => ({
        description: l.Description || '',
        amount: parseFloat(l.Amount || 0),
        account: l.AccountBasedExpenseLineDetail?.AccountRef?.name || l.ItemBasedExpenseLineDetail?.ItemRef?.name || ''
      }))
    }));

  // Combine and sort by date desc
  const all = [...bills, ...billPayments, ...purchases]
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  // Totals
  const totalBills = bills.reduce((s, b) => s + b.amount, 0);
  const totalPaid = billPayments.reduce((s, b) => s + b.amount, 0);
  const totalPurchases = purchases.reduce((s, b) => s + b.amount, 0);

  // Group by vendor
  const byVendor = {};
  [...bills, ...billPayments, ...purchases].forEach(t => {
    const v = t.vendor;
    if (!byVendor[v]) byVendor[v] = { vendor: v, total: 0, count: 0 };
    byVendor[v].total += t.amount;
    byVendor[v].count += 1;
  });
  const vendorSummary = Object.values(byVendor)
    .sort((a, b) => b.total - a.total);

  return new Response(JSON.stringify({
    period: { start: startDate, end: endDate },
    summary: {
      totalBills: Math.round(totalBills * 100) / 100,
      totalBillPayments: Math.round(totalPaid * 100) / 100,
      totalPurchases: Math.round(totalPurchases * 100) / 100,
      totalExpenses: Math.round((totalBills + totalPurchases) * 100) / 100
    },
    byVendor: vendorSummary,
    transactions: all
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function createPlaidLinkToken(env, corsHeaders) {
  const response = await fetch('https://production.plaid.com/link/token/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: env.PLAID_CLIENT_ID,
      secret: env.PLAID_SECRET,
      client_name: 'Oxley Tire Inc.',
      country_codes: ['US'],
      language: 'en',
      user: { client_user_id: 'oxley-matt' },
      products: ['transactions'],
      redirect_uri: 'https://inventory-setup-b3f20.web.app/connect-chase.html'
    })
  });
  const data = await response.json();
  console.log('Plaid link token response:', JSON.stringify(data));
  if (!response.ok) return new Response(JSON.stringify({ error: data.error_message || 'Link token failed', details: data }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  return new Response(JSON.stringify({ link_token: data.link_token }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function exchangePlaidToken(request, env, corsHeaders) {
  const { public_token, metadata } = await request.json();
  const response = await fetch('https://production.plaid.com/item/public_token/exchange', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: env.PLAID_CLIENT_ID,
      secret: env.PLAID_SECRET,
      public_token
    })
  });
  const data = await response.json();
  if (!response.ok) return new Response(JSON.stringify({ error: data.error_message || 'Exchange failed' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  
  await env.QBO_TOKENS.put('plaid_access_token', data.access_token);
  await env.QBO_TOKENS.put('plaid_item_id', data.item_id);
  
  const accounts = (metadata.accounts || []).map(a => a.name + ' ' + (a.mask || ''));
  return new Response(JSON.stringify({ success: true, accounts }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function getChaseTransactions(env, corsHeaders, days = 90) {
  const accessToken = await env.QBO_TOKENS.get('plaid_access_token');
  if (!accessToken) return new Response(JSON.stringify({ error: 'Chase not connected. Visit /connect-chase first.' }), { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

  const endDate = new Date().toISOString().split('T')[0];
  const startDate = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

  const response = await fetch('https://production.plaid.com/transactions/get', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: env.PLAID_CLIENT_ID,
      secret: env.PLAID_SECRET,
      access_token: accessToken,
      start_date: startDate,
      end_date: endDate,
      options: { count: 500 }
    })
  });

  const data = await response.json();
  if (!response.ok) return new Response(JSON.stringify({ error: data.error_message || 'Plaid error', code: data.error_code }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

  // Apply auto-categorization rules
  const rules = [
  // TRANSFERS & CARD PAYMENTS -- not expenses
  { match: /payment to chase card|chase card ending/i, category: 'Transfer:Card Payment' },
  { match: /online transfer to (chk|mma|sav)\b|online transfer to \.{3}\d+ transaction/i, category: 'Transfer:Internal' },
  { match: /american express orig id|amex epayment|orig co name:american express/i, category: 'Transfer:Card Payment' },
  { match: /\bafterpay\b|\bklarna\b/i, category: 'Transfer:Card Payment' },
  // COGS
  { match: /to jin\b|jinyu|ach payment.*\bjin\b/i, category: 'Cost of Goods Sold' },
  { match: /zelle payment to jason|jason ttyd|\bctw\b/i, category: 'Cost of Goods Sold' },
  { match: /k&?m tire/i, category: 'Cost of Goods Sold' },
  { match: /gulf coast tire/i, category: 'Cost of Goods Sold' },
  { match: /bzo|south gateway|\batd\b|amulet|mekaniq|hesselbein|jee tire|southern tire mart/i, category: 'Cost of Goods Sold' },
  { match: /realtime vendor/i, category: 'Cost of Goods Sold' },
  { match: /\bafg\b|\brtg\b/i, category: 'Cost of Goods Sold' },
  // TAXES
  { match: /webfile|comptroller|irs treas|tax pymt/i, category: 'Taxes' },
  // ACCOUNTING / LEGAL
  { match: /the numbers team|numbers team|chasity tax/i, category: 'Legal & Professional Fees:Accounting Fee' },
  { match: /identity.?iq|experian|equifax|transunion|inmates|justanswer/i, category: 'Legal & Professional Fees:Legal Fees' },
  // CONTRACTORS
  { match: /tom koehl|tkoehl|michelle charles|jose bena|james clark|kirk mccarver|andrew price/i, category: 'Contracters' },
  // SOFTWARE
  { match: /claude|anthropic|github|microsoft|google(?! vr)|cloudflare|bizze|openai|grammarly|render\b|myemailext|workspace oxle|ondemandti|cheaterscanner|cloud fb/i, category: 'Office/General Administrative Expenses:Software' },
  { match: /\bintuit\b/i, category: 'Office/General Administrative Expenses:Software' },
  // VEHICLE / FUEL
  { match: /chevron|exxon|shell|texaco|valero|conoco|bp |mobil|murphy|raceway|truck stop|hwy 90 truck|speedy stop|stuckey|love'?s|pilot|flying j/i, category: 'Vehicle:Gas And Fuel' },
  { match: /enterprise rent|uber(?! eats)/i, category: 'Vehicle:Vehicle Rental' },
  { match: /o'reilly|oreilly/i, category: 'Vehicle:Vehicle Repairs' },
  { match: /bluewave/i, category: 'Vehicle:Wash and Roadside' },
  // BANK FEES
  { match: /late fee|flex for business|same-day|service charge|\bnsf\b|tran fee|intuit.*fee/i, category: 'Bank Fees' },
  // INSURANCE / UTILITIES
  { match: /clearcover/i, category: 'Insurance:Auto Insurance' },
  { match: /t-?mobile|tmobile|zagg/i, category: 'Utilities:Communication' },
  // MEALS
  { match: /doordash|good chop|uber eats|casa ole|taco bell|jw.?s patio|brookshire|henry'?s seafood|taco loco/i, category: 'Meals' },
  // SUPPLIES / OFFICE
  { match: /home depot|m&d supply|sutherland|ebay|\baffirm\b/i, category: 'Supplies & Materials' },
  { match: /amazon|amzn|walmart|dollar general/i, category: 'Office/General Administrative Expenses:Office Supplies' },
  { match: /arlo/i, category: 'Office/General Administrative Expenses:Security' },
  // RENT / STORAGE / SHIPPING
  { match: /idaho housing/i, category: 'Rent or Lease of Building' },
  { match: /lone star storage/i, category: 'Storage Rental' },
  { match: /usps|freeshipping|chelsea lafleur/i, category: 'Shipping, Freight & Delivery' },
  // OWNER DRAW / PERSONAL
  { match: /atm withdrawal|non-chase atm|^withdrawal \d|cash app.*\boxley\b|cash app.*matthew ox|^oxley matt$|lesliespool|leslie'?s pool|spec'?s|longhorn liquor|vape n more|\bcvs\b|boomtown|samsung|aliexpress|temu|dbrand/i, category: "Owner's Equity:Owner's Draw" },
  // PAYROLL
  { match: /intuit.*payroll|payroll.*intuit/i, category: 'Payroll' },
];

  const categorized = (data.transactions || []).map(t => {
    const name = t.merchant_name || t.name || '';
    let autoCategory = t.category ? t.category.join(' > ') : 'Uncategorized';
    let matched = false;
    for (const rule of rules) {
      if (rule.match.test(name)) {
        autoCategory = rule.category;
        matched = true;
        break;
      }
    }
    return {
      date: t.date,
      name: t.merchant_name || t.name,
      amount: t.amount,
      type: t.amount > 0 ? 'DEBIT' : 'CREDIT',
      account: t.account_id,
      accountName: (data.accounts || []).find(a => a.account_id === t.account_id)?.name || '',
      category: autoCategory,
      autoMatched: matched,
      pending: t.pending,
      plaidCategory: t.category
    };
  }).sort((a, b) => new Date(b.date) - new Date(a.date));

  const accounts = (data.accounts || []).map(a => ({
    name: a.name,
    mask: a.mask,
    type: a.type,
    balance: a.balances.current,
    available: a.balances.available
  }));

  const byCategory = {};
  let transfersTotal = 0;
  categorized.filter(t => t.amount > 0).forEach(t => {
    if (t.category.startsWith('Transfer')) { transfersTotal += t.amount; return; }
    byCategory[t.category] = (byCategory[t.category] || 0) + t.amount;
  });
  const realExpenseTotal = Object.values(byCategory).reduce((s, v) => s + v, 0);

  return new Response(JSON.stringify({
    period: { start: startDate, end: endDate, days },
    accounts,
    totalTransactions: categorized.length,
    totalDebits: Math.round(categorized.filter(t => t.amount > 0).reduce((s, t) => s + t.amount, 0) * 100) / 100,
    totalCredits: Math.round(Math.abs(categorized.filter(t => t.amount < 0).reduce((s, t) => s + t.amount, 0)) * 100) / 100,
    transfersTotal: Math.round(transfersTotal * 100) / 100,
    realExpenseTotal: Math.round(realExpenseTotal * 100) / 100,
    byCategory: Object.entries(byCategory).sort((a, b) => b[1] - a[1]).map(([cat, total]) => ({ category: cat, total: Math.round(total * 100) / 100 })),
    transactions: categorized
  }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}