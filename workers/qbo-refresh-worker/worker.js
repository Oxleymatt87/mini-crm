const REALM_ID = "9130357532009796";
const SHEET_ID = "1EghclLR5lUwHRsEVvmmNrHZQcyKvLGP0JCQHyJKOoEY";
const QBO_API_BASE = "https://quickbooks.api.intuit.com/v3/company";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });

    try {
      // NEW: Apify webhook endpoint
      if (url.pathname === '/new-prospect' && request.method === 'POST') {
        return await handleNewProspect(request, env, corsHeaders);
      }

      if (url.pathname === '/token-status') {
        const tokens = await getTokens(env);
        return new Response(JSON.stringify({ hasAccessToken: !!tokens.access_token, hasRefreshToken: !!tokens.refresh_token, expiresIn: tokens.expires_in }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
      if (url.pathname === '/query' && request.method === 'POST') return await handleQuery(request, env, corsHeaders);
      if (url.pathname === '/customers') return await fetchCustomers(env, corsHeaders);
      if (url.pathname === '/sales-data') return await fetchSalesData(env, corsHeaders);
      if (url.pathname === '/profit-loss') { const s = url.searchParams.get('start_date')||'2026-01-01', e = url.searchParams.get('end_date')||new Date().toISOString().split('T')[0]; return await fetchProfitLoss(env, corsHeaders, s, e); }
      if (url.pathname === '/top-customers') { const y = url.searchParams.get('year')||'2026'; return await fetchTopCustomers(env, corsHeaders, y); }
      if (url.pathname === '/bank-transactions') { const l = parseInt(url.searchParams.get('limit')||'100'); return await fetchBankTransactions(env, corsHeaders, l); }
      if (url.pathname === '/overdue-invoices') return await fetchOverdueInvoices(env, corsHeaders);
      if (url.pathname === '/dashboard-summary') return await fetchDashboardSummary(env, corsHeaders);
      if (url.pathname === '/chase-report' || url.pathname === '/chase-dashboard') return new Response(CHASE_REPORT_HTML, { headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' } });
      if (url.pathname === '/expenses-detail') { const s = url.searchParams.get('start_date')||'2026-01-01', e = url.searchParams.get('end_date')||new Date().toISOString().split('T')[0]; return await fetchExpensesDetail(env, corsHeaders, s, e); }
      if (url.pathname === '/connect-chase') return new Response(CONNECT_HTML, { headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' } });
      if (url.pathname === '/plaid-link-token' && request.method === 'POST') return await createPlaidLinkToken(env, corsHeaders);
      if (url.pathname === '/plaid-exchange' && request.method === 'POST') return await exchangePlaidToken(request, env, corsHeaders);
      if (url.pathname === '/chase-transactions') { const d = parseInt(url.searchParams.get('days')||'90'); return await getChaseTransactions(env, corsHeaders, d); }
      if (url.pathname === '/dad') return new Response(DAD_HTML, { headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' } });

      if (url.pathname === '/payments-by-customer') {
        const s = url.searchParams.get('start_date') || '2026-01-01';
        const e = url.searchParams.get('end_date') || '2026-06-14';
        return await fetchPaymentsByCustomer(env, corsHeaders, s, e);
      }

      return new Response(JSON.stringify({ status: 'ok', endpoints: ['/dad','/dashboard-summary','/overdue-invoices','/chase-transactions','/bank-transactions','/profit-loss','/top-customers','/expenses-detail','/connect-chase','/new-prospect','/payments-by-customer'] }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }
  },
  async scheduled(event, env, ctx) { await refreshAccessToken(env); }
};

// ─── APIFY WEBHOOK ────────────────────────────────────────────────────────────
async function handleNewProspect(request, env, corsHeaders) {
  try {
    const body = await request.json();
    const prospects = Array.isArray(body) ? body : [body];
    const added = [], skipped = [];

    for (const p of prospects) {
      const name = p.title || p.name || p.companyName || '';
      if (!name) { skipped.push('unnamed'); continue; }

      const doc = {
        fields: {
          name:     { stringValue: name },
          address:  { stringValue: p.address || p.street || '' },
          city:     { stringValue: p.city || '' },
          state:    { stringValue: p.state || 'TX' },
          zip:      { stringValue: p.postalCode || p.zip || '' },
          phone:    { stringValue: p.phone || p.phoneNumber || '' },
          email:    { stringValue: p.email || '' },
          website:  { stringValue: p.website || '' },
          category: { stringValue: p.categoryName || p.category || 'Fleet/Trucking' },
          lat:      { doubleValue: p.location?.lat || p.latitude || 0 },
          lng:      { doubleValue: p.location?.lng || p.longitude || 0 },
          source:   { stringValue: 'Apify' },
          addedAt:  { stringValue: new Date().toISOString() },
          status:   { stringValue: 'New Lead' },
          notes:    { stringValue: '' },
        }
      };

      const docId = name.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 40) + '_' + Date.now();
      const res = await fetch(
        `https://firestore.googleapis.com/v1/projects/inventory-setup-b3f20/databases/(default)/documents/prospects/${docId}`,
        { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(doc) }
      );
      if (res.ok) added.push(name); else skipped.push(name);
    }

    return new Response(JSON.stringify({ success: true, added: added.length, skipped: skipped.length, addedNames: added }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

async function getTokens(env) {
  const [at, rt, ea] = await Promise.all([env.QBO_TOKENS.get('access_token'), env.QBO_TOKENS.get('refresh_token'), env.QBO_TOKENS.get('expires_at')]);
  const now = Math.floor(Date.now() / 1000);
  return { access_token: at, refresh_token: rt, expires_in: ea ? parseInt(ea) - now : null };
}

async function refreshAccessToken(env) {
  const tokens = await getTokens(env);
  if (!tokens.refresh_token) throw new Error('No refresh token');
  const res = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + btoa(`${env.QBO_CLIENT_ID}:${env.QBO_CLIENT_SECRET}`) },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token })
  });
  if (!res.ok) throw new Error(`Token refresh failed: ${res.status}`);
  const d = await res.json();
  const now = Math.floor(Date.now() / 1000);
  await Promise.all([env.QBO_TOKENS.put('access_token', d.access_token), env.QBO_TOKENS.put('refresh_token', d.refresh_token), env.QBO_TOKENS.put('expires_at', (now + d.expires_in).toString())]);
  return d;
}

async function qboApiCall(endpoint, env) {
  let tokens = await getTokens(env);
  if (!tokens.expires_in || tokens.expires_in < 300) tokens = await refreshAccessToken(env);
  const fullUrl = endpoint.startsWith('https://') ? endpoint : `${QBO_API_BASE}/${REALM_ID}/${endpoint}`;
  const res = await fetch(fullUrl, { headers: { 'Authorization': `Bearer ${tokens.access_token}`, 'Accept': 'application/json' } });
  if (!res.ok) throw new Error(`QBO API error: ${res.status} ${await res.text()}`);
  return await res.json();
}

async function fetchCustomers(env, h) {
  const d = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Customer MAXRESULTS 1000'), env);
  return new Response(JSON.stringify({ count: d.QueryResponse.Customer?.length||0, customers: d.QueryResponse.Customer||[] }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchSalesData(env, h) {
  const d = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
  return new Response(JSON.stringify({ count: d.QueryResponse.Invoice?.length||0, invoices: d.QueryResponse.Invoice||[] }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchBankTransactions(env, h, limit=100) {
  const [pd, dd] = await Promise.all([
    qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Purchase MAXRESULTS ${limit}`)}`, env),
    qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Deposit MAXRESULTS ${limit}`)}`, env)
  ]);
  const purchases = (pd.QueryResponse.Purchase||[]).map(p => ({ type:'EXPENSE', date:p.TxnDate, amount:-Math.abs(parseFloat(p.TotalAmt||0)), memo:p.PrivateNote||'', account:p.AccountRef?.name||'', entity:p.EntityRef?.name||p.VendorRef?.name||'', id:p.Id }));
  const deposits = (dd.QueryResponse.Deposit||[]).map(d => ({ type:'DEPOSIT', date:d.TxnDate, amount:parseFloat(d.TotalAmt||0), memo:d.PrivateNote||'', account:d.DepositToAccountRef?.name||'', entity:'', id:d.Id }));
  const all = [...purchases, ...deposits].sort((a,b)=>new Date(b.date)-new Date(a.date));
  return new Response(JSON.stringify({ count:all.length, transactions:all }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchOverdueInvoices(env, h) {
  const today = new Date().toISOString().split('T')[0];
  const d = await qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Invoice WHERE DueDate < '${today}' AND Balance > '0' MAXRESULTS 500`)}`, env);
  const invoices = (d.QueryResponse.Invoice||[]).map(inv => ({ id:inv.Id, invoiceNum:inv.DocNumber, customer:inv.CustomerRef?.name||'Unknown', amount:parseFloat(inv.TotalAmt||0), balance:parseFloat(inv.Balance||0), dueDate:inv.DueDate, txnDate:inv.TxnDate, daysOverdue:Math.floor((new Date()-new Date(inv.DueDate))/86400000), email:inv.BillEmail?.Address||'' })).sort((a,b)=>b.daysOverdue-a.daysOverdue);
  return new Response(JSON.stringify({ count:invoices.length, totalOverdue:invoices.reduce((s,i)=>s+i.balance,0), invoices }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchDashboardSummary(env, h) {
  const today = new Date().toISOString().split('T')[0];
  const firstOfMonth = today.substring(0,7)+'-01';
  const [od, id, pd, dd] = await Promise.all([
    qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Invoice WHERE DueDate < '${today}' AND Balance > '0' MAXRESULTS 500`)}`, env),
    qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Invoice WHERE TxnDate >= '${firstOfMonth}' MAXRESULTS 500`)}`, env),
    qboApiCall(`query?query=${encodeURIComponent('SELECT * FROM Purchase MAXRESULTS 1000')}`, env),
    qboApiCall(`query?query=${encodeURIComponent('SELECT * FROM Deposit MAXRESULTS 1000')}`, env)
  ]);
  const oi = od.QueryResponse.Invoice||[], mi = id.QueryResponse.Invoice||[], pu = pd.QueryResponse.Purchase||[], de = dd.QueryResponse.Deposit||[];
  const totalOverdue = oi.reduce((s,i)=>s+parseFloat(i.Balance||0),0);
  const monthRevenue = mi.reduce((s,i)=>s+parseFloat(i.TotalAmt||0),0);
  const monthExpenses = pu.reduce((s,p)=>s+parseFloat(p.TotalAmt||0),0);
  const topOverdue = oi.sort((a,b)=>parseFloat(b.Balance)-parseFloat(a.Balance)).map(inv=>({ customer:inv.CustomerRef?.name, balance:parseFloat(inv.Balance||0), daysOverdue:Math.floor((new Date()-new Date(inv.DueDate))/86400000), dueDate:inv.DueDate, invoiceNum:inv.DocNumber }));
  const recentDeposits = de.sort((a,b)=>new Date(b.TxnDate)-new Date(a.TxnDate)).map(d=>({ date:d.TxnDate, amount:parseFloat(d.TotalAmt||0), account:d.DepositToAccountRef?.name||'' }));
  const recentExpenses = pu.sort((a,b)=>new Date(b.TxnDate)-new Date(a.TxnDate)).map(p=>({ date:p.TxnDate, amount:parseFloat(p.TotalAmt||0), vendor:p.EntityRef?.name||p.VendorRef?.name||'', account:p.AccountRef?.name||'' }));
  return new Response(JSON.stringify({ asOf:today, summary:{ totalOverdue:Math.round(totalOverdue*100)/100, overdueCount:oi.length, monthRevenue:Math.round(monthRevenue*100)/100, monthExpenses:Math.round(monthExpenses*100)/100, netThisMonth:Math.round((monthRevenue-monthExpenses)*100)/100 }, topOverdueAccounts:topOverdue, recentDeposits, recentExpenses }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchProfitLoss(env, h, s, e) {
  const d = await qboApiCall(`${QBO_API_BASE}/${REALM_ID}/reports/ProfitAndLoss?start_date=${s}&end_date=${e}&minorversion=65`, env);
  return new Response(JSON.stringify(d), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchTopCustomers(env, h, year) {
  const d = await qboApiCall(`query?query=${encodeURIComponent(`SELECT * FROM Invoice WHERE TxnDate >= '${year}-01-01' AND TxnDate <= '${year}-12-31' MAXRESULTS 1000`)}`, env);
  const custs = {};
  for (const inv of d?.QueryResponse?.Invoice||[]) { const n = inv.CustomerRef?.name||'Unknown'; custs[n]=(custs[n]||0)+parseFloat(inv.TotalAmt||0); }
  const sorted = Object.entries(custs).sort((a,b)=>b[1]-a[1]).slice(0,25).map(([name,total])=>({ name, total:Math.round(total*100)/100 }));
  return new Response(JSON.stringify({ year, customers:sorted }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function handleQuery(request, env, h) {
  const { query } = await request.json();
  const data = await qboApiCall('query?query='+encodeURIComponent('SELECT * FROM Invoice MAXRESULTS 1000'), env);
  return new Response(JSON.stringify({ query, results: data?.QueryResponse?.Invoice||[] }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function fetchExpensesDetail(env, h, startDate, endDate) {
  const [bd, bpd, pd] = await Promise.all([
    qboApiCall('query?query='+encodeURIComponent(`SELECT * FROM Bill WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 1000`), env),
    qboApiCall('query?query='+encodeURIComponent(`SELECT * FROM BillPayment WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 1000`), env),
    qboApiCall('query?query='+encodeURIComponent(`SELECT * FROM Purchase WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 1000`), env)
  ]);
  const bills=(bd.QueryResponse.Bill||[]).map(b=>({ type:'BILL',id:b.Id,date:b.TxnDate,vendor:b.VendorRef?.name||'Unknown',amount:parseFloat(b.TotalAmt||0),balance:parseFloat(b.Balance||0),memo:b.PrivateNote||'' }));
  const bps=(bpd.QueryResponse.BillPayment||[]).map(b=>({ type:'BILL_PAYMENT',id:b.Id,date:b.TxnDate,vendor:b.VendorRef?.name||'Unknown',amount:parseFloat(b.TotalAmt||0) }));
  const purchases=(pd.QueryResponse.Purchase||[]).map(p=>({ type:'PURCHASE',id:p.Id,date:p.TxnDate,vendor:p.EntityRef?.name||p.VendorRef?.name||'Unknown',amount:parseFloat(p.TotalAmt||0),account:p.AccountRef?.name||'' }));
  const all=[...bills,...bps,...purchases].sort((a,b)=>new Date(b.date)-new Date(a.date));
  const byVendor={};
  all.forEach(t=>{ const v=t.vendor; if(!byVendor[v]) byVendor[v]={vendor:v,total:0,count:0}; byVendor[v].total+=t.amount; byVendor[v].count+=1; });
  return new Response(JSON.stringify({ period:{start:startDate,end:endDate}, transactions:all, byVendor:Object.values(byVendor).sort((a,b)=>b.total-a.total) }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
async function createPlaidLinkToken(env, h) {
  const res = await fetch('https://production.plaid.com/link/token/create', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ client_id:env.PLAID_CLIENT_ID, secret:env.PLAID_SECRET, client_name:'Oxley Tire Inc.', country_codes:['US'], language:'en', user:{client_user_id:'oxley-matt'}, products:['transactions'], transactions:{days_requested:730}, redirect_uri:'https://inventory-setup-b3f20.web.app/connect-chase.html' }) });
  const d = await res.json();
  if (!res.ok) return new Response(JSON.stringify({ error:d.error_message||'Link token failed', details:d }), { status:400, headers:{ ...h, 'Content-Type':'application/json' } });
  return new Response(JSON.stringify({ link_token:d.link_token }), { headers:{ ...h, 'Content-Type':'application/json' } });
}
async function exchangePlaidToken(request, env, h) {
  const { public_token, metadata } = await request.json();
  const res = await fetch('https://production.plaid.com/item/public_token/exchange', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ client_id:env.PLAID_CLIENT_ID, secret:env.PLAID_SECRET, public_token }) });
  const d = await res.json();
  if (!res.ok) return new Response(JSON.stringify({ error:d.error_message||'Exchange failed' }), { status:400, headers:{ ...h, 'Content-Type':'application/json' } });
  await Promise.all([env.QBO_TOKENS.put('plaid_access_token', d.access_token), env.QBO_TOKENS.put('plaid_item_id', d.item_id)]);
  return new Response(JSON.stringify({ success:true, accounts:(metadata.accounts||[]).map(a=>a.name+' '+a.mask) }), { headers:{ ...h, 'Content-Type':'application/json' } });
}
async function getChaseTransactions(env, h, days=90) {
  const accessToken = await env.QBO_TOKENS.get('plaid_access_token');
  if (!accessToken) return new Response(JSON.stringify({ error:'Chase not connected. Visit /connect-chase first.' }), { status:401, headers:{ ...h, 'Content-Type':'application/json' } });
  const endDate = new Date().toISOString().split('T')[0];
  const startDate = new Date(Date.now()-days*86400000).toISOString().split('T')[0];
  const data = { transactions:[], accounts:[] };
  let total = null;
  while (total===null || data.transactions.length < total) {
    const res = await fetch('https://production.plaid.com/transactions/get', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ client_id:env.PLAID_CLIENT_ID, secret:env.PLAID_SECRET, access_token:accessToken, start_date:startDate, end_date:endDate, options:{count:500,offset:data.transactions.length} }) });
    const page = await res.json();
    if (!res.ok) return new Response(JSON.stringify({ error:page.error_message||'Plaid error', code:page.error_code }), { status:400, headers:{ ...h, 'Content-Type':'application/json' } });
    if (!data.accounts.length) data.accounts = page.accounts||[];
    const batch = page.transactions||[];
    data.transactions.push(...batch);
    total = page.total_transactions||0;
    if (batch.length===0 || data.transactions.length>=100000) break;
  }
  const rules = [
    { match:/payment to chase card|chase card ending|payment.?thank you/i, category:'Transfer:Card Payment' },
    { match:/online transfer (?:to|from)/i, category:'Transfer:Internal' },
    { match:/american express|amex epayment|visa payment|\bafterpay\b|\bklarna\b/i, category:'Transfer:Card Payment' },
    { match:/to jin\b|jinyu|ach payment.*\bjin\b/i, category:'Cost of Goods Sold' },
    { match:/zelle payment to jason|jason ttyd|\bctw\b|k&?m tire|gulf coast tire/i, category:'Cost of Goods Sold' },
    { match:/bzo|south gateway|\batd\b|amulet|mekaniq|hesselbein|jee tire|southern tire mart/i, category:'Cost of Goods Sold' },
    { match:/realtime vendor|\bafg\b|\brtg\b/i, category:'Cost of Goods Sold' },
    { match:/webfile|comptroller|irs treas|tax pymt/i, category:'Taxes' },
    { match:/the numbers team|chasity tax/i, category:'Legal & Professional Fees:Accounting Fee' },
    { match:/tom koehl|michelle charles|jose bena|james clark|kirk mccarver|andrew price/i, category:'Contracters' },
    { match:/claude|anthropic|github|microsoft|google|cloudflare|\baws\b|amazon web services/i, category:'Office/General Administrative Expenses:Software' },
    { match:/chevron|exxon|shell|texaco|valero|conoco|bp |\bmobil\b|murphy|raceway|love'?s|pilot|flying j/i, category:'Vehicle:Gas And Fuel' },
    { match:/t-?mobile|tmobile/i, category:'Utilities:Communication' },
    { match:/clearcover/i, category:'Insurance:Auto Insurance' },
    { match:/doordash|uber eats|brookshire/i, category:'Meals' },
    { match:/home depot|m&d supply|\baffirm\b/i, category:'Supplies & Materials' },
    { match:/amazon|amzn|walmart/i, category:'Office/General Administrative Expenses:Office Supplies' },
    { match:/idaho housing/i, category:'Rent or Lease of Building' },
    { match:/lone star storage/i, category:'Storage Rental' },
    { match:/intuit.*payroll|payroll.*intuit/i, category:'Payroll' },
    { match:/intuit|tran fee|service charge/i, category:'Bank Fees' },
  ];
  const incomeRules = [
    { match:/zelle payment from|cash app|instant transfer fro/i, category:'Customer Payment:Zelle & Cash App' },
    { match:/\bintuit\b/i, category:'Customer Payment:Card (QuickBooks)' },
    { match:/remote online deposit|atm check deposit/i, category:'Customer Payment:Check Deposit' },
    { match:/atm cash deposit/i, category:'Customer Payment:Cash Deposit' },
    { match:/internal revenue service/i, category:'Tax Refund' },
  ];
  const categorized = data.transactions.map(t => {
    const name = t.merchant_name||t.name||'';
    let autoCategory = 'Uncategorized';
    let matched = false;
    if (t.amount < 0) { for (const r of incomeRules) { if (r.match.test(name)) { autoCategory=r.category; matched=true; break; } } }
    if (!matched && t.amount > 0 && /\bintuit\b/i.test(name)) { autoCategory = t.amount>=1500?'Payroll':'Bank Fees'; matched=true; }
    if (!matched) { for (const r of rules) { if (r.match.test(name)) { autoCategory=r.category; matched=true; break; } } }
    return { date:t.date, name:t.merchant_name||t.name, amount:t.amount, type:t.amount>0?'DEBIT':'CREDIT', account:t.account_id, accountName:(data.accounts||[]).find(a=>a.account_id===t.account_id)?.name||'', category:autoCategory, autoMatched:matched, pending:t.pending };
  }).sort((a,b)=>new Date(b.date)-new Date(a.date));
  const accounts = (data.accounts||[]).map(a=>({ name:a.name, mask:a.mask, type:a.type, balance:a.balances.current, available:a.balances.available }));
  const byCategory={};
  let transfersTotal=0;
  categorized.filter(t=>t.amount>0).forEach(t=>{ if(t.category.startsWith('Transfer')){transfersTotal+=t.amount;return;} byCategory[t.category]=(byCategory[t.category]||0)+t.amount; });
  const realExpenseTotal=Object.values(byCategory).reduce((s,v)=>s+v,0);
  const totalCredits=Math.abs(categorized.filter(t=>t.amount<0).reduce((s,t)=>s+t.amount,0));
  const transfersInTotal=Math.abs(categorized.filter(t=>t.amount<0&&t.category.startsWith('Transfer')).reduce((s,t)=>s+t.amount,0));
  return new Response(JSON.stringify({ period:{start:startDate,end:endDate,days}, accounts, totalTransactions:categorized.length, totalDebits:Math.round(categorized.filter(t=>t.amount>0).reduce((s,t)=>s+t.amount,0)*100)/100, totalCredits:Math.round(totalCredits*100)/100, transfersTotal:Math.round(transfersTotal*100)/100, transfersInTotal:Math.round(transfersInTotal*100)/100, realIncomeTotal:Math.round((totalCredits-transfersInTotal)*100)/100, realExpenseTotal:Math.round(realExpenseTotal*100)/100, byCategory:Object.entries(byCategory).sort((a,b)=>b[1]-a[1]).map(([cat,total])=>({category:cat,total:Math.round(total*100)/100})), transactions:categorized }), { headers:{ ...h, 'Content-Type':'application/json' } });
}

// ─── PAYMENTS BY CUSTOMER (Deposits grouped by customer + payment method) ─────
// Queries every QBO Deposit in [startDate, endDate], reads each deposit line's
// Entity (customer) and PaymentMethodRef (payment method), and groups the
// dollar totals into { customer: { payment_method: amount } }.
// For QuickBooks Payments deposits (system-recorded, no Entity on the line) it
// follows the line's LinkedTxn into the underlying Payment / SalesReceipt to
// recover the real customer.
// Reuses the existing token logic: qboApiCall() pulls the access token from the
// QBO_TOKENS KV namespace and auto-refreshes via refreshAccessToken() when stale.
async function fetchPaymentsByCustomer(env, h, startDate, endDate) {
  // Resolve PaymentMethod id -> name (deposit lines sometimes carry only the ref value)
  const methodMap = {};
  try {
    const pm = await qboApiCall('query?query=' + encodeURIComponent('SELECT * FROM PaymentMethod MAXRESULTS 1000'), env);
    for (const m of pm?.QueryResponse?.PaymentMethod || []) methodMap[m.Id] = m.Name;
  } catch (e) { /* non-fatal: fall back to ref names / memo inference */ }

  // Page through every Deposit in the date range (QBO caps a page at 1000)
  const deposits = [];
  const PAGE = 1000;
  let startPos = 1;
  while (true) {
    const q = `SELECT * FROM Deposit WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' ORDERBY TxnDate STARTPOSITION ${startPos} MAXRESULTS ${PAGE}`;
    const d = await qboApiCall('query?query=' + encodeURIComponent(q), env);
    const batch = d?.QueryResponse?.Deposit || [];
    deposits.push(...batch);
    if (batch.length < PAGE) break;
    startPos += PAGE;
  }

  // Best-effort payment-method guess from free-text memo/description
  const inferMethod = (txt) => {
    const s = (txt || '').toLowerCase();
    if (/zelle/.test(s)) return 'Zelle';
    if (/cash ?app/.test(s)) return 'Cash App';
    if (/cheque|\bchecks?\b|\bck\b|check ?#/.test(s)) return 'Check';
    if (/\bcash\b/.test(s)) return 'Cash';
    if (/credit|debit|\bcard\b|visa|master ?card|amex|discover|quickbooks|intuit/.test(s)) return 'Card';
    if (/\bach\b|\bwire\b|e-?transfer|bank transfer/.test(s)) return 'ACH/Wire';
    if (/money ?order/.test(s)) return 'Money Order';
    return null;
  };

  const round2 = (n) => Math.round(n * 100) / 100;

  // PASS 1: flatten deposit lines; collect linked Payment/SalesReceipt ids for
  // lines that have no customer Entity, so we can resolve them in bulk.
  const items = [];
  const needByType = { Payment: new Set(), SalesReceipt: new Set() };
  for (const dep of deposits) {
    const depMemo = dep.PrivateNote || '';
    for (const line of dep.Line || []) {
      const amt = parseFloat(line.Amount || 0);
      if (!amt) continue;
      const dld = line.DepositLineDetail || {};
      const desc = line.Description || '';

      const customer = (dld.Entity && dld.Entity.name) ? dld.Entity.name : null;

      let method = (dld.PaymentMethodRef && dld.PaymentMethodRef.name) ? dld.PaymentMethodRef.name : null;
      if (!method && dld.PaymentMethodRef && dld.PaymentMethodRef.value) method = methodMap[dld.PaymentMethodRef.value] || null;
      if (!method) method = inferMethod(desc) || inferMethod(depMemo) || 'Unknown';

      const linked = (line.LinkedTxn || []).map((l) => ({ type: l.TxnType, id: l.TxnId }));
      if (!customer) {
        for (const l of linked) if (needByType[l.type]) needByType[l.type].add(l.id);
      }
      items.push({ depositId: dep.Id, date: dep.TxnDate, amt, desc, depMemo, customer, method, linked });
    }
  }

  // Resolve linked Payment / SalesReceipt ids -> customer name (batched, 100 ids/query)
  const linkedCustomer = {}; // "Type:Id" -> name
  for (const type of Object.keys(needByType)) {
    const ids = [...needByType[type]];
    for (let i = 0; i < ids.length; i += 100) {
      const chunk = ids.slice(i, i + 100).map((id) => `'${id}'`).join(',');
      try {
        const r = await qboApiCall('query?query=' + encodeURIComponent(`SELECT * FROM ${type} WHERE Id IN (${chunk})`), env);
        for (const e of r?.QueryResponse?.[type] || []) linkedCustomer[`${type}:${e.Id}`] = (e.CustomerRef && e.CustomerRef.name) || null;
      } catch (e) { /* non-fatal: those lines stay Unknown */ }
    }
  }

  // PASS 2: aggregate
  const byCustomer = {};
  const byMethod = {};
  const unknownSamples = [];
  let grandTotal = 0, lineCount = 0, resolvedViaLink = 0;

  for (const it of items) {
    let customer = it.customer;
    if (!customer) {
      for (const l of it.linked) {
        const name = linkedCustomer[`${l.type}:${l.id}`];
        if (name) { customer = name; resolvedViaLink++; break; }
      }
    }
    if (!customer) customer = 'Unknown';
    const method = it.method;

    if (!byCustomer[customer]) byCustomer[customer] = {};
    byCustomer[customer][method] = round2((byCustomer[customer][method] || 0) + it.amt);
    byMethod[method] = round2((byMethod[method] || 0) + it.amt);
    grandTotal += it.amt;
    lineCount++;

    if ((customer === 'Unknown' || method === 'Unknown') && unknownSamples.length < 50) {
      unknownSamples.push({ depositId: it.depositId, date: it.date, amount: round2(it.amt), customer, method, description: it.desc, memo: it.depMemo, linked: it.linked });
    }
  }

  // Sort customers by total (largest first) for readable curl output
  const sortedCustomers = {};
  Object.keys(byCustomer)
    .sort((a, b) => {
      const ta = Object.values(byCustomer[a]).reduce((s, v) => s + v, 0);
      const tb = Object.values(byCustomer[b]).reduce((s, v) => s + v, 0);
      return tb - ta;
    })
    .forEach((c) => { sortedCustomers[c] = byCustomer[c]; });

  return new Response(JSON.stringify({
    period: { start: startDate, end: endDate },
    depositCount: deposits.length,
    lineCount,
    grandTotal: round2(grandTotal),
    resolvedViaLinkedTxn: resolvedViaLink,
    byMethod,
    byCustomer: sortedCustomers,
    diagnostics: { unknownSampleCount: unknownSamples.length, unknownSamples }
  }), { headers: { ...h, 'Content-Type': 'application/json' } });
}

const CONNECT_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Connect Chase</title><style>body{background:#0a0a0a;color:#e8e8e8;font-family:Arial,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#111;border:1px solid #222;border-top:2px solid #e8a020;padding:40px;max-width:400px;width:90%;text-align:center}h1{font-size:24px;color:#e8a020;margin-bottom:8px;letter-spacing:2px}p{color:#888;font-size:14px;margin-bottom:24px}button{background:#e8a020;color:#000;border:none;padding:16px 32px;font-size:16px;font-weight:700;cursor:pointer;width:100%;letter-spacing:1px}button:disabled{background:#444;color:#666;cursor:not-allowed}#status{margin-top:16px;font-size:13px;color:#888;min-height:20px}#status.success{color:#27ae60}#status.error{color:#c0392b}</style></head><body><div class="box"><h1>OXLEY TIRE</h1><p>Connect your Chase accounts to enable live transaction tracking. This is a one-time setup.</p><button id="btn" onclick="startLink()">CONNECT CHASE</button><div id="status"></div></div><script src="https://cdn.plaid.com/link/v2/stable/link-initialize.js"></script><script>async function startLink(){const btn=document.getElementById('btn'),s=document.getElementById('status');btn.disabled=true;s.textContent='Initializing...';s.className='';try{const r=await fetch('https://qbo-refresh-worker.moxley.workers.dev/plaid-link-token',{method:'POST'});const d=await r.json();if(!d.link_token)throw new Error(d.error||'Failed');const h=Plaid.create({token:d.link_token,onSuccess:async(pt,m)=>{s.textContent='Exchanging...';const er=await fetch('https://qbo-refresh-worker.moxley.workers.dev/plaid-exchange',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({public_token:pt,metadata:m})});const ed=await er.json();if(ed.success){s.textContent='✅ Chase connected! Close this window.';s.className='success';btn.textContent='CONNECTED';}else throw new Error(ed.error||'Exchange failed');},onExit:(e)=>{btn.disabled=false;s.textContent=e?'Error: '+(e.display_message||e.error_code||JSON.stringify(e)):'Cancelled.';if(e)s.className='error';}});h.open();}catch(e){s.textContent='Error: '+e.message;s.className='error';btn.disabled=false;}}</script></body></html>`;

const DAD_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Oxley Tire — Command Center</title><link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet"><style>:root{--bg:#0a0a0a;--surface:#111111;--border:#222222;--accent:#e8a020;--red:#c0392b;--green:#27ae60;--text:#e8e8e8;--muted:#666666;--mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;--display:'Bebas Neue',sans-serif}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}header{background:var(--surface);border-bottom:2px solid var(--accent);padding:16px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}.logo{font-family:var(--display);font-size:28px;letter-spacing:2px;color:var(--accent)}.logo span{color:var(--text);font-size:13px;font-family:var(--mono);display:block;letter-spacing:3px;margin-top:2px}#refresh-btn{background:var(--accent);color:#000;border:none;padding:8px 16px;font-family:var(--mono);font-size:12px;font-weight:600;cursor:pointer;letter-spacing:1px;margin-top:4px;display:block;width:100%}.main{padding:16px;max-width:900px;margin:0 auto}#loading{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:80px 20px;gap:16px}.spinner{width:40px;height:40px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.loading-text{font-family:var(--mono);font-size:13px;color:var(--muted);letter-spacing:2px}.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}@media(min-width:600px){.summary-grid{grid-template-columns:repeat(3,1fr)}}.card{background:var(--surface);border:1px solid var(--border);padding:16px;position:relative;overflow:hidden}.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent)}.card.red::before{background:var(--red)}.card.green::before{background:var(--green)}.card-label{font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:8px}.card-value{font-family:var(--display);font-size:32px;line-height:1;letter-spacing:1px}.card-value.red{color:var(--red)}.card-value.green{color:var(--green)}.card-value.amber{color:var(--accent)}.card-sub{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px}.section{margin-bottom:24px}.section-header{display:flex;align-items:center;gap:12px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}.section-title{font-family:var(--display);font-size:22px;letter-spacing:2px;color:var(--accent)}.badge{background:var(--red);color:#fff;font-family:var(--mono);font-size:11px;font-weight:600;padding:2px 8px;border-radius:2px}.badge.green{background:var(--green)}.badge.amber{background:var(--accent);color:#000}.invoice-list{display:flex;flex-direction:column;gap:6px}.invoice-row{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--red);padding:12px 14px;display:flex;align-items:center;justify-content:space-between;gap:12px}.inv-customer{font-weight:600;font-size:14px;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.inv-meta{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:2px}.inv-amount{font-family:var(--mono);font-size:15px;font-weight:600;color:var(--red);white-space:nowrap}.inv-days{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right;white-space:nowrap}.inv-days.hot{color:var(--red);font-weight:600}.inv-days.warm{color:var(--accent)}.txn-list{display:flex;flex-direction:column;gap:4px}.txn-row{background:var(--surface);border:1px solid var(--border);padding:10px 14px;display:flex;align-items:center;justify-content:space-between;gap:12px}.txn-type{font-family:var(--mono);font-size:10px;letter-spacing:1px;padding:2px 6px;border-radius:2px;white-space:nowrap}.txn-type.deposit{background:rgba(39,174,96,.15);color:var(--green)}.txn-type.expense{background:rgba(192,57,43,.15);color:var(--red)}.txn-desc{flex:1;min-width:0;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.txn-sub{font-family:var(--mono);font-size:11px;color:var(--muted)}.txn-amount{font-family:var(--mono);font-size:14px;font-weight:600;white-space:nowrap}.txn-amount.pos{color:var(--green)}.txn-amount.neg{color:var(--red)}.txn-date{font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}#content{display:none}</style></head><body><header><div class="logo">OXLEY TIRE<span>COMMAND CENTER</span></div><div><div id="update-time" style="font-family:var(--mono);font-size:11px;color:var(--muted)">Loading...</div><button id="refresh-btn" onclick="loadData()">↻ REFRESH</button></div></header><div class="main"><div id="loading"><div class="spinner"></div><div class="loading-text">PULLING LIVE DATA...</div></div><div id="error" style="display:none"><div style="background:#1a0a0a;border:1px solid var(--red);padding:20px;text-align:center;font-family:var(--mono);font-size:13px;color:var(--red)">Failed to load. Try refreshing.</div></div><div id="content"><div class="summary-grid" id="summary-cards"></div><div class="section"><div class="section-header"><div class="section-title">OVERDUE INVOICES</div><div class="badge" id="overdue-badge">—</div></div><div class="invoice-list" id="invoice-list"></div></div><div class="section"><div class="section-header"><div class="section-title">RECENT DEPOSITS</div><div class="badge green">MONEY IN</div></div><div class="txn-list" id="deposit-list"></div></div><div class="section"><div class="section-header"><div class="section-title">RECENT EXPENSES</div><div class="badge amber">MONEY OUT</div></div><div class="txn-list" id="expense-list"></div></div></div></div><script>const W='https://qbo-refresh-worker.moxley.workers.dev';function fmt(n){return'$'+Math.abs(n).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}function fmtDate(d){if(!d)return'';const p=d.split('-');return p[1]+'/'+p[2]+'/'+p[0].slice(2)}async function loadData(){document.getElementById('loading').style.display='flex';document.getElementById('content').style.display='none';document.getElementById('error').style.display='none';document.getElementById('refresh-btn').textContent='↻ LOADING...';try{const[sr,tr]=await Promise.all([fetch(W+'/dashboard-summary'),fetch(W+'/chase-transactions?days=90')]);const[s,t]=await Promise.all([sr.json(),tr.json()]);renderSummary(s,t);renderInvoices(s.topOverdueAccounts||[]);renderTransactions(t.transactions||[]);document.getElementById('update-time').textContent='Updated: '+new Date().toLocaleTimeString();document.getElementById('refresh-btn').textContent='↻ REFRESH';document.getElementById('loading').style.display='none';document.getElementById('content').style.display='block';}catch(e){document.getElementById('loading').style.display='none';document.getElementById('error').style.display='block';document.getElementById('refresh-btn').textContent='↻ REFRESH';}}function renderSummary(data,txnData){const s=data.summary,accts=txnData?.accounts||[],chk=accts.find(a=>a.mask==='2236'),cc=accts.find(a=>a.mask==='8784');const cards=[{label:'OVERDUE AR',value:fmt(s.totalOverdue),sub:s.overdueCount+' invoices',cls:'red'},{label:'CHECKING 2236',value:chk?fmt(chk.balance):'--',sub:chk?fmt(chk.available)+' available':'Live Chase',cls:'green'},{label:'CC 8784',value:cc?fmt(cc.balance):'--',sub:cc?fmt(cc.available)+' available':'Live Chase',cls:'red'},{label:'MTD REVENUE',value:fmt(s.monthRevenue),sub:'This month',cls:'green'},{label:'MTD NET',value:fmt(s.netThisMonth),sub:s.netThisMonth>=0?'Profitable':'In the red',cls:s.netThisMonth>=0?'green':'red'},{label:'AS OF',value:fmtDate(data.asOf),sub:'Live data',cls:''}];document.getElementById('summary-cards').innerHTML=cards.map(c=>'<div class="card '+c.cls+'"><div class="card-label">'+c.label+'</div><div class="card-value '+c.cls+'">'+c.value+'</div><div class="card-sub">'+c.sub+'</div></div>').join('');}function renderInvoices(invoices){document.getElementById('overdue-badge').textContent=invoices.length+' accounts';document.getElementById('invoice-list').innerHTML=invoices.map(inv=>{const u=inv.daysOverdue>60?'hot':inv.daysOverdue>30?'warm':'';return'<div class="invoice-row"><div><div class="inv-customer">'+inv.customer+'</div><div class="inv-meta">INV #'+inv.invoiceNum+' · Due '+fmtDate(inv.dueDate)+'</div></div><div style="text-align:right"><div class="inv-amount">'+fmt(inv.balance)+'</div><div class="inv-days '+u+'">'+inv.daysOverdue+'d overdue</div></div></div>';}).join('');}function renderTransactions(txns){const deps=txns.filter(t=>t.type==='CREDIT'),exps=txns.filter(t=>t.type==='DEBIT');document.getElementById('deposit-list').innerHTML=deps.length?deps.slice(0,30).map(t=>'<div class="txn-row"><span class="txn-type deposit">IN</span><div class="txn-desc"><div>'+t.name+'</div><div class="txn-sub">'+t.category+'</div></div><div style="text-align:right"><div class="txn-amount pos">'+fmt(t.amount)+'</div><div class="txn-date">'+fmtDate(t.date)+'</div></div></div>').join(''):'<div style="color:var(--muted);padding:12px;font-size:13px">No recent deposits.</div>';document.getElementById('expense-list').innerHTML=exps.length?exps.slice(0,30).map(t=>'<div class="txn-row"><span class="txn-type expense">OUT</span><div class="txn-desc"><div>'+t.name+'</div><div class="txn-sub">'+t.category+'</div></div><div style="text-align:right"><div class="txn-amount neg">'+fmt(t.amount)+'</div><div class="txn-date">'+fmtDate(t.date)+'</div></div></div>').join(''):'<div style="color:var(--muted);padding:12px;font-size:13px">No recent expenses.</div>';}loadData();</script></body></html>`;

const CHASE_REPORT_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Oxley Tire — Chase Spending</title><style>:root{--bg:#0a0a0a;--panel:#121212;--line:#242424;--gold:#e8a020;--green:#27ae60;--red:#d6493b;--muted:#8a8a8a;--text:#ececec}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:14px}header{position:sticky;top:0;background:#0c0c0c;border-bottom:2px solid var(--gold);padding:14px 18px;z-index:5}h1{margin:0 0 4px;font-size:18px;color:var(--gold);letter-spacing:1px}.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}select,button,input{background:#1b1b1b;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:14px}button{cursor:pointer}button.gold{background:var(--gold);color:#000;font-weight:700;border:none}.wrap{padding:18px;max-width:1100px;margin:0 auto}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:22px}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}.card .val{font-size:22px;font-weight:700;margin-top:6px}.green{color:var(--green)}.red{color:var(--red)}.muted{color:var(--muted)}h2{font-size:15px;color:var(--gold);border-bottom:1px solid var(--line);padding-bottom:6px;margin:26px 0 12px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}.bar{height:6px;background:#222;border-radius:4px;overflow:hidden;margin-top:4px}.bar>span{display:block;height:100%;background:var(--gold)}tr.cr td{color:var(--green)}#txwrap{max-height:600px;overflow:auto;border:1px solid var(--line);border-radius:10px}#txwrap thead th{position:sticky;top:0;background:#161616}.loading{color:var(--muted);padding:40px;text-align:center}</style></head><body><header><h1>OXLEY TIRE — CHASE SPENDING</h1><div id="period" class="muted">Loading…</div><div class="controls"><label>Window:<select id="days" onchange="load()"><option value="30">Last 30 days</option><option value="90">Last 90 days</option><option value="153" selected>Year to date</option><option value="365">Last 12 months</option></select></label><button onclick="load()">Refresh</button><button class="gold" onclick="downloadCSV()">Download CSV</button></div></header><div class="wrap"><div id="content"><div class="loading">Loading…</div></div></div><script>var WORKER=location.origin,DATA=null;function fmt(n){n=Number(n)||0;return(n<0?'-$':'$')+Math.abs(n).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}function esc(s){s=(s==null?'':String(s));return s.split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;')}function load(){var days=document.getElementById('days').value;document.getElementById('content').innerHTML='<div class="loading">Loading '+days+' days…</div>';fetch(WORKER+'/chase-transactions?days='+days+'&cb='+Date.now()).then(function(r){return r.json()}).then(function(d){DATA=d;render(d)}).catch(function(e){document.getElementById('content').innerHTML='<div class="loading">Error: '+esc(e.message)+'</div>'})}function render(d){document.getElementById('period').textContent='Period: '+d.period.start+' to '+d.period.end+'  ('+d.totalTransactions+' transactions)';var net=(d.realIncomeTotal||0)-(d.realExpenseTotal||0),h=[];h.push('<div class="cards">');h.push('<div class="card"><div class="label">Real Income</div><div class="val green">'+fmt(d.realIncomeTotal)+'</div></div>');h.push('<div class="card"><div class="label">Real Expense</div><div class="val red">'+fmt(d.realExpenseTotal)+'</div></div>');h.push('<div class="card"><div class="label">Net</div><div class="val '+(net>=0?'green':'red')+'">'+fmt(net)+'</div></div>');h.push('<div class="card"><div class="label">Transfers (excluded)</div><div class="val muted">'+fmt(d.transfersTotal)+'</div></div>');h.push('</div>');var months={};(d.transactions||[]).forEach(function(t){if(!t.date||(t.category||'').indexOf('Transfer')===0)return;var m=t.date.slice(0,7);if(!months[m])months[m]={inc:0,exp:0};if(t.amount<0)months[m].inc+=-t.amount;else months[m].exp+=t.amount});var mk=Object.keys(months).sort();if(mk.length){var maxv=0;mk.forEach(function(m){maxv=Math.max(maxv,months[m].inc,months[m].exp)});h.push('<h2>Monthly Timeline</h2><table><thead><tr><th>Month</th><th class="num">Money In</th><th class="num">Money Out</th><th class="num">Net</th></tr></thead><tbody>');mk.forEach(function(m){var o=months[m],net=o.inc-o.exp,inb=maxv?(o.inc/maxv*100):0,exb=maxv?(o.exp/maxv*100):0;h.push('<tr><td>'+esc(m)+'</td><td class="num green">'+fmt(o.inc)+'<div class="bar"><span style="width:'+inb.toFixed(1)+'%;background:var(--green)"></span></div></td><td class="num red">'+fmt(o.exp)+'<div class="bar"><span style="width:'+exb.toFixed(1)+'%"></span></div></td><td class="num '+(net>=0?'green':'red')+'">'+fmt(net)+'</td></tr>')});h.push('</tbody></table>')}h.push('<h2>Account Balances</h2><table><thead><tr><th>Account</th><th class="num">Balance</th><th class="num">Available</th></tr></thead><tbody>');(d.accounts||[]).forEach(function(a){h.push('<tr><td>'+esc(a.name)+' ('+esc(a.mask)+')</td><td class="num">'+fmt(a.balance)+'</td><td class="num">'+fmt(a.available)+'</td></tr>')});h.push('</tbody></table>');var exp=d.realExpenseTotal||1;h.push('<h2>Spending by Category</h2><table><thead><tr><th>Category</th><th class="num">Total</th><th class="num">%</th></tr></thead><tbody>');(d.byCategory||[]).forEach(function(c){var p=(c.total/exp*100);h.push('<tr><td>'+esc(c.category)+'<div class="bar"><span style="width:'+p.toFixed(1)+'%"></span></div></td><td class="num">'+fmt(c.total)+'</td><td class="num muted">'+p.toFixed(1)+'%</td></tr>')});h.push('</tbody></table>');h.push('<h2>All Transactions</h2><div class="controls"><input id="q" placeholder="Search…" oninput="filterTx()" style="flex:1;min-width:160px">');h.push('<select id="acct" onchange="filterTx()"><option value="">All accounts</option>');(d.accounts||[]).forEach(function(a){h.push('<option value="'+esc(a.name)+'">'+esc(a.name)+' ('+esc(a.mask)+')</option>')});h.push('</select></div><div id="txwrap"><table><thead><tr><th>Date</th><th>Account</th><th>Name</th><th>Category</th><th class="num">Amount</th></tr></thead><tbody id="txbody"></tbody></table></div>');document.getElementById('content').innerHTML=h.join('');filterTx()}function filterTx(){if(!DATA)return;var q=(document.getElementById('q').value||'').toLowerCase(),acct=document.getElementById('acct').value||'',rows=[];(DATA.transactions||[]).forEach(function(t){if(acct&&t.accountName!==acct)return;var hay=((t.name||'')+' '+(t.category||'')).toLowerCase();if(q&&hay.indexOf(q)<0)return;var isCr=t.amount<0;rows.push('<tr class="'+(isCr?'cr':'')+'"><td class="muted">'+esc(t.date)+'</td><td class="muted">'+esc(t.accountName)+'</td><td>'+esc(t.name)+'</td><td>'+esc(t.category)+'</td><td class="num">'+(isCr?'+':'')+fmt(Math.abs(t.amount))+'</td></tr>')});document.getElementById('txbody').innerHTML=rows.join('')||'<tr><td colspan="5" class="muted">No matching transactions.</td></tr>'}function downloadCSV(){if(!DATA)return;function cell(v){v=(v==null?'':String(v));if(v.indexOf('"')>-1||v.indexOf(',')>-1||v.indexOf('\\n')>-1){v='"'+v.split('"').join('""')+'"'}return v}var lines=['Date,Account,Mask,Name,Category,Type,Amount'],maskFor={};(DATA.accounts||[]).forEach(function(a){maskFor[a.name]=a.mask});(DATA.transactions||[]).forEach(function(t){lines.push([cell(t.date),cell(t.accountName),cell(maskFor[t.accountName]||''),cell(t.name),cell(t.category),cell(t.type),cell(t.amount)].join(','))});var blob=new Blob([lines.join('\\n')],{type:'text/csv'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='chase-'+DATA.period.start+'_to_'+DATA.period.end+'.csv';document.body.appendChild(a);a.click();document.body.removeChild(a)}load();</script></body></html>`;