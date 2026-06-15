// ─── PAYMENTS BY CUSTOMER (Deposits grouped by customer + payment method) ─────
// Queries every QBO Deposit in [startDate, endDate], reads each deposit line's
// Entity (customer) and PaymentMethodRef (payment method), and groups the
// dollar totals into { customer: { payment_method: amount } }.
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
  const byCustomer = {};
  const byMethod = {};
  const unknownSamples = [];
  let grandTotal = 0, lineCount = 0;

  for (const dep of deposits) {
    const depMemo = dep.PrivateNote || '';
    for (const line of dep.Line || []) {
      const amt = parseFloat(line.Amount || 0);
      if (!amt) continue;
      const dld = line.DepositLineDetail || {};
      const desc = line.Description || '';

      const customer = (dld.Entity && dld.Entity.name) ? dld.Entity.name : 'Unknown';

      let method = (dld.PaymentMethodRef && dld.PaymentMethodRef.name) ? dld.PaymentMethodRef.name : null;
      if (!method && dld.PaymentMethodRef && dld.PaymentMethodRef.value) method = methodMap[dld.PaymentMethodRef.value] || null;
      if (!method) method = inferMethod(desc) || inferMethod(depMemo) || 'Unknown';

      if (!byCustomer[customer]) byCustomer[customer] = {};
      byCustomer[customer][method] = round2((byCustomer[customer][method] || 0) + amt);
      byMethod[method] = round2((byMethod[method] || 0) + amt);
      grandTotal += amt;
      lineCount++;

      if ((customer === 'Unknown' || method === 'Unknown') && unknownSamples.length < 50) {
        unknownSamples.push({ depositId: dep.Id, date: dep.TxnDate, amount: round2(amt), customer, method, description: desc, memo: depMemo });
      }
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
    byMethod,
    byCustomer: sortedCustomers,
    diagnostics: { unknownSampleCount: unknownSamples.length, unknownSamples }
  }), { headers: { ...h, 'Content-Type': 'application/json' } });
}
