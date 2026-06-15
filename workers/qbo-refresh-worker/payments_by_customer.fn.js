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
