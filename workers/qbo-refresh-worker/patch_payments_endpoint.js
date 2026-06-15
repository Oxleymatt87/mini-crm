#!/usr/bin/env node
// Inserts (or upgrades) the /payments-by-customer route + fetchPaymentsByCustomer()
// in the qbo-refresh-worker source WITHOUT touching any other code.
//
//   node patch_payments_endpoint.js <input-source.js> <output-source.js>
//
// <input-source.js> should be the *live deployed* worker source so existing
// endpoints and the inline HTML dashboards stay byte-for-byte identical.
// Re-running upgrades a previously-inserted version (removes the old route +
// function first, then inserts the current ones).

const fs = require('fs');
const path = require('path');

const [, , inPath, outPath] = process.argv;
if (!inPath || !outPath) {
  console.error('usage: node patch_payments_endpoint.js <input.js> <output.js>');
  process.exit(2);
}

let src = fs.readFileSync(inPath, 'utf8');

// If Cloudflare returned the script as multipart/form-data, pull out the JS module body.
if (/Content-Disposition:\s*form-data/i.test(src)) {
  const parts = src.split(/--[-0-9a-f]{16,}/i);
  let best = '';
  for (const p of parts) {
    const idx = p.indexOf('\r\n\r\n') !== -1 ? p.indexOf('\r\n\r\n') + 4
              : (p.indexOf('\n\n') !== -1 ? p.indexOf('\n\n') + 2 : -1);
    if (idx === -1) continue;
    const body = p.slice(idx).replace(/\r?\n--\s*$/, '').trim();
    if (body.includes('export default') && body.length > best.length) best = body;
  }
  if (best) src = best;
}

if (!src.includes('export default')) {
  throw new Error('Input does not look like a Worker module (no "export default").');
}

const had = src.includes('/payments-by-customer');

// 0) Remove any previously-inserted route block (exact shape we always emit).
src = src.replace(
  /[ \t]*if \(url\.pathname === '\/payments-by-customer'\)[\s\S]*?return await fetchPaymentsByCustomer\([^\n]*\n[ \t]*\}\n+/,
  ''
);
// Remove any previously-inserted function (with its leading comment block).
src = src.replace(
  /(?:[ \t]*\/\/[^\n]*\n)*async function fetchPaymentsByCustomer[\s\S]*?\nconst CONNECT_HTML =/,
  'const CONNECT_HTML ='
);

// 1) Route handler — inserted just before the fallback "status: ok" response.
const ROUTE =
  "      if (url.pathname === '/payments-by-customer') {\n" +
  "        const s = url.searchParams.get('start_date') || '2026-01-01';\n" +
  "        const e = url.searchParams.get('end_date') || '2026-06-14';\n" +
  "        return await fetchPaymentsByCustomer(env, corsHeaders, s, e);\n" +
  "      }\n\n";

const routeAnchor = "      return new Response(JSON.stringify({ status: 'ok'";
if (!src.includes(routeAnchor)) throw new Error('Route anchor not found in source.');
src = src.replace(routeAnchor, ROUTE + routeAnchor);

// 2) Function body — inserted just before the first inline HTML constant.
const fn = fs.readFileSync(path.join(__dirname, 'payments_by_customer.fn.js'), 'utf8').trim();
const funcAnchor = 'const CONNECT_HTML =';
if (!src.includes(funcAnchor)) throw new Error('Function anchor (CONNECT_HTML) not found in source.');
src = src.replace(funcAnchor, fn + '\n\n' + funcAnchor);

// 3) Advertise the endpoint in the default index response (only if missing).
if (!src.includes("'/payments-by-customer'") || (src.match(/'\/payments-by-customer'/g) || []).length < 2) {
  if (!/'\/new-prospect','\/payments-by-customer']/.test(src)) {
    src = src.replace("'/new-prospect']", "'/new-prospect','/payments-by-customer']");
  }
}

fs.writeFileSync(outPath, src);
console.error(had
  ? 'Upgraded: replaced existing /payments-by-customer route + function.'
  : 'Patched: added /payments-by-customer route + fetchPaymentsByCustomer().');
