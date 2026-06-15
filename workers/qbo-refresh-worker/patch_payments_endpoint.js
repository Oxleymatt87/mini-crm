#!/usr/bin/env node
// Inserts the /payments-by-customer route + fetchPaymentsByCustomer() into the
// qbo-refresh-worker source WITHOUT touching any existing code (idempotent).
//
//   node patch_payments_endpoint.js <input-source.js> <output-source.js>
//
// <input-source.js> should be the *live deployed* worker source (fetched via the
// Cloudflare API in deploy_payments_endpoint.sh) so existing endpoints and the
// inline HTML dashboards stay byte-for-byte identical.

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

if (src.includes('/payments-by-customer')) {
  fs.writeFileSync(outPath, src);
  console.error('Already patched — /payments-by-customer present. Wrote source unchanged.');
  process.exit(0);
}

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
let fn = fs.readFileSync(path.join(__dirname, 'payments_by_customer.fn.js'), 'utf8').trim();
const funcAnchor = 'const CONNECT_HTML =';
if (!src.includes(funcAnchor)) throw new Error('Function anchor (CONNECT_HTML) not found in source.');
src = src.replace(funcAnchor, fn + '\n\n' + funcAnchor);

// 3) Advertise the new endpoint in the default index response (best-effort).
src = src.replace("'/new-prospect']", "'/new-prospect','/payments-by-customer']");

fs.writeFileSync(outPath, src);
console.error('Patched: added /payments-by-customer route + fetchPaymentsByCustomer().');
