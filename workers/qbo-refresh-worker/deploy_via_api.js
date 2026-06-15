#!/usr/bin/env node
// Self-contained Node deploy for the /payments-by-customer endpoint.
//
// SAFE-BY-DESIGN: instead of overwriting the whole worker with a hand-written
// code string (which would delete every other endpoint and drop the QBO_TOKENS
// KV binding + secrets), this:
//   1. fetches the CURRENTLY deployed worker source,
//   2. patches in ONLY the new route + fetchPaymentsByCustomer() function,
//   3. uploads it back via the multipart Workers Script API with
//      keep_bindings (preserves existing secrets) + the QBO_TOKENS KV binding,
//   4. logs the response and tests the live endpoint.
//
// Usage:  CF_API_TOKEN=... node deploy_via_api.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ACCOUNT_ID = 'e450a418975ed9b1212f52452bb1b5d5';
const SCRIPT_NAME = 'qbo-refresh-worker';
const KV_NAMESPACE_ID = '9e61d4d0d02a476692cfa71c1002908b'; // QBO_TOKENS
const COMPAT_DATE = '2024-11-01';
const WORKER_URL = `https://${SCRIPT_NAME}.moxley.workers.dev/payments-by-customer`;

const TOKEN = process.env.CF_API_TOKEN;
if (!TOKEN) { console.error('Set CF_API_TOKEN env var.'); process.exit(2); }

const API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}`;
const auth = { Authorization: `Bearer ${TOKEN}` };

(async () => {
  // 1) Fetch current deployed source.
  // Note: GET .../content is rejected for this token type (10405); the bare
  // script endpoint returns the module(s) as multipart, which the patcher reads.
  console.log('→ Fetching current deployed worker source...');
  const res = await fetch(API, { headers: auth });
  if (!res.ok) { console.error(`GET content failed: ${res.status}\n${await res.text()}`); process.exit(1); }
  const live = await res.text();

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qbo-'));
  const curPath = path.join(tmp, 'current.js');
  const outPath = path.join(tmp, 'worker.js');
  fs.writeFileSync(curPath, live);

  // 2) Patch in only the new route + function (idempotent, preserves everything else)
  console.log('→ Patching in /payments-by-customer...');
  execFileSync('node', [path.join(__dirname, 'patch_payments_endpoint.js'), curPath, outPath], { stdio: 'inherit' });
  const code = fs.readFileSync(outPath, 'utf8');

  // 3) Upload via multipart, preserving secrets (keep_bindings) + KV binding
  console.log('→ Uploading patched worker (multipart, bindings preserved)...');
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: COMPAT_DATE,
    keep_bindings: ['secret_text', 'secret_key'],
    bindings: [{ type: 'kv_namespace', name: 'QBO_TOKENS', namespace_id: KV_NAMESPACE_ID }],
  };
  const fd = new FormData();
  fd.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
  fd.append('worker.js', new Blob([code], { type: 'application/javascript+module' }), 'worker.js');

  const up = await fetch(API, { method: 'PUT', headers: auth, body: fd });
  const text = await up.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  console.log('Deploy response:', json ? JSON.stringify(json.errors || json.messages || { success: json.success }, null, 2) : text);

  if (!json || !json.success) { console.error('❌ Deploy failed.'); process.exit(1); }
  console.log('✅ Deployed.');

  // 4) Test the live endpoint
  console.log(`→ Testing ${WORKER_URL} ...`);
  const t = await fetch(WORKER_URL);
  console.log('Test HTTP status:', t.status);
  const body = await t.text();
  console.log(body.slice(0, 3000));
})().catch((e) => { console.error('Error:', e.message); process.exit(1); });
