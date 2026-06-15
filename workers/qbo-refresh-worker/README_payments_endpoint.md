# `/payments-by-customer` endpoint

Adds a read-only endpoint to `qbo-refresh-worker` that breaks down QuickBooks
**Deposits** by customer and payment method.

## What it returns

`GET https://qbo-refresh-worker.moxley.workers.dev/payments-by-customer`

Defaults to **Jan 1 2026 → Jun 14 2026**. Override with
`?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD`.

```jsonc
{
  "period": { "start": "2026-01-01", "end": "2026-06-14" },
  "depositCount": 0,
  "lineCount": 0,
  "grandTotal": 0,
  "byMethod": { "Cash": 0, "Check": 0, "Zelle": 0 },
  "byCustomer": {            // <-- the requested { customer: { payment_method: amount } }
    "Acme Trucking": { "Check": 1200.00, "Zelle": 350.00 },
    "Unknown": { "Cash": 75.00 }
  },
  "diagnostics": { "unknownSampleCount": 0, "unknownSamples": [] }
}
```

`byCustomer` is sorted by total (largest first). `diagnostics.unknownSamples`
lists up to 50 deposit lines where the customer or method couldn't be resolved
(shows the date/amount/memo) so the mapping can be refined later.

## How it works

- Reuses the existing token logic: `qboApiCall()` reads the access token from the
  **`QBO_TOKENS` KV namespace** and auto-refreshes via `refreshAccessToken()` when
  it's within 5 minutes of expiry. No new secrets needed.
- Pages through `SELECT * FROM Deposit WHERE TxnDate >= ... AND TxnDate <= ...`
  (1000/page) against production QBO (realm `9130357532009796`).
- Per deposit line: customer = `DepositLineDetail.Entity.name`; payment method =
  `DepositLineDetail.PaymentMethodRef` (resolved against the `PaymentMethod` list
  when only an id is present), falling back to keyword inference from the line
  description / deposit memo, else `"Unknown"`.

## Deploy

The deploy script fetches the **currently deployed** worker source and patches in
*only* the new route + function, so every existing endpoint and the inline HTML
dashboards (`/dad`, `/chase-report`, `/connect-chase`) stay byte-for-byte
identical. Existing secrets are preserved via `keep_bindings`; the `QBO_TOKENS`
KV binding is re-declared.

```bash
export CF_API_TOKEN="<cloudflare API token with Workers Scripts:Edit>"
cd workers/qbo-refresh-worker
./deploy_payments_endpoint.sh
```

Then from Termux:

```bash
curl -s "https://qbo-refresh-worker.moxley.workers.dev/payments-by-customer" | head -c 2000
```

## Files

- `payments_by_customer.fn.js` — the `fetchPaymentsByCustomer()` function (source of truth).
- `patch_payments_endpoint.js` — idempotent patcher that injects the route + function.
- `deploy_payments_endpoint.sh` — fetch live source → patch → multipart upload.

> Note: the repo's `worker.js` is an older snapshot. The live worker is a newer
> revision (KV-based tokens, Plaid/Chase + dashboard endpoints); that live
> revision is the patch/deploy base, which is why deployment pulls it fresh
> rather than uploading `worker.js`.
