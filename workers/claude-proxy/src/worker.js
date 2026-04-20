// claude-proxy — thin Cloudflare Worker in front of the Anthropic Messages API.
//
// Routing logic:
//   * Vision requests  (any message.content block with type === 'image')
//       → no system prompt, max_tokens 1024
//   * Chat requests    (everything else)
//       → Oxley Tire sales copilot system prompt, max_tokens 500
//
// The client can still override `model`, `temperature`, `top_p`, `top_k`,
// `stop_sequences`, and `metadata` on the request body. `system` and
// `max_tokens` are set by the worker and ignored if the client sends them.
//
// Secret: ANTHROPIC_API_KEY (already provisioned — do not commit).
// Optional env: SALES_SYSTEM_PROMPT — overrides the hardcoded prompt below
// without a redeploy (set via `wrangler secret put SALES_SYSTEM_PROMPT`).

const DEFAULT_MODEL = 'claude-sonnet-4-6';
const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';

const SALES_COPILOT_PROMPT = `You are the Oxley Tire sales copilot.

Oxley Tire Inc. is a commercial truck tire wholesaler. You assist the sales
team with customer intelligence, invoice and balance questions, tire size /
brand / model lookups, margin math, and quick operational decisions.

Style:
- Be direct, concise, and technical. No filler, no disclaimers.
- Prices are USD. Dates are US format. Sizes use ISO metric (e.g. 11R22.5,
  295/75R22.5). Brand/model codes are uppercase (AT505, AD507, SL101).
- When referring to a customer, assume it's the QBO customer record.
- If asked about data you cannot see, say so in one line rather than guessing.
- Prefer short bulleted lists over prose for structured answers.`;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return preflight();
    if (request.method !== 'POST') return cors(text('method not allowed', 405));

    if (!env.ANTHROPIC_API_KEY) {
      return cors(json({ error: 'ANTHROPIC_API_KEY not configured on worker' }, 500));
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return cors(json({ error: 'invalid JSON body' }, 400));
    }

    const messages = Array.isArray(body?.messages) ? body.messages : [];
    if (messages.length === 0) {
      return cors(json({ error: 'messages[] required' }, 400));
    }

    const isVision = hasImageBlock(messages);

    const payload = {
      model: typeof body.model === 'string' ? body.model : DEFAULT_MODEL,
      messages,
      max_tokens: isVision ? 1024 : 500,
    };
    if (!isVision) {
      payload.system = env.SALES_SYSTEM_PROMPT || SALES_COPILOT_PROMPT;
    }
    // Pass through safe client-controlled knobs.
    for (const k of ['temperature', 'top_p', 'top_k', 'stop_sequences', 'metadata']) {
      if (body[k] !== undefined) payload[k] = body[k];
    }

    const upstream = await fetch(ANTHROPIC_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': ANTHROPIC_VERSION,
      },
      body: JSON.stringify(payload),
    });

    const bodyText = await upstream.text();
    return cors(new Response(bodyText, {
      status: upstream.status,
      headers: {
        'content-type': upstream.headers.get('content-type') || 'application/json',
        'x-claude-proxy-mode': isVision ? 'vision' : 'chat',
      },
    }));
  },
};

function hasImageBlock(messages) {
  for (const m of messages) {
    const c = m?.content;
    if (!Array.isArray(c)) continue;
    for (const block of c) {
      if (block && block.type === 'image') return true;
    }
  }
  return false;
}

function preflight() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(),
  });
}

function cors(resp) {
  const h = corsHeaders();
  for (const [k, v] of Object.entries(h)) resp.headers.set(k, v);
  return resp;
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'POST, OPTIONS',
    'access-control-allow-headers': 'content-type, x-claude-proxy-client',
    'access-control-max-age': '86400',
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function text(s, status = 200) {
  return new Response(s, { status, headers: { 'content-type': 'text/plain' } });
}
