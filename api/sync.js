const crypto = require('node:crypto');

const ALLOWED_ORIGINS = new Set([
  'https://salehzaid.github.io',
  'https://exec-committee-hotat.vercel.app',
]);

function setCors(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Cache-Control', 'no-store');
}

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function signToken() {
  const payload = b64url(JSON.stringify({
    exp: Date.now() + (30 * 24 * 60 * 60 * 1000),
  }));
  const signature = crypto
    .createHmac('sha256', process.env.SYNC_SECRET)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

function verifyToken(token) {
  if (!token || !process.env.SYNC_SECRET) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  const expected = crypto
    .createHmac('sha256', process.env.SYNC_SECRET)
    .update(payload)
    .digest('base64url');
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (
    actualBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  ) return false;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now();
  } catch {
    return false;
  }
}

async function sql(query, params = []) {
  const response = await fetch(process.env.NEON_SQL_URL, {
    method: 'POST',
    headers: {
      'Neon-Connection-String': process.env.NEON_CONNECTION_STRING,
    },
    body: JSON.stringify({ query, params }),
  });
  if (!response.ok) throw new Error(`Database request failed: ${response.status}`);
  return response.json();
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });

  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

  if (body.action === 'login') {
    if (!process.env.SYNC_PIN || body.pin !== process.env.SYNC_PIN) {
      return res.status(401).json({ error: 'invalid_pin' });
    }
    return res.status(200).json({ token: signToken() });
  }

  const auth = req.headers.authorization || '';
  if (!verifyToken(auth.replace(/^Bearer\s+/i, ''))) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    if (body.action === 'get') {
      const result = await sql(
        'select payload from committee_state where id=$1',
        ['main'],
      );
      return res.status(200).json({ state: result.rows?.[0]?.payload || null });
    }

    if (body.action === 'save') {
      if (!body.state || typeof body.state !== 'object' || !body.state.meta) {
        return res.status(400).json({ error: 'invalid_state' });
      }
      await sql(
        'insert into committee_state(id, payload, updated_at) values($1, $2::jsonb, now()) on conflict (id) do update set payload=excluded.payload, updated_at=now()',
        ['main', JSON.stringify(body.state)],
      );
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: 'invalid_action' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'sync_failed' });
  }
};
