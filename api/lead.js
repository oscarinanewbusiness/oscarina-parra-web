// /api/lead.js
// Browser -> this same-origin endpoint -> private Google Apps Script webhook.
// Keep LEAD_WEBHOOK_SECRET only in Vercel environment variables.

const DEFAULT_ALLOWED_ORIGINS = [
  'https://oscarinainsurance.com',
  'https://www.oscarinainsurance.com',
  'https://oscarinaparrainsurancegroup.com',
  'https://www.oscarinaparrainsurancegroup.com'
];

function clean(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function validEmail(email) {
  if (!email) return true;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPhone(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  return digits.length >= 10 && digits.length <= 15;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const webhookUrl = process.env.LEAD_WEBHOOK_URL;
  const webhookSecret = process.env.LEAD_WEBHOOK_SECRET;

  if (!webhookUrl || !webhookSecret) {
    return res.status(503).json({ ok: false, error: 'Lead capture is not configured' });
  }

  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);

  const allowed = allowedOrigins.length ? allowedOrigins : DEFAULT_ALLOWED_ORIGINS;
  const origin = req.headers.origin || '';
  if (origin && !allowed.includes(origin)) {
    return res.status(403).json({ ok: false, error: 'Origin not allowed' });
  }

  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  } catch (_) {
    return res.status(400).json({ ok: false, error: 'Invalid JSON' });
  }

  // Honeypot: pretend success so bots do not retry.
  if (clean(body.website, 120)) {
    return res.status(200).json({ ok: true, spam: true });
  }

  const payload = {
    secret: webhookSecret,
    lead_id: clean(body.lead_id, 100),
    nombre: clean(body.nombre, 120),
    telefono: clean(body.telefono, 40),
    email: clean(body.email, 180),
    estado: clean(body.estado, 80),
    mensaje: clean(body.mensaje, 1000),
    consentimiento: body.consentimiento === true,
    source: clean(body.source, 80),
    cta: clean(body.cta, 160),
    intended_channel: clean(body.intended_channel, 40),
    page_title: clean(body.page_title, 180),
    landing_page: clean(body.attribution?.landing_page, 1000),
    referrer: clean(body.attribution?.referrer, 1000),
    utm_source: clean(body.attribution?.utm_source, 180),
    utm_medium: clean(body.attribution?.utm_medium, 180),
    utm_campaign: clean(body.attribution?.utm_campaign, 220),
    utm_term: clean(body.attribution?.utm_term, 220),
    utm_content: clean(body.attribution?.utm_content, 220),
    gclid: clean(body.attribution?.gclid, 300),
    gbraid: clean(body.attribution?.gbraid, 300),
    wbraid: clean(body.attribution?.wbraid, 300),
    user_agent: clean(req.headers['user-agent'], 500)
  };

  if (!payload.lead_id || !payload.nombre || !payload.estado || !payload.consentimiento) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }
  if (!validPhone(payload.telefono)) {
    return res.status(400).json({ ok: false, error: 'Invalid phone' });
  }
  if (!validEmail(payload.email)) {
    return res.status(400).json({ ok: false, error: 'Invalid email' });
  }

  try {
    const r = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      redirect: 'follow'
    });

    const text = await r.text();
    let data = {};
    try { data = JSON.parse(text); } catch (_) {}

    if (!r.ok || data.ok !== true) {
      return res.status(502).json({ ok: false, error: 'Lead storage failed' });
    }

    return res.status(200).json({
      ok: true,
      lead_id: payload.lead_id,
      duplicate: data.duplicate === true
    });
  } catch (_) {
    return res.status(502).json({ ok: false, error: 'Lead storage unavailable' });
  }
}
