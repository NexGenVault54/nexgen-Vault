// api/r2-presign.js
// Vercel serverless function. Signs R2 PUT/DELETE URLs.
// Holds the R2 secret in env vars. Never returns the secret to the client.
//
// Security model:
//   - Caller must be an authenticated Supabase user.
//   - Path must live under the caller's own user folder.
//   - PUT requests are only signed for allow-listed media types: the
//     extension must be in ALLOWED_EXTENSIONS and the content-type must
//     be compatible with it. The content-type is signed into the URL, so
//     R2 rejects any PUT whose Content-Type header does not match what
//     was authorised.
//   - DELETE requests skip the extension/content-type check.

const crypto = require('crypto');

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;

const SUPABASE_URL = 'https://ipypwqajsfxrdzlxfnlr.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlweXB3cWFqc2Z4cmR6bHhmbmxyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg2OTEzODUsImV4cCI6MjEwNDI2NzM4NX0.QW6tzaMxlNg9EYuRq0tCOlGipBlrjBuiV6lZuSr1Jj4';

/* Allow-lists — must stay in sync with _ALLOWED_MEDIA_EXT in index.html */
const ALLOWED_EXTENSIONS = ['jpg','jpeg','png','webp','gif','mp4','webm','mov','m4v','3gp'];

const ALLOWED_CONTENT_TYPES = [
  'image/jpeg','image/png','image/webp','image/gif',
  'video/mp4','video/webm','video/quicktime','video/3gpp','video/x-m4v'
];

/* Extension → required content-types. Enforces that a .jpg cannot be
   uploaded with video/mp4, etc. This is the strongest guarantee we can
   give without inspecting the actual bytes. */
const MIME_BY_EXT = {
  jpg:   ['image/jpeg'],
  jpeg:  ['image/jpeg'],
  png:   ['image/png'],
  webp:  ['image/webp'],
  gif:   ['image/gif'],
  mp4:   ['video/mp4'],
  webm:  ['video/webm'],
  mov:   ['video/quicktime'],
  m4v:   ['video/x-m4v','video/mp4'],
  '3gp': ['video/3gpp']
};

/* Fallback content-type when the client does not declare one, based on
   the file extension. Used to keep uploads working for older clients
   that do not send body.contentType. */
const DEFAULT_MIME_BY_EXT = {
  jpg:   'image/jpeg',
  jpeg:  'image/jpeg',
  png:   'image/png',
  webp:  'image/webp',
  gif:   'image/gif',
  mp4:   'video/mp4',
  webm:  'video/webm',
  mov:   'video/quicktime',
  m4v:   'video/mp4',
  '3gp': 'video/3gpp'
};

const MAX_PATH_LENGTH = 400;

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function getSignatureKey(secret, date, region, service) {
  const kDate = hmac('AWS4' + secret, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

function encodeRfc3986(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, c =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

/* presign() signs host plus any extra headers passed in. For PUT we
   pass { 'content-type': <mime> } so R2 rejects any PUT whose
   Content-Type header does not match the signature. */
function presign(method, path, expires, extraHeaders) {
  extraHeaders = extraHeaders || {};
  const host = R2_ACCOUNT_ID + '.r2.cloudflarestorage.com';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const region = 'auto';
  const service = 's3';
  const credentialScope = dateStamp + '/' + region + '/' + service + '/aws4_request';

  const canonicalUri = '/' + R2_BUCKET + '/' + path.split('/').map(encodeRfc3986).join('/');

  const headersToSign = { host: host };
  Object.keys(extraHeaders).forEach(function (k) {
    headersToSign[k.toLowerCase()] = String(extraHeaders[k]).trim();
  });
  const signedHeaderNames = Object.keys(headersToSign).sort();
  const signedHeaders = signedHeaderNames.join(';');
  const canonicalHeaders = signedHeaderNames
    .map(function (name) { return name + ':' + headersToSign[name] + '\n'; })
    .join('');

  const queryParams = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': R2_ACCESS_KEY_ID + '/' + credentialScope,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': signedHeaders
  };

  const canonicalQuery = Object.keys(queryParams)
    .sort()
    .map(k => encodeRfc3986(k) + '=' + encodeRfc3986(queryParams[k]))
    .join('&');

  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256hex(canonicalRequest)
  ].join('\n');

  const signingKey = getSignatureKey(R2_SECRET_ACCESS_KEY, dateStamp, region, service);
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return 'https://' + host + canonicalUri + '?' + canonicalQuery + '&X-Amz-Signature=' + signature;
}

async function verifyUser(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  const r = await fetch(SUPABASE_URL + '/auth/v1/user', {
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + token
    }
  });
  if (!r.ok) return null;
  const user = await r.json().catch(() => null);
  if (!user || !user.id) return null;
  return user;
}

function extFromPath(p) {
  const dot = p.lastIndexOf('.');
  if (dot === -1) return '';
  const slash = p.lastIndexOf('/');
  if (slash > dot) return '';
  return p.slice(dot + 1).toLowerCase();
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  const user = await verifyUser(req.headers.authorization);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const body = req.body || {};
  const action = body.action;
  const path = body.path;

  if (!action || !path || typeof path !== 'string') {
    return res.status(400).json({ error: 'Missing action or path' });
  }
  if (path.length > MAX_PATH_LENGTH) {
    return res.status(400).json({ error: 'Path too long' });
  }
  if (path.indexOf('..') !== -1 || path.startsWith('/')) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  if (!path.startsWith(user.id + '/')) {
    return res.status(403).json({ error: 'Path must be under your user folder' });
  }
  if (action !== 'put' && action !== 'delete') {
    return res.status(400).json({ error: 'Invalid action' });
  }

  if (action === 'put') {
    /* ---- PUT: strict extension + content-type checks ---- */
    const ext = extFromPath(path);
    if (!ext || ALLOWED_EXTENSIONS.indexOf(ext) === -1) {
      return res.status(400).json({
        error: 'Unsupported file extension',
        allowed: ALLOWED_EXTENSIONS
      });
    }

    /* Determine the content-type we will sign. Prefer the client's
       declared type; fall back to the extension's default. Both must
       be in the allow-list. */
    let contentType = (body.contentType || '').toString().trim().toLowerCase();
    if (!contentType) contentType = DEFAULT_MIME_BY_EXT[ext] || '';
    if (ALLOWED_CONTENT_TYPES.indexOf(contentType) === -1) {
      return res.status(400).json({
        error: 'Unsupported content-type',
        allowed: ALLOWED_CONTENT_TYPES
      });
    }

    /* Extension must be compatible with the declared content-type. */
    const compatible = MIME_BY_EXT[ext] || [];
    if (compatible.indexOf(contentType) === -1) {
      return res.status(400).json({
        error: 'Extension does not match content-type',
        extension: ext,
        allowedContentTypesForExtension: compatible
      });
    }

    /* Sign content-type into the URL. R2 will reject any PUT whose
       Content-Type header differs from this value. */
    const url = presign('PUT', path, 3600, { 'content-type': contentType });
    return res.status(200).json({ url: url, contentType: contentType });
  }

  /* ---- DELETE: no extension/content-type check needed ---- */
  const url = presign('DELETE', path, 3600);
  return res.status(200).json({ url: url });
};
