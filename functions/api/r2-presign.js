// api/r2-presign.js
// Vercel serverless function. Signs R2 PUT/DELETE URLs.
// Holds the R2 secret in env vars. Never returns the secret to the client.
//
// Security model:
//   - Caller must be an authenticated Supabase user.
//   - Path must live under the caller's own user folder.
//   - PUT: extension and content-type allow-listed; content-type signed
//     into the URL so R2 rejects mismatches.
//   - DELETE: only signed if the file is not referenced by any row in
//     posts / sparks / statuses / ads. Prevents accidental orphaning of
//     media that is still in use.

const crypto = require('crypto');

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;

/* Public base URL of the R2 bucket. Must match Z.R2_PUBLIC_BASE in
   index.html. Used to reconstruct full media URLs when checking whether
   a file is still referenced by a database row. */
const R2_PUBLIC_BASE = process.env.R2_PUBLIC_BASE || 'https://pub-cd1b1d46d6d2450283f494cb457ca83e.r2.dev';

const SUPABASE_URL = 'https://ipypwqajsfxrdzlxfnlr.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlweXB3cWFqc2Z4cmR6bHhmbmxyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg2OTEzODUsImV4cCI6MjEwNDI2NzM4NX0.QW6tzaMxlNg9EYuRq0tCOlGipBlrjBuiV6lZuSr1Jj4';

/* Allow-lists — must stay in sync with _ALLOWED_MEDIA_EXT in index.html */
const ALLOWED_EXTENSIONS = ['jpg','jpeg','png','webp','gif','mp4','webm','mov','m4v','3gp'];

const ALLOWED_CONTENT_TYPES = [
  'image/jpeg','image/png','image/webp','image/gif',
  'video/mp4','video/webm','video/quicktime','video/3gpp','video/x-m4v'
];

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

/* Ask Supabase whether any row in {table} still points at {fullUrl} via
   {urlColumn}. {excludeId} skips one row (the one currently being
   deleted). On error we return true (assume referenced) — safer to
   leave an orphan than to delete a file still in use. */
async function findReference(table, urlColumn, fullUrl, excludeId, bearerToken) {
  try {
    const params = new URLSearchParams();
    params.set('select', 'id');
    params.set(urlColumn, 'eq.' + fullUrl);
    if (excludeId) params.set('id', 'neq.' + excludeId);
    params.set('limit', '1');

    const r = await fetch(SUPABASE_URL + '/rest/v1/' + table + '?' + params.toString(), {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': 'Bearer ' + bearerToken
      }
    });
    if (!r.ok) return true;
    const data = await r.json().catch(function () { return []; });
    return Array.isArray(data) && data.length > 0;
  } catch (e) {
    return true;
  }
}

async function isReferenced(fullUrl, excludeId, bearerToken) {
  const checks = await Promise.all([
    findReference('posts',    'media_url', fullUrl, excludeId, bearerToken),
    findReference('sparks',   'video_url', fullUrl, excludeId, bearerToken),
    findReference('statuses', 'media_url', fullUrl, null,      bearerToken),
    findReference('ads',      'media_url', fullUrl, null,      bearerToken)
  ]);
  return checks.some(function (v) { return v; });
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
    const ext = extFromPath(path);
    if (!ext || ALLOWED_EXTENSIONS.indexOf(ext) === -1) {
      return res.status(400).json({
        error: 'Unsupported file extension',
        allowed: ALLOWED_EXTENSIONS
      });
    }

    let contentType = (body.contentType || '').toString().trim().toLowerCase();
    if (!contentType) contentType = DEFAULT_MIME_BY_EXT[ext] || '';
    if (ALLOWED_CONTENT_TYPES.indexOf(contentType) === -1) {
      return res.status(400).json({
        error: 'Unsupported content-type',
        allowed: ALLOWED_CONTENT_TYPES
      });
    }

    const compatible = MIME_BY_EXT[ext] || [];
    if (compatible.indexOf(contentType) === -1) {
      return res.status(400).json({
        error: 'Extension does not match content-type',
        extension: ext,
        allowedContentTypesForExtension: compatible
      });
    }

    const url = presign('PUT', path, 3600, { 'content-type': contentType });
    return res.status(200).json({ url: url, contentType: contentType });
  }

  /* ---- DELETE ---- */
  const fullUrl = R2_PUBLIC_BASE + '/' + path;
  const excludeId = (typeof body.excludeId === 'string' && body.excludeId) ? body.excludeId : null;
  const bearerToken = req.headers.authorization.slice(7);

  const referenced = await isReferenced(fullUrl, excludeId, bearerToken);
  if (referenced) {
    return res.status(409).json({ error: 'File still referenced by existing content' });
  }

  const url = presign('DELETE', path, 3600);
  return res.status(200).json({ url: url });
};
