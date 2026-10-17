// functions/api/r2-presign.js
// Cloudflare Pages Function. Signs R2 PUT/DELETE URLs.
// Holds the R2 secret in env vars. Never returns the secret to the client.
//
// Converted from Vercel serverless format to Cloudflare Pages Functions.
// Logic is unchanged — only the runtime interface changed:
//   - crypto: Node 'crypto' → Web Crypto API (async)
//   - env:    process.env    → env (from context)
//   - HTTP:   req/res        → request/Response
//
// Security model (unchanged):
//   - Caller must be an authenticated Supabase user.
//   - Path must live under the caller's own user folder.
//   - PUT: extension and content-type allow-listed; content-type signed
//     into the URL so R2 rejects mismatches.
//   - DELETE: only signed if the file is not referenced by any row in
//     posts / sparks / statuses / ads.

/* ---- Allow-lists (must stay in sync with _ALLOWED_MEDIA_EXT in index.html) ---- */
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
const SUPABASE_URL = 'https://ipypwqajsfxrdzlxfnlr.supabase.co';

/* ---- Web Crypto helpers (replace Node's require('crypto')) ---- */
const _enc = new TextEncoder();

async function hmacSha256(keyBytes, dataBytes) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, dataBytes);
  return new Uint8Array(sig);
}

async function sha256Hex(dataStr) {
  const bytes = _enc.encode(dataStr);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map(function(b){ return b.toString(16).padStart(2, '0'); })
    .join('');
}

async function getSignatureKey(secret, date, region, service) {
  let k = await hmacSha256(_enc.encode('AWS4' + secret), _enc.encode(date));
  k = await hmacSha256(k, _enc.encode(region));
  k = await hmacSha256(k, _enc.encode(service));
  k = await hmacSha256(k, _enc.encode('aws4_request'));
  return k;
}

function encodeRfc3986(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, function(c){
    return '%' + c.charCodeAt(0).toString(16).toUpperCase();
  });
}

/* ---- Presign — async because Web Crypto is async ---- */
async function presign(method, path, expires, extraHeaders, env) {
  extraHeaders = extraHeaders || {};
  const host = env.R2_ACCOUNT_ID + '.r2.cloudflarestorage.com';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const region = 'auto';
  const service = 's3';
  const credentialScope = dateStamp + '/' + region + '/' + service + '/aws4_request';

  const canonicalUri = '/' + env.R2_BUCKET + '/' +
    path.split('/').map(encodeRfc3986).join('/');

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
    'X-Amz-Credential': env.R2_ACCESS_KEY_ID + '/' + credentialScope,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': signedHeaders
  };

  const canonicalQuery = Object.keys(queryParams)
    .sort()
    .map(function(k){ return encodeRfc3986(k) + '=' + encodeRfc3986(queryParams[k]); })
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
    await sha256Hex(canonicalRequest)
  ].join('\n');

  const signingKey = await getSignatureKey(env.R2_SECRET_ACCESS_KEY, dateStamp, region, service);
  const sigBytes = await hmacSha256(signingKey, _enc.encode(stringToSign));
  const signature = Array.from(sigBytes)
    .map(function(b){ return b.toString(16).padStart(2, '0'); })
    .join('');

  return 'https://' + host + canonicalUri + '?' + canonicalQuery +
    '&X-Amz-Signature=' + signature;
}

/* ---- Auth (same logic, Web Fetch API) ---- */
async function verifyUser(authHeader, env) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  const r = await fetch(SUPABASE_URL + '/auth/v1/user', {
    headers: {
      'apikey': env.SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + token
    }
  });
  if (!r.ok) return null;
  const user = await r.json().catch(function(){ return null; });
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

async function findReference(table, urlColumn, fullUrl, excludeId, bearerToken, env) {
  try {
    const params = new URLSearchParams();
    params.set('select', 'id');
    params.set(urlColumn, 'eq.' + fullUrl);
    if (excludeId) params.set('id', 'neq.' + excludeId);
    params.set('limit', '1');

    const r = await fetch(SUPABASE_URL + '/rest/v1/' + table + '?' + params.toString(), {
      headers: {
        'apikey': env.SUPABASE_ANON_KEY,
        'Authorization': 'Bearer ' + bearerToken
      }
    });
    if (!r.ok) return true;
    const data = await r.json().catch(function(){ return []; });
    return Array.isArray(data) && data.length > 0;
  } catch (e) {
    return true;
  }
}

async function isReferenced(fullUrl, excludeId, bearerToken, env) {
  const checks = await Promise.all([
    findReference('posts',    'media_url', fullUrl, excludeId, bearerToken, env),
    findReference('sparks',   'video_url', fullUrl, excludeId, bearerToken, env),
    findReference('statuses', 'media_url', fullUrl, null,      bearerToken, env),
    findReference('ads',      'media_url', fullUrl, null,      bearerToken, env)
  ]);
  return checks.some(function (v) { return v; });
}

/* ---- JSON response helper (replaces res.status().json()) ---- */
function jsonResponse(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

/* ---- Main entry point ---- */
export async function onRequest(context) {
  try {
    const { request, env } = context;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    if (!env.R2_ACCOUNT_ID || !env.R2_ACCESS_KEY_ID ||
        !env.R2_SECRET_ACCESS_KEY || !env.R2_BUCKET) {
      return jsonResponse({ error: 'Server not configured (R2 env vars missing)' }, 500);
    }
    if (!env.SUPABASE_ANON_KEY) {
      return jsonResponse({ error: 'Server not configured (SUPABASE_ANON_KEY missing)' }, 500);
    }

    const authHeader = request.headers.get('Authorization');
    const user = await verifyUser(authHeader, env);
    if (!user) {
      return jsonResponse({ error: 'Not authenticated' }, 401);
    }

    let body;
    try { body = await request.json(); }
    catch (e) { return jsonResponse({ error: 'Invalid JSON body' }, 400); }

    const action = body.action;
    const path = body.path;

    if (!action || !path || typeof path !== 'string') {
      return jsonResponse({ error: 'Missing action or path' }, 400);
    }
    if (path.length > MAX_PATH_LENGTH) {
      return jsonResponse({ error: 'Path too long' }, 400);
    }
    if (path.indexOf('..') !== -1 || path.startsWith('/')) {
      return jsonResponse({ error: 'Invalid path' }, 400);
    }
    if (!path.startsWith(user.id + '/')) {
      return jsonResponse({ error: 'Path must be under your user folder' }, 403);
    }
    if (action !== 'put' && action !== 'delete') {
      return jsonResponse({ error: 'Invalid action' }, 400);
    }

    if (action === 'put') {
      const ext = extFromPath(path);
      if (!ext || ALLOWED_EXTENSIONS.indexOf(ext) === -1) {
        return jsonResponse({
          error: 'Unsupported file extension',
          allowed: ALLOWED_EXTENSIONS
        }, 400);
      }

      let contentType = (body.contentType || '').toString().trim().toLowerCase();
      if (!contentType) contentType = DEFAULT_MIME_BY_EXT[ext] || '';
      if (ALLOWED_CONTENT_TYPES.indexOf(contentType) === -1) {
        return jsonResponse({
          error: 'Unsupported content-type',
          allowed: ALLOWED_CONTENT_TYPES
        }, 400);
      }

      const compatible = MIME_BY_EXT[ext] || [];
      if (compatible.indexOf(contentType) === -1) {
        return jsonResponse({
          error: 'Extension does not match content-type',
          extension: ext,
          allowedContentTypesForExtension: compatible
        }, 400);
      }

      const url = await presign('PUT', path, 3600, { 'content-type': contentType }, env);
      return jsonResponse({ url: url, contentType: contentType }, 200);
    }

    /* ---- DELETE ---- */
    const publicBase = env.R2_PUBLIC_BASE ||
      'https://pub-cd1b1d46d6d2450283f494cb457ca83e.r2.dev';
    const fullUrl = publicBase + '/' + path;
    const excludeId = (typeof body.excludeId === 'string' && body.excludeId)
      ? body.excludeId : null;
    const bearerToken = authHeader.slice(7);

    const referenced = await isReferenced(fullUrl, excludeId, bearerToken, env);
    if (referenced) {
      return jsonResponse({ error: 'File still referenced by existing content' }, 409);
    }

    const url = await presign('DELETE', path, 3600, {}, env);
    return jsonResponse({ url: url }, 200);

  } catch (err) {
    return jsonResponse({
      error: 'Server error',
      detail: (err && err.message) ? err.message : 'unknown'
    }, 500);
  }
}
