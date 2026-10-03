function(properties, context) {

const crypto = require('crypto');
const secret = context.keys['Secret'] || '';

// Fail closed: without a configured secret nothing can be valid.
if (!secret) return { valid: false };

const safeEqual = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

// Exact match (default, and what existing workflows without a mode use).
if (properties.mode !== 'HMAC') {
    const valid = safeEqual(Buffer.from(properties.value || '', 'utf8'), Buffer.from(secret, 'utf8'));
    return { valid: valid };
}

// HMAC: Value is the received signature, Payload is the signed content.
const algorithms = { 'sha-256': 'sha256', 'sha-1': 'sha1', 'sha-512': 'sha512' };
const algorithm = algorithms[(properties.algorithm || '').toLowerCase()] || 'sha256';
const encoding = (properties.encoding || '').toLowerCase() === 'base64' ? 'base64' : 'hex';

let signature = (properties.value || '').trim();
const prefix = properties.signature_prefix || '';
if (prefix && signature.startsWith(prefix)) signature = signature.slice(prefix.length);
if (!signature) return { valid: false };

const expected = crypto.createHmac(algorithm, secret).update(properties.payload || '', 'utf8').digest();
const valid = safeEqual(Buffer.from(signature, encoding), expected);
return { valid: valid };

}
