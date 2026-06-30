function(properties, context) {

const crypto = require('crypto');
const a = Buffer.from(properties.value || '', 'utf8');
const b = Buffer.from(context.keys['Secret'] || '', 'utf8');
const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
return { valid: valid };

}