import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const directory = resolve('keys');
mkdirSync(directory, { recursive: true, mode: 0o700 });
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
// Refuse to overwrite existing keys: replacing them changes the trust root.
writeFileSync(resolve(directory, 'private.pem'), privateKey, { mode: 0o600, flag: 'wx' });
writeFileSync(resolve(directory, 'public.pem'), publicKey, { mode: 0o644, flag: 'wx' });
console.log('Created keys/private.pem and keys/public.pem. Upload with wrangler secret put.');
console.log('Local .dev.vars values (keep private):');
console.log(`SIGNING_PRIVATE_KEY=${JSON.stringify(privateKey)}`);
console.log(`SIGNING_PUBLIC_KEY=${JSON.stringify(publicKey)}`);
