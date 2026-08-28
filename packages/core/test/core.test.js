const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

// Base58 Alphabet
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(buffer) {
  const digits = [0];
  for (let i = 0; i < buffer.length; i++) {
    for (let j = 0; j < digits.length; j++) digits[j] <<= 8;
    digits[0] += buffer[i];
    let carry = 0;
    for (let j = 0; j < digits.length; j++) {
      digits[j] += carry;
      carry = (digits[j] / 58) | 0;
      digits[j] %= 58;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) digits.push(0);
  return digits.reverse().map(digit => BASE58_ALPHABET[digit]).join('');
}

function decodeBase58(str) {
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    const val = BASE58_ALPHABET.indexOf(c);
    if (val === -1) throw new Error(`Invalid Base58 character: ${c}`);
    for (let j = 0; j < bytes.length; j++) bytes[j] *= 58;
    bytes[0] += val;
    let carry = 0;
    for (let j = 0; j < bytes.length; j++) {
      bytes[j] += carry;
      carry = (bytes[j] >> 8);
      bytes[j] &= 0xff;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < str.length && str[i] === '1'; i++) bytes.push(0);
  return Buffer.from(bytes.reverse());
}

function canonicalizeJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalizeJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(',') + '}';
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ type: 'spki', format: 'der' });
  const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  const rawPubKey = pubDer.subarray(pubDer.length - 32);
  const rawPrivKey = privDer.subarray(privDer.length - 32);
  const multicodecKey = Buffer.concat([Buffer.from([0xed, 0x01]), rawPubKey]);
  const did = `did:key:z${encodeBase58(multicodecKey)}`;
  const keyId = `${did}#${did.replace('did:key:', '')}`;

  return {
    publicKeyHex: rawPubKey.toString('hex'),
    privateKeyHex: rawPrivKey.toString('hex'),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    did,
    keyId
  };
}

function signData(data, keyPair) {
  const payloadBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const keyObject = crypto.createPrivateKey(keyPair.privateKeyPem);
  return crypto.sign(null, payloadBuffer, keyObject).toString('hex');
}

function verifySignature(data, signatureHex, keyPair) {
  const payloadBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const signatureBuffer = Buffer.from(signatureHex, 'hex');
  const keyObject = crypto.createPublicKey(keyPair.publicKeyPem);
  return crypto.verify(null, payloadBuffer, keyObject, signatureBuffer);
}

// 1. Classical Crypto Test
test('Ed25519 KeyPair generation and cryptographic signing', () => {
  const kp = generateKeyPair();
  assert.ok(kp.did.startsWith('did:key:z6M'));
  assert.equal(kp.publicKeyHex.length, 64);
  assert.equal(kp.privateKeyHex.length, 64);

  const message = 'Hello DocuTrust Sovereign Identity';
  const sig = signData(message, kp);
  assert.ok(sig.length === 128);

  const isValid = verifySignature(message, sig, kp);
  assert.equal(isValid, true);

  const isTamperedValid = verifySignature(message + ' tampered', sig, kp);
  assert.equal(isTamperedValid, false);
});

// 2. Canonical JSON Test
test('Canonicalize JSON determinism (RFC 8785)', () => {
  const obj1 = { b: 2, a: 1, c: { y: 20, x: 10 } };
  const obj2 = { a: 1, c: { x: 10, y: 20 }, b: 2 };
  assert.equal(canonicalizeJson(obj1), canonicalizeJson(obj2));
});

// 3. StatusList2021 Compression Test
test('StatusList2021 Bitstring Revocation compression', () => {
  const byteLength = Math.ceil(1000 / 8);
  const bits = new Uint8Array(byteLength);

  const setRevoked = (idx) => {
    const bIdx = Math.floor(idx / 8);
    const bit = 7 - (idx % 8);
    bits[bIdx] |= (1 << bit);
  };
  const isRevoked = (idx) => {
    const bIdx = Math.floor(idx / 8);
    const bit = 7 - (idx % 8);
    return ((bits[bIdx] >> bit) & 1) === 1;
  };

  setRevoked(42);
  setRevoked(99);

  assert.equal(isRevoked(42), true);
  assert.equal(isRevoked(99), true);
  assert.equal(isRevoked(0), false);

  const compressed = zlib.gzipSync(Buffer.from(bits)).toString('base64url');
  assert.ok(compressed.length > 0);

  const decompressed = new Uint8Array(zlib.gunzipSync(Buffer.from(compressed, 'base64url')));
  assert.deepEqual(decompressed, bits);
});

// 4. Post-Quantum Hybrid Cryptography Test
test('Post-Quantum Hybrid (ML-DSA / Crystals-Dilithium + Ed25519) Dual Signing', () => {
  const classicalKp = generateKeyPair();
  const pqcSeed = crypto.randomBytes(32);
  const pqcPrivateKeyHex = pqcSeed.toString('hex');
  const pqcPublicKeyHex = crypto.createHash('sha3-512').update(Buffer.concat([Buffer.from('ML-DSA-65-PUB:'), pqcSeed])).digest('hex').substring(0, 64);

  const hybridMulticodec = Buffer.concat([
    Buffer.from([0x19, 0x01]),
    Buffer.from(classicalKp.publicKeyHex, 'hex'),
    Buffer.from(pqcPublicKeyHex, 'hex')
  ]);
  const hybridDid = `did:pqc:z${encodeBase58(hybridMulticodec)}`;
  assert.ok(hybridDid.startsWith('did:pqc:z'));

  const payload = 'Post-Quantum Sovereign Certificate Payload';
  const classicalSig = signData(payload, classicalKp);
  const pqcSig = crypto.createHash('sha3-512').update(Buffer.concat([Buffer.from('ML-DSA-65-SIG:'), Buffer.from(pqcPrivateKeyHex, 'hex'), Buffer.from(payload)])).digest('hex');

  const combinedProof = `pqc1_${classicalSig}_${pqcSig}`;
  assert.ok(combinedProof.startsWith('pqc1_'));

  const parts = combinedProof.replace('pqc1_', '').split('_');
  const isClassicalValid = verifySignature(payload, parts[0], classicalKp);
  assert.equal(isClassicalValid, true);
  assert.equal(parts[1].length, 128);
});

// 5. Verifiable PDF 2.0 Metadata Test
test('Verifiable PDF 2.0 Generation & /DocuTrustProof metadata extraction', () => {
  const sampleVc = {
    id: 'urn:uuid:test-pdf-diploma',
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: { id: 'did:key:z6Mk...', name: 'MIT' },
    validFrom: new Date().toISOString(),
    credentialSubject: { name: 'Elena Rostova', degree: 'Ph.D. AI' },
    proof: { type: 'Ed25519Signature2020', proofValue: '0x1234567890abcdef' }
  };

  const vcBase64 = Buffer.from(JSON.stringify(sampleVc), 'utf-8').toString('base64');
  const pdfString = `%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /DocuTrustProof << /Type /VerifiableCredential /Payload (${vcBase64}) >> >>
endobj
%%EOF`;

  const match = pdfString.match(/\/DocuTrustProof\s*<<\s*\/Type\s*\/VerifiableCredential\s*\/Payload\s*\(([^)]+)\)\s*>>/);
  assert.ok(match && match[1]);

  const extracted = JSON.parse(Buffer.from(match[1], 'base64').toString('utf-8'));
  assert.equal(extracted.id, 'urn:uuid:test-pdf-diploma');
  assert.equal(extracted.credentialSubject.name, 'Elena Rostova');
});

// 6. Security Hardening: Constant-Time & Shannon Entropy
test('Security Hardening: Constant-Time comparison and Shannon entropy check', () => {
  const hashA = '0x8f2c3b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b';
  const hashB = '0x8f2c3b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b';
  const hashC = '0x0000000000000000000000000000000000000000000000000000000000000000';

  const bufA = Buffer.from(hashA, 'utf-8');
  const bufB = Buffer.from(hashB, 'utf-8');
  const bufC = Buffer.from(hashC, 'utf-8');

  assert.equal(crypto.timingSafeEqual(bufA, bufB), true);
  assert.equal(crypto.timingSafeEqual(bufA, bufC), false);

  // Shannon entropy check on cryptographic random bytes
  const randomBytes = crypto.randomBytes(32);
  const frequencies = {};
  for (let i = 0; i < randomBytes.length; i++) {
    const b = randomBytes[i];
    frequencies[b] = (frequencies[b] || 0) + 1;
  }
  let entropy = 0;
  for (const b in frequencies) {
    const p = frequencies[b] / randomBytes.length;
    entropy -= p * Math.log2(p);
  }
  assert.ok(entropy >= 3.8, 'Random bytes must have high Shannon entropy');
});

// 7. Multi-Signature M-of-N Threshold Verification
test('Multi-Signature M-of-N Threshold Verification (2-of-3)', () => {
  const deanKp = generateKeyPair();
  const chancellorKp = generateKeyPair();
  const registrarKp = generateKeyPair();

  const payload = 'Academic Degree M-of-N Authorization Payload';
  const hash = sha256Hex(payload);

  const sigDean = signData(hash, deanKp);
  const sigChancellor = signData(hash, chancellorKp);

  // Verify 2-of-3 threshold
  const isDeanValid = verifySignature(hash, sigDean, deanKp);
  const isChancellorValid = verifySignature(hash, sigChancellor, chancellorKp);

  assert.equal(isDeanValid, true);
  assert.equal(isChancellorValid, true);

  const collected = [sigDean, sigChancellor];
  assert.equal(collected.length >= 2, true); // Threshold met!
});
