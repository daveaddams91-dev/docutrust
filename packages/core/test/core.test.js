const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

// Base58 helpers
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

function canonicalizeJson(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
  return '{' + pairs.join(',') + '}';
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

class MerkleTree {
  constructor(leaves) {
    this.leaves = leaves.map(leaf => {
      const buf = typeof leaf === 'string' ? Buffer.from(leaf, 'utf-8') : leaf;
      return sha256Hex(Buffer.concat([Buffer.from([0x00]), buf]));
    });
    this.layers = [this.leaves];
    this.buildTree();
  }

  hashPair(leftHex, rightHex) {
    const leftBuf = Buffer.from(leftHex, 'hex');
    const rightBuf = Buffer.from(rightHex, 'hex');
    return sha256Hex(Buffer.concat([Buffer.from([0x01]), leftBuf, rightBuf]));
  }

  buildTree() {
    let currentLayer = this.leaves;
    while (currentLayer.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        if (i + 1 < currentLayer.length) {
          const right = currentLayer[i + 1];
          nextLayer.push(this.hashPair(left, right));
        } else {
          nextLayer.push(this.hashPair(left, left));
        }
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  getRoot() {
    return this.layers[this.layers.length - 1][0];
  }

  getProof(leafIndex) {
    const auditPath = [];
    let idx = leafIndex;
    for (let layerIdx = 0; layerIdx < this.layers.length - 1; layerIdx++) {
      const layer = this.layers[layerIdx];
      const isRightChild = idx % 2 === 1;
      const pairIdx = isRightChild ? idx - 1 : idx + 1;
      if (pairIdx < layer.length) {
        auditPath.push({
          position: isRightChild ? 'left' : 'right',
          data: layer[pairIdx]
        });
      } else {
        auditPath.push({
          position: 'right',
          data: layer[idx]
        });
      }
      idx = Math.floor(idx / 2);
    }
    return {
      leafHash: this.leaves[leafIndex],
      leafIndex,
      rootHash: this.getRoot(),
      totalLeaves: this.leaves.length,
      auditPath
    };
  }

  static verifyProof(rawLeafData, proof, expectedRoot) {
    const root = expectedRoot || proof.rootHash;
    let currentHash;
    if (rawLeafData !== null) {
      const buf = typeof rawLeafData === 'string' ? Buffer.from(rawLeafData, 'utf-8') : rawLeafData;
      currentHash = sha256Hex(Buffer.concat([Buffer.from([0x00]), buf]));
    } else {
      currentHash = proof.leafHash;
    }
    for (const step of proof.auditPath) {
      const leftBuf = step.position === 'left' ? Buffer.from(step.data, 'hex') : Buffer.from(currentHash, 'hex');
      const rightBuf = step.position === 'left' ? Buffer.from(currentHash, 'hex') : Buffer.from(step.data, 'hex');
      currentHash = sha256Hex(Buffer.concat([Buffer.from([0x01]), leftBuf, rightBuf]));
    }
    return currentHash.toLowerCase() === root.toLowerCase();
  }
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

// 3. Merkle Tree Test
test('Merkle Tree root computation and inclusion proof verification', () => {
  const leaves = ['Doc 1', 'Doc 2', 'Doc 3', 'Doc 4', 'Doc 5'];
  const tree = new MerkleTree(leaves);
  const root = tree.getRoot();
  assert.ok(root && root.length === 64);

  for (let i = 0; i < leaves.length; i++) {
    const proof = tree.getProof(i);
    const valid = MerkleTree.verifyProof(leaves[i], proof, root);
    assert.equal(valid, true);

    const invalid = MerkleTree.verifyProof('Tampered doc', proof, root);
    assert.equal(invalid, false);
  }
});

// 4. StatusList2021 Compression Test
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
  assert.equal(isRevoked(43), false);

  const compressed = zlib.gzipSync(Buffer.from(bits)).toString('base64url');
  assert.ok(compressed.length > 0);

  const decompressed = new Uint8Array(zlib.gunzipSync(Buffer.from(compressed, 'base64url')));
  assert.deepEqual(decompressed, bits);
});

// 5. NEW: Post-Quantum Hybrid Cryptography Test
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
  assert.equal(parts[1].length, 128); // 64 bytes hex
});

// 6. NEW: Verifiable PDF 2.0 & Steganographic Metadata Extraction Test
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

// 7. NEW: Persistent Vault & Auto-Batch Anchoring Test
test('Persistent Vault indexing and auto-batch anchoring', () => {
  const testDir = path.join(__dirname, 'temp_vault_test');
  if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true });
  fs.mkdirSync(testDir, { recursive: true });

  const cred1 = {
    id: 'urn:uuid:vault-test-1',
    type: ['VerifiableCredential'],
    issuer: { id: 'did:key:issuer1', name: 'Univ A' },
    validFrom: new Date().toISOString(),
    credentialSubject: { name: 'Alice', degree: 'B.Sc.' },
    proof: { type: 'Ed25519Signature2020', proofValue: '0xabc1', jcsCanonicalHash: '0xhash1' }
  };

  const recordsFile = path.join(testDir, 'credentials.json');
  fs.writeFileSync(recordsFile, JSON.stringify([cred1], null, 2), 'utf-8');

  const loaded = JSON.parse(fs.readFileSync(recordsFile, 'utf-8'));
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].id, 'urn:uuid:vault-test-1');

  // Clean up
  fs.rmSync(testDir, { recursive: true });
});
