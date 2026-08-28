const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const zlib = require('zlib');

// Test implementations directly or compiled
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

test('Ed25519 KeyPair generation and cryptographic signing', () => {
  const kp = generateKeyPair();
  assert.ok(kp.did.startsWith('did:key:z6M'));
  assert.equal(kp.publicKeyHex.length, 64);
  assert.equal(kp.privateKeyHex.length, 64);

  const message = 'Hello DocuTrust Sovereign Identity';
  const sig = signData(message, kp);
  assert.ok(sig.length === 128); // 64 bytes hex = 128 chars

  const isValid = verifySignature(message, sig, kp);
  assert.equal(isValid, true);

  const isTamperedValid = verifySignature(message + ' tampered', sig, kp);
  assert.equal(isTamperedValid, false);
});

test('Canonicalize JSON determinism (RFC 8785)', () => {
  const obj1 = { b: 2, a: 1, c: { y: 20, x: 10 } };
  const obj2 = { a: 1, c: { x: 10, y: 20 }, b: 2 };
  assert.equal(canonicalizeJson(obj1), canonicalizeJson(obj2));
});

test('Merkle Tree root computation and inclusion proof verification', () => {
  const leaves = ['Doc 1', 'Doc 2', 'Doc 3', 'Doc 4', 'Doc 5'];
  const tree = new MerkleTree(leaves);
  const root = tree.getRoot();
  assert.ok(root && root.length === 64);

  for (let i = 0; i < leaves.length; i++) {
    const proof = tree.getProof(i);
    const valid = MerkleTree.verifyProof(leaves[i], proof, root);
    assert.equal(valid, true, `Proof for leaf ${i} should be valid`);

    const invalid = MerkleTree.verifyProof('Tampered doc', proof, root);
    assert.equal(invalid, false, `Proof for tampered leaf ${i} must fail`);
  }
});

test('StatusList2021 Bitstring Revocation compression', () => {
  const byteLength = Math.ceil(1000 / 8);
  const bits = new Uint8Array(byteLength);

  // Revoke index 42 and 99
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
