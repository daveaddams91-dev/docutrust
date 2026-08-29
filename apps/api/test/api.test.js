const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { server } = require('../src/server.js');

let baseUrl;
let serverInstance;

function makeRequest(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json;
        try {
          json = data ? JSON.parse(data) : {};
        } catch (e) {
          json = data;
        }
        resolve({ status: res.statusCode, headers: res.headers, body: json });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

test('API Server Suite', async (t) => {
  // Start server on random available port
  await new Promise((resolve) => {
    serverInstance = server.listen(0, () => {
      const port = serverInstance.address().port;
      baseUrl = `http://localhost:${port}`;
      resolve();
    });
  });

  t.after(() => {
    if (serverInstance) serverInstance.close();
  });

  await t.test('1. GET /api/v1/health returns system info and features', async () => {
    const res = await makeRequest('GET', '/api/v1/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'healthy');
    assert.equal(res.body.version, '2.1.0');
    assert.ok(Array.isArray(res.body.features));
    assert.ok(res.body.systemDid.startsWith('did:key:z6M'));
  });

  let classicalKeys;
  await t.test('2. POST /api/v1/keys/generate creates Ed25519 keypair', async () => {
    const res = await makeRequest('POST', '/api/v1/keys/generate');
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.keyPair.did.startsWith('did:key:z6M'));
    assert.equal(res.body.keyPair.publicKeyHex.length, 64);
    classicalKeys = res.body.keyPair;
  });

  let pqcKeys;
  await t.test('3. POST /api/v1/keys/generate-pqc creates ML-DSA Hybrid keypair', async () => {
    const res = await makeRequest('POST', '/api/v1/keys/generate-pqc');
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.pqcKeyPair.hybridDid.startsWith('did:pqc:z'));
    assert.equal(res.body.pqcKeyPair.algorithm, 'ML-DSA-65-Ed25519-Hybrid');
    pqcKeys = res.body.pqcKeyPair;
  });

  let issuedCredential;
  await t.test('4. POST /api/v1/credentials/issue issues a signed W3C VC', async () => {
    const payload = {
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      issuerName: 'Stanford University',
      keyPair: classicalKeys,
      credentialSubject: {
        name: 'Elena Rostova',
        title: 'Ph.D. in Artificial Intelligence',
        gpa: '3.98'
      }
    };
    const res = await makeRequest('POST', '/api/v1/credentials/issue', payload);
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.credential.id.startsWith('urn:uuid:'));
    assert.equal(res.body.credential.proof.type, 'Ed25519Signature2020');
    issuedCredential = res.body.credential;
  });

  await t.test('5. POST /api/v1/credentials/verify verifies issued VC', async () => {
    const res = await makeRequest('POST', '/api/v1/credentials/verify', { credential: issuedCredential });
    assert.equal(res.status, 200);
    assert.equal(res.body.valid, true);
    assert.equal(res.body.signatureValid, true);

    // Tampered verification fails
    const tampered = JSON.parse(JSON.stringify(issuedCredential));
    tampered.credentialSubject.name = 'Mallory';
    const tamperedRes = await makeRequest('POST', '/api/v1/credentials/verify', { credential: tampered });
    assert.equal(tamperedRes.status, 200);
    assert.equal(tamperedRes.body.valid, false);
  });

  let batchCredentials;
  await t.test('6. POST /api/v1/credentials/issue-batch issues batch with Merkle tree', async () => {
    const records = [
      { credentialSubject: { name: 'Student A', degree: 'B.Sc.' } },
      { credentialSubject: { name: 'Student B', degree: 'M.Sc.' } }
    ];
    const res = await makeRequest('POST', '/api/v1/credentials/issue-batch', {
      records,
      keyPair: classicalKeys,
      anchorToLedger: true
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.totalIssued, 2);
    assert.ok(res.body.merkleRoot.length === 64);
    assert.ok(res.body.anchorReceipt.confirmed);
    batchCredentials = res.body.credentials;
  });

  await t.test('7. POST /api/v1/credentials/selective-disclosure generates salted presentation', async () => {
    const res = await makeRequest('POST', '/api/v1/credentials/selective-disclosure', {
      credential: issuedCredential,
      revealKeys: ['name', 'title']
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.claimsRoot.length === 64);
    assert.equal(res.body.disclosedClaims.length, 2);
  });

  await t.test('8. POST /api/v1/credentials/render-pdf & verify-pdf', async () => {
    const pdfRes = await makeRequest('POST', '/api/v1/credentials/render-pdf', { credential: issuedCredential });
    assert.equal(pdfRes.status, 200);
    assert.ok(pdfRes.headers['content-type'].includes('application/pdf'));

    const pdfBase64 = Buffer.from(pdfRes.body).toString('base64');
    const verifyRes = await makeRequest('POST', '/api/v1/credentials/verify-pdf', { pdfBase64 });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
    assert.equal(verifyRes.body.recipientName, 'Elena Rostova');
  });

  await t.test('9. GET /api/v1/vault/credentials & /metrics & auto-anchor', async () => {
    const credsRes = await makeRequest('GET', '/api/v1/vault/credentials?q=Elena');
    assert.equal(credsRes.status, 200);
    assert.ok(credsRes.body.total >= 1);

    const metricsRes = await makeRequest('GET', '/api/v1/vault/metrics');
    assert.equal(metricsRes.status, 200);
    assert.ok(metricsRes.body.totalCredentials >= 1);

    const anchorRes = await makeRequest('POST', '/api/v1/vault/auto-anchor');
    assert.equal(anchorRes.status, 200);
  });

  let encryptedPayload;
  await t.test('10. POST /api/v1/vault/encrypt & /decrypt (Envelope Encryption)', async () => {
    const encRes = await makeRequest('POST', '/api/v1/vault/encrypt', {
      data: { secret: 'Fortress Vault Top Secret 2026' },
      passphrase: 'VaultPassword123!'
    });
    assert.equal(encRes.status, 200);
    assert.equal(encRes.body.success, true);
    assert.equal(encRes.body.encrypted.algorithm, 'AES-256-GCM');
    encryptedPayload = encRes.body.encrypted;

    const decRes = await makeRequest('POST', '/api/v1/vault/decrypt', {
      encrypted: encryptedPayload,
      passphrase: 'VaultPassword123!'
    });
    assert.equal(decRes.status, 200);
    assert.equal(decRes.body.success, true);
    assert.equal(decRes.body.decrypted.secret, 'Fortress Vault Top Secret 2026');
  });

  let zkRangeProof;
  await t.test('11. POST /api/v1/credentials/zk-predicate/prove & /verify', async () => {
    const proveRes = await makeRequest('POST', '/api/v1/credentials/zk-predicate/prove', {
      predicateType: 'range',
      claimKey: 'gpa',
      actualValue: 3.95,
      min: 3.5,
      max: 4.0
    });
    assert.equal(proveRes.status, 200);
    assert.equal(proveRes.body.success, true);
    zkRangeProof = proveRes.body.proof;

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/zk-predicate/verify', {
      proof: zkRangeProof
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  let kemKeys, encapsulation;
  await t.test('12. POST /api/v1/kem/generate-keys, /encapsulate, & /decapsulate', async () => {
    const keyRes = await makeRequest('POST', '/api/v1/kem/generate-keys');
    assert.equal(keyRes.status, 200);
    assert.ok(keyRes.body.keys.hybridRecipientId.startsWith('did:kem:z'));
    kemKeys = keyRes.body.keys;

    const encRes = await makeRequest('POST', '/api/v1/kem/encapsulate', {
      recipientPublicKey: kemKeys
    });
    assert.equal(encRes.status, 200);
    assert.ok(encRes.body.sharedSecretHex.length === 64);
    encapsulation = encRes.body.encapsulation;

    const decRes = await makeRequest('POST', '/api/v1/kem/decapsulate', {
      encapsulation,
      recipientKeys: kemKeys
    });
    assert.equal(decRes.status, 200);
    assert.equal(decRes.body.sharedSecretHex, encRes.body.sharedSecretHex);
  });

  await t.test('13. POST /api/v1/credentials/pop/challenge & /verify', async () => {
    const chalRes = await makeRequest('POST', '/api/v1/credentials/pop/challenge', {
      audience: 'did:web:employer.com'
    });
    assert.equal(chalRes.status, 200);
    assert.ok(chalRes.body.challenge.challengeId.startsWith('pop_'));

    // Create holder presentation using core protocol
    const { ProofOfPossessionProtocol } = require('@docutrust/core');
    const presentation = ProofOfPossessionProtocol.createPresentation(issuedCredential, chalRes.body.challenge, classicalKeys);

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/pop/verify', {
      presentation,
      expectedAudience: 'did:web:employer.com'
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
    assert.equal(verifyRes.body.holderPossessionValid, true);
  });

  await t.test('14. GET /api/v1/ledger/hashchain', async () => {
    const chainRes = await makeRequest('GET', '/api/v1/ledger/hashchain');
    assert.equal(chainRes.status, 200);
    assert.equal(chainRes.body.success, true);
    assert.equal(chainRes.body.integrity.valid, true);
  });

  let shamirShares;
  await t.test('15. POST /api/v1/keys/shamir/split & /combine', async () => {
    const splitRes = await makeRequest('POST', '/api/v1/keys/shamir/split', {
      secret: 'super-root-recovery-key-2026',
      totalShares: 5,
      threshold: 3
    });
    assert.equal(splitRes.status, 200);
    assert.equal(splitRes.body.success, true);
    assert.equal(splitRes.body.shares.length, 5);
    shamirShares = splitRes.body.shares;

    const combineRes = await makeRequest('POST', '/api/v1/keys/shamir/combine', {
      shares: [shamirShares[0], shamirShares[2], shamirShares[4]]
    });
    assert.equal(combineRes.status, 200);
    assert.equal(combineRes.body.success, true);
    assert.equal(combineRes.body.secret, 'super-root-recovery-key-2026');
  });

  let sdPackage;
  await t.test('16. POST /api/v1/credentials/sd-jwt/issue & /verify', async () => {
    const issueRes = await makeRequest('POST', '/api/v1/credentials/sd-jwt/issue', {
      claims: { name: 'Elena', role: 'Security Architect', level: 5 },
      keyPair: classicalKeys
    });
    assert.equal(issueRes.status, 200);
    assert.equal(issueRes.body.success, true);
    sdPackage = issueRes.body.sdPackage;

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/sd-jwt/verify', {
      presentation: sdPackage.combinedSdJwt
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
    assert.equal(verifyRes.body.disclosedClaims.name, 'Elena');
  });

  await t.test('17. POST /api/v1/trust/verify-issuer', async () => {
    const trustRes = await makeRequest('POST', '/api/v1/trust/verify-issuer', {
      issuerDid: 'did:key:zUnknownIssuer999',
      schemaType: 'UniversityDegreeCredential'
    });
    assert.equal(trustRes.status, 200);
    assert.equal(trustRes.body.authorized, false);
  });

  await t.test('18. POST /api/v1/revocation/bloom/create & /check', async () => {
    const createRes = await makeRequest('POST', '/api/v1/revocation/bloom/create', {
      revokedIds: ['urn:uuid:revoked-credential-100', 'urn:uuid:revoked-credential-200']
    });
    assert.equal(createRes.status, 200);
    assert.equal(createRes.body.success, true);
    const signedFilter = createRes.body.signedFilter;

    const checkRevoked = await makeRequest('POST', '/api/v1/revocation/bloom/check', {
      signedFilter,
      credentialId: 'urn:uuid:revoked-credential-100'
    });
    assert.equal(checkRevoked.status, 200);
    assert.equal(checkRevoked.body.isRevoked, true);

    const checkActive = await makeRequest('POST', '/api/v1/revocation/bloom/check', {
      signedFilter,
      credentialId: 'urn:uuid:active-credential-999'
    });
    assert.equal(checkActive.status, 200);
    assert.equal(checkActive.body.isRevoked, false);
  });

  let bbsKeyPair, bbsSignature, bbsProof;
  await t.test('19. POST /api/v1/credentials/bbs (Keygen, Issue, Derive Proof, Verify Proof)', async () => {
    const keyRes = await makeRequest('POST', '/api/v1/credentials/bbs/generate-keys', { maxMessages: 5 });
    assert.equal(keyRes.status, 200);
    assert.ok(keyRes.body.keyPair.did.startsWith('did:bbs:z'));
    bbsKeyPair = keyRes.body.keyPair;

    const messages = ['Elena', 'Stanford', 'Ph.D.', '3.98'];
    const issueRes = await makeRequest('POST', '/api/v1/credentials/bbs/issue', {
      messages,
      keyPair: bbsKeyPair
    });
    assert.equal(issueRes.status, 200);
    assert.equal(issueRes.body.signature.messageCount, 4);
    bbsSignature = issueRes.body.signature;

    const proofRes = await makeRequest('POST', '/api/v1/credentials/bbs/derive-proof', {
      signature: bbsSignature,
      allMessages: messages,
      disclosedIndices: [1, 2],
      keyPair: bbsKeyPair,
      nonce: 'nonce-123'
    });
    assert.equal(proofRes.status, 200);
    assert.deepEqual(proofRes.body.proof.disclosedIndices, [1, 2]);
    bbsProof = proofRes.body.proof;

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/bbs/verify-proof', {
      proof: bbsProof,
      expectedIssuerDid: bbsKeyPair.did
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
    assert.equal(verifyRes.body.disclosedMessages[1], 'Stanford');
  });

  await t.test('20. POST /api/v1/oracle/timestamp & /verify-timestamp', async () => {
    const timeRes = await makeRequest('POST', '/api/v1/oracle/timestamp', {
      data: 'Audit Record For Ledger 2026',
      nonce: 'ts-nonce-001'
    });
    assert.equal(timeRes.status, 200);
    assert.equal(timeRes.body.token.type, 'DocuTrustTimestampToken2026');
    const token = timeRes.body.token;

    const verifyRes = await makeRequest('POST', '/api/v1/oracle/verify-timestamp', {
      token,
      expectedData: 'Audit Record For Ledger 2026'
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  let didcommEnvelope;
  await t.test('21. POST /api/v1/didcomm/pack & /unpack', async () => {
    const packRes = await makeRequest('POST', '/api/v1/didcomm/pack', {
      message: {
        id: 'msg-001',
        type: 'https://docutrust.org/didcomm/ping',
        body: { greeting: 'Zero-Trust Handshake' },
        to: [classicalKeys.did]
      },
      senderKeyPair: classicalKeys,
      recipientPublicKeyHex: classicalKeys.publicKeyHex,
      recipientDid: classicalKeys.did
    });
    assert.equal(packRes.status, 200);
    assert.ok(packRes.body.envelope.ciphertext);
    didcommEnvelope = packRes.body.envelope;

    const unpackRes = await makeRequest('POST', '/api/v1/didcomm/unpack', {
      envelope: didcommEnvelope,
      recipientKeyPair: classicalKeys
    });
    assert.equal(unpackRes.status, 200);
    assert.equal(unpackRes.body.valid, true);
    assert.equal(unpackRes.body.message.body.greeting, 'Zero-Trust Handshake');
  });

  await t.test('22. POST & GET /api/v1/ledger/mmr (Append, Peaks, Proof, Verify)', async () => {
    const appendRes = await makeRequest('POST', '/api/v1/ledger/mmr/append', {
      leaf: 'Ledger MMR Leaf #1'
    });
    assert.equal(appendRes.status, 200);
    assert.ok(appendRes.body.entry.peakRoot);

    const getRes = await makeRequest('GET', '/api/v1/ledger/mmr');
    assert.equal(getRes.status, 200);
    assert.ok(getRes.body.size >= 1);

    const proofRes = await makeRequest('POST', '/api/v1/ledger/mmr/proof', {
      elementIndex: 0
    });
    assert.equal(proofRes.status, 200);
    assert.ok(proofRes.body.proof);

    const verifyRes = await makeRequest('POST', '/api/v1/ledger/mmr/verify', {
      proof: proofRes.body.proof
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  await t.test('23. POST /api/v1/credentials/zk-predicate/prove-age & /verify-age', async () => {
    const proveRes = await makeRequest('POST', '/api/v1/credentials/zk-predicate/prove-age', {
      claimKey: 'birthDate',
      birthDate: '1998-05-20',
      minimumAgeYears: 21,
      referenceDate: '2026-08-29'
    });
    assert.equal(proveRes.status, 200);
    assert.equal(proveRes.body.success, true);
    assert.equal(proveRes.body.proof.type, 'ZKAgePredicateProof2026');

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/zk-predicate/verify-age', {
      proof: proveRes.body.proof
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  await t.test('24. POST /api/v1/credentials/zk-predicate/prove-date & /verify-date', async () => {
    const proveRes = await makeRequest('POST', '/api/v1/credentials/zk-predicate/prove-date', {
      claimKey: 'graduationDate',
      actualDate: '2024-06-15',
      minDate: '2020-01-01',
      maxDate: '2026-12-31'
    });
    assert.equal(proveRes.status, 200);
    assert.equal(proveRes.body.success, true);
    assert.equal(proveRes.body.proof.type, 'ZKDatePredicateProof2026');

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/zk-predicate/verify-date', {
      proof: proveRes.body.proof
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });
});

