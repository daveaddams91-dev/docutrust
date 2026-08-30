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
    assert.equal(res.body.version, '2.4.0');
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

  await t.test('25. POST /api/v1/credentials/eip712 (Keygen, Sign, Verify)', async () => {
    const keyRes = await makeRequest('POST', '/api/v1/crypto/secp256k1/generate', { chainId: 1 });
    assert.equal(keyRes.status, 200);
    assert.ok(keyRes.body.keyPair.did.startsWith('did:pkh:eip155:1:0x'));
    const ethKeys = keyRes.body.keyPair;

    const unsignedVc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:api-eth-001',
      type: ['VerifiableCredential', 'DegreeCredential'],
      issuer: ethKeys.did,
      credentialSubject: { id: 'did:pkh:eip155:1:0x123', student: 'Vitalik' }
    };

    const signRes = await makeRequest('POST', '/api/v1/credentials/eip712/sign', {
      unsignedVc,
      keyPair: ethKeys
    });
    assert.equal(signRes.status, 200);
    assert.equal(signRes.body.signedVc.proof.type, 'EthereumEip712Signature2026');

    const verifyRes = await makeRequest('POST', '/api/v1/credentials/eip712/verify', {
      credential: signRes.body.signedVc,
      expectedSigner: ethKeys.ethereumAddress
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  await t.test('26. POST /api/v1/recovery/social (Setup, Initiate, Vote, Finalize)', async () => {
    const guardians = [
      { did: 'did:key:zGuard1', name: 'Alice' },
      { did: 'did:key:zGuard2', name: 'Bob' },
      { did: 'did:key:zGuard3', name: 'Charlie' }
    ];
    const setupRes = await makeRequest('POST', '/api/v1/recovery/social/setup', {
      ownerDid: 'did:key:zOwner123',
      secret: 'VaultMasterSecret123',
      guardians,
      threshold: 2,
      challengePeriodHours: 24
    });
    assert.equal(setupRes.status, 200);
    assert.equal(setupRes.body.guardians.length, 3);
    const shares = setupRes.body.rawShares;

    const initRes = await makeRequest('POST', '/api/v1/recovery/social/initiate', {
      ownerDid: 'did:key:zOwner123',
      requesterDid: 'did:key:zReq999',
      config: setupRes.body.config
    });
    assert.equal(initRes.status, 200);
    let session = initRes.body.session;

    const vote1 = await makeRequest('POST', '/api/v1/recovery/social/vote', {
      session,
      guardianDid: guardians[0].did,
      shareIndex: shares[0].index,
      rawShareHex: shares[0].shareHex
    });
    assert.equal(vote1.status, 200);
    session = vote1.body.session;

    const vote2 = await makeRequest('POST', '/api/v1/recovery/social/vote', {
      session,
      guardianDid: guardians[1].did,
      shareIndex: shares[1].index,
      rawShareHex: shares[1].shareHex
    });
    assert.equal(vote2.status, 200);
    session = vote2.body.session;

    const finalizeRes = await makeRequest('POST', '/api/v1/recovery/social/finalize', {
      session,
      forceTimelockOverride: true
    });
    assert.equal(finalizeRes.status, 200);
    assert.equal(finalizeRes.body.status, 'SUCCESS');
    assert.equal(finalizeRes.body.reconstructedSecret, 'VaultMasterSecret123');
  });

  await t.test('27. POST /api/v1/zk (Non-membership & Composite Predicates)', async () => {
    const proveNonMem = await makeRequest('POST', '/api/v1/zk/prove-non-membership', {
      claimKey: 'passportId',
      secretValue: 'US-991238',
      salt: '11223344556677881122334455667788',
      restrictedSet: ['SANCTIONED-01', 'SANCTIONED-02']
    });
    assert.equal(proveNonMem.status, 200);
    assert.equal(proveNonMem.body.proof.type, 'ZKSetNonMembershipProof2026');

    const verifyNonMem = await makeRequest('POST', '/api/v1/zk/verify-non-membership', {
      proof: proveNonMem.body.proof,
      restrictedSet: ['SANCTIONED-01', 'SANCTIONED-02']
    });
    assert.equal(verifyNonMem.status, 200);
    assert.equal(verifyNonMem.body.valid, true);

    const compProve = await makeRequest('POST', '/api/v1/zk/prove-composite', {
      proofs: [proveNonMem.body.proof]
    });
    assert.equal(compProve.status, 200);
    assert.equal(compProve.body.compositeProof.type, 'ZKCompositePredicateProof2026');

    const compVerify = await makeRequest('POST', '/api/v1/zk/verify-composite', {
      compositeProof: compProve.body.compositeProof,
      context: { restrictedSets: { passportId: ['SANCTIONED-01', 'SANCTIONED-02'] } }
    });
    assert.equal(compVerify.status, 200);
    assert.equal(compVerify.body.valid, true);
  });

  await t.test('28. POST /api/v1/ledger/multichain/anchor', async () => {
    const anchorRes = await makeRequest('POST', '/api/v1/ledger/multichain/anchor', {
      chain: 'ethereum',
      merkleRoot: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      batchCount: 250
    });
    assert.equal(anchorRes.status, 200);
    assert.equal(anchorRes.body.success, true);
    assert.ok(anchorRes.body.anchor.calldataHex.startsWith('0x892a4b12'));
  });

  await t.test('29. POST /api/v1/schema endpoints (validate, validate-credential, hash)', async () => {
    const schema = {
      $id: 'https://schema.docutrust.org/diploma.json',
      type: 'object',
      required: ['studentId', 'gpa'],
      properties: {
        studentId: { type: 'string', pattern: '^STU-\\d{4}$' },
        gpa: { type: 'number', minimum: 0.0, maximum: 4.0 }
      },
      additionalProperties: false
    };

    // 1. Compute hash
    const hashRes = await makeRequest('POST', '/api/v1/schema/hash', { schema });
    assert.equal(hashRes.status, 200);
    assert.equal(hashRes.body.schemaHash.length, 64);

    // 2. Validate data
    const validRes = await makeRequest('POST', '/api/v1/schema/validate', {
      data: { studentId: 'STU-1234', gpa: 3.8 },
      schema
    });
    assert.equal(validRes.status, 200);
    assert.equal(validRes.body.valid, true);

    const invalidRes = await makeRequest('POST', '/api/v1/schema/validate', {
      data: { studentId: 'INVALID', gpa: 4.5 },
      schema
    });
    assert.equal(invalidRes.status, 200);
    assert.equal(invalidRes.body.valid, false);

    // 3. Validate credential subject
    const credRes = await makeRequest('POST', '/api/v1/schema/validate-credential', {
      credential: {
        id: 'urn:uuid:vc-test',
        credentialSubject: { studentId: 'STU-1234', gpa: 3.8 }
      },
      schema
    });
    assert.equal(credRes.status, 200);
    assert.equal(credRes.body.valid, true);
  });

  await t.test('30. POST /api/v1/accumulator endpoints (create, add, witness, verify, delete)', async () => {
    const accId = 'acc_api_test_01';
    const createRes = await makeRequest('POST', '/api/v1/accumulator/create', { id: accId });
    assert.equal(createRes.status, 200);
    assert.equal(createRes.body.state.id, accId);

    const member1 = 'did:key:z6MkuMember1';
    const member2 = 'did:key:z6MkuMember2';

    // Add batch
    const addRes = await makeRequest('POST', '/api/v1/accumulator/add', {
      id: accId,
      elements: [member1, member2]
    });
    assert.equal(addRes.status, 200);
    assert.equal(addRes.body.addedCount, 2);

    // Create witness
    const witRes = await makeRequest('POST', '/api/v1/accumulator/witness', {
      id: accId,
      element: member1
    });
    assert.equal(witRes.status, 200);
    assert.equal(witRes.body.witness.element, member1);

    // Verify witness
    const verRes = await makeRequest('POST', '/api/v1/accumulator/verify-witness', {
      witness: witRes.body.witness,
      currentAccumulatorHex: addRes.body.state.accumulator
    });
    assert.equal(verRes.status, 200);
    assert.equal(verRes.body.valid, true);

    // Delete member1
    const delRes = await makeRequest('POST', '/api/v1/accumulator/delete', {
      id: accId,
      element: member1
    });
    assert.equal(delRes.status, 200);

    // Old witness should now be invalid against new accumulator state
    const verAfterDel = await makeRequest('POST', '/api/v1/accumulator/verify-witness', {
      witness: witRes.body.witness,
      currentAccumulatorHex: delRes.body.state.accumulator
    });
    assert.equal(verAfterDel.status, 200);
    assert.equal(verAfterDel.body.valid, false);
  });

  await t.test('31. POST /api/v1/jwe endpoints (generate-keys, encrypt, decrypt)', async () => {
    const k1Res = await makeRequest('POST', '/api/v1/jwe/generate-keys');
    const k2Res = await makeRequest('POST', '/api/v1/jwe/generate-keys');
    assert.equal(k1Res.status, 200);
    assert.equal(k2Res.status, 200);

    const payload = { confidentialKey: 'SECRET-9988', classification: 'RESTRICTED' };
    const recipients = [
      { did: k1Res.body.keyPair.did, publicKey: k1Res.body.keyPair.publicKeyHex },
      { did: k2Res.body.keyPair.did, publicKey: k2Res.body.keyPair.publicKeyHex }
    ];

    const encRes = await makeRequest('POST', '/api/v1/jwe/encrypt', { payload, recipients });
    assert.equal(encRes.status, 200);
    assert.equal(encRes.body.jwe.recipients.length, 2);

    const dec1Res = await makeRequest('POST', '/api/v1/jwe/decrypt', {
      jwe: encRes.body.jwe,
      recipientDid: k1Res.body.keyPair.did,
      recipientPrivateKey: k1Res.body.keyPair.privateKeyHex
    });
    assert.equal(dec1Res.status, 200);
    assert.deepEqual(dec1Res.body.parsedJson, payload);
  });

  await t.test('32. POST /api/v1/zk (Set Intersection)', async () => {
    const recognized = ['ROLE-ADMIN', 'ROLE-AUDITOR', 'ROLE-EXECUTIVE'];
    const proveRes = await makeRequest('POST', '/api/v1/zk/prove-intersection', {
      claimKey: 'role',
      secretValue: 'ROLE-AUDITOR',
      salt: '11223344556677881122334455667788',
      targetSet: recognized
    });
    assert.equal(proveRes.status, 200);
    assert.equal(proveRes.body.proof.type, 'ZKSetIntersectionProof2026');

    const verifyRes = await makeRequest('POST', '/api/v1/zk/verify-intersection', {
      proof: proveRes.body.proof,
      targetSet: recognized
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  await t.test('33. POST /api/v1/accumulator (Non-Membership Witness & Verify)', async () => {
    const accId = 'acc_api_non_member_test';
    await makeRequest('POST', '/api/v1/accumulator/create', { id: accId });
    const addRes = await makeRequest('POST', '/api/v1/accumulator/add', {
      id: accId,
      elements: ['user_alpha_1', 'user_beta_2']
    });
    assert.equal(addRes.status, 200);

    const nonMember = 'user_gamma_3';
    const nonMemRes = await makeRequest('POST', '/api/v1/accumulator/non-membership-witness', {
      id: accId,
      element: nonMember
    });
    assert.equal(nonMemRes.status, 200);
    assert.equal(nonMemRes.body.witness.element, nonMember);

    const verifyRes = await makeRequest('POST', '/api/v1/accumulator/verify-non-membership', {
      witness: nonMemRes.body.witness,
      currentAccumulatorHex: addRes.body.state.accumulator,
      generatorHex: addRes.body.state.generator,
      modulusHex: addRes.body.state.modulus
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  await t.test('34. POST /api/v1/statuslist2024 endpoints (create, check, update)', async () => {
    const createRes = await makeRequest('POST', '/api/v1/statuslist2024/create', {
      length: 1000,
      statusSize: 2,
      statusPurpose: 'revocation',
      id: 'https://api.docutrust.org/status/2024-01',
      issuerDid: 'did:key:z6MkuMockIssuer'
    });
    assert.equal(createRes.status, 200);
    assert.ok(createRes.body.encodedList.startsWith('u'));
    assert.equal(createRes.body.statusSize, 2);

    // Initial check (index 10 is Valid: 0)
    const checkRes = await makeRequest('POST', '/api/v1/statuslist2024/check', {
      encodedList: createRes.body.encodedList,
      index: 10,
      length: 1000,
      statusSize: 2
    });
    assert.equal(checkRes.status, 200);
    assert.equal(checkRes.body.valid, true);
    assert.equal(checkRes.body.revoked, false);

    // Update index 10 to Revoked (1)
    const updateRes = await makeRequest('POST', '/api/v1/statuslist2024/update', {
      encodedList: createRes.body.encodedList,
      index: 10,
      status: 1,
      length: 1000,
      statusSize: 2
    });
    assert.equal(updateRes.status, 200);

    // Check again
    const checkAfterUpdate = await makeRequest('POST', '/api/v1/statuslist2024/check', {
      encodedList: updateRes.body.encodedList,
      index: 10,
      length: 1000,
      statusSize: 2
    });
    assert.equal(checkAfterUpdate.status, 200);
    assert.equal(checkAfterUpdate.body.valid, false);
    assert.equal(checkAfterUpdate.body.revoked, true);
  });

  await t.test('35. POST /api/v1/pe endpoints (definition, submission, evaluate)', async () => {
    const defRes = await makeRequest('POST', '/api/v1/pe/definition/create', {
      id: 'kyc_income_def',
      inputDescriptors: [
        {
          id: 'income_descriptor',
          schema: [{ uri: 'IncomeVerificationCredential' }],
          constraints: {
            fields: [
              { path: ['$.credentialSubject.annualIncome'], filter: { type: 'number', minimum: 50000 } }
            ]
          }
        }
      ]
    });
    assert.equal(defRes.status, 200);
    assert.equal(defRes.body.definition.id, 'kyc_income_def');

    const subRes = await makeRequest('POST', '/api/v1/pe/submission/create', {
      definitionId: 'kyc_income_def',
      descriptorMap: [
        { id: 'income_descriptor', format: 'ldp_vc', path: '$.verifiableCredential[0]' }
      ]
    });
    assert.equal(subRes.status, 200);

    const presentation = {
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        {
          type: ['VerifiableCredential', 'IncomeVerificationCredential'],
          credentialSubject: { annualIncome: 95000 }
        }
      ]
    };

    const evalRes = await makeRequest('POST', '/api/v1/pe/evaluate', {
      presentation,
      definition: defRes.body.definition,
      submission: subRes.body.submission
    });
    assert.equal(evalRes.status, 200);
    assert.equal(evalRes.body.result.valid, true);
    assert.equal(evalRes.body.result.matchedDescriptors.length, 1);
  });

  await t.test('36. POST /api/v1/zk/prove-graph and /verify-graph', async () => {
    const proveAge = await makeRequest('POST', '/api/v1/credentials/zk-predicate/prove-age', {
      claimKey: 'dob',
      birthDate: '1995-06-20',
      minAgeYears: 18
    });
    assert.equal(proveAge.status, 200);

    const root = {
      id: 'kyc_graph_root',
      operator: 'AND',
      children: [
        { id: 'leaf_age', proof: proveAge.body.proof }
      ]
    };

    const graphRes = await makeRequest('POST', '/api/v1/zk/prove-graph', {
      graphId: 'kyc_composite_graph_01',
      root
    });
    assert.equal(graphRes.status, 200);
    assert.equal(graphRes.body.proof.type, 'ZKPredicateGraphProof2026');

    const verifyRes = await makeRequest('POST', '/api/v1/zk/verify-graph', {
      graphProof: graphRes.body.proof
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.result.valid, true);
  });
});

