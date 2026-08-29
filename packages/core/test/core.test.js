const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  // Crypto
  canonicalizeJson,
  encodeBase58,
  decodeBase58,
  generateKeyPair,
  signData,
  verifySignature,
  sha256Hex,
  // Security
  constantTimeCompare,
  AntiReplayGuard,
  sanitizeJsonPayload,
  calculateShannonEntropy,
  // Merkle
  MerkleTree,
  // Selective Disclosure
  createSelectiveDisclosurePackage,
  generateSelectiveDisclosurePresentation,
  verifySelectiveDisclosurePresentation,
  // PQC
  generatePQCKeyPair,
  signPQCHybrid,
  verifyPQCHybrid,
  // MultiSig
  MultiSigEngine,
  // Revocation
  StatusList2021,
  // DID
  DIDResolver,
  // Ledger
  LocalLedgerAnchor,
  MockEVMAnchor,
  // VC
  VerifiableCredentialsEngine,
  // Templates
  renderCertificateSvg,
  // PDF
  generateVerifiablePdf,
  verifyPdfDocument,
  extractVerifiablePdfProof,
  // DB
  CredentialVault
} = require('../dist/index.js');

// 1. Cryptography Tests
test('1. Cryptography: KeyPair generation, base58 encoding, and Ed25519 signatures', () => {
  const kp = generateKeyPair();
  assert.ok(kp.did.startsWith('did:key:z6M'));
  assert.equal(kp.publicKeyHex.length, 64);
  assert.equal(kp.privateKeyHex.length, 64);

  const message = 'Hello DocuTrust Sovereign Identity';
  const sig = signData(message, kp);
  assert.equal(sig.length, 128);

  const isValid = verifySignature(message, sig, kp);
  assert.equal(isValid, true);

  const isDidValid = verifySignature(message, sig, kp.did);
  assert.equal(isDidValid, true);

  const isTamperedValid = verifySignature(message + ' tampered', sig, kp);
  assert.equal(isTamperedValid, false);
});

test('2. Cryptography: JSON Canonicalization (RFC 8785)', () => {
  const obj1 = { b: 2, a: 1, c: { y: 20, x: 10 } };
  const obj2 = { a: 1, c: { x: 10, y: 20 }, b: 2 };
  assert.equal(canonicalizeJson(obj1), canonicalizeJson(obj2));
  assert.equal(canonicalizeJson(null), 'null');
  assert.equal(canonicalizeJson([3, 1, 2]), '[3,1,2]');
});

// 2. Security Hardening Tests
test('3. Security: Constant-time comparison, replay guard, sanitizer, and Shannon entropy', () => {
  assert.equal(constantTimeCompare('secretHash123', 'secretHash123'), true);
  assert.equal(constantTimeCompare('secretHash123', 'wrongHash4567'), false);

  // AntiReplayGuard
  const nonce = 'nonce_' + Date.now();
  const timestamp = Date.now();
  assert.equal(AntiReplayGuard.validateRequest(nonce, timestamp).valid, true);
  assert.equal(AntiReplayGuard.validateRequest(nonce, timestamp).valid, false); // Replay rejected!
  assert.equal(AntiReplayGuard.validateRequest('nonce_old', Date.now() - 600000).valid, false); // Expired timestamp

  // Prototype pollution sanitizer
  const dirty = { safe: 'yes', __proto__: { admin: true } };
  const clean = sanitizeJsonPayload(dirty);
  assert.equal(clean.safe, 'yes');
  assert.equal(Object.prototype.hasOwnProperty.call(clean, '__proto__'), false);

  // Shannon entropy
  const highEntropy = Buffer.from('4a9b2c8d1e3f7a5b6c0d8e2f4a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b', 'hex');
  assert.ok(calculateShannonEntropy(highEntropy) >= 3.5);
});

// 3. Merkle Tree Tests
test('4. Merkle Tree: RFC 6962 Domain Separation & Audit Paths', () => {
  const leaves = ['cert_1', 'cert_2', 'cert_3', 'cert_4'];
  const tree = new MerkleTree(leaves);
  const root = tree.getRoot();
  assert.equal(root.length, 64);

  for (let i = 0; i < leaves.length; i++) {
    const proof = tree.getProof(i);
    assert.equal(MerkleTree.verifyProof(leaves[i], proof, root), true);
    assert.equal(MerkleTree.verifyProof(leaves[i] + '_tampered', proof, root), false);
  }
});

// 4. Selective Disclosure Tests
test('5. Selective Disclosure: Salted claims and Presentation Verification', () => {
  const claims = {
    name: 'Elena Rostova',
    degree: 'Ph.D. in Artificial Intelligence',
    gpa: '3.98',
    nationalId: '984-21-9901'
  };

  const sdPkg = createSelectiveDisclosurePackage(claims);
  assert.ok(sdPkg.claimsRoot.length === 64);

  // Disclose only name and degree, hiding gpa and nationalId
  const presentation = generateSelectiveDisclosurePresentation(sdPkg, ['name', 'degree']);
  assert.equal(presentation.disclosedClaims.length, 2);
  assert.equal(Object.keys(presentation.hiddenClaimHashes).length, 2);

  const verification = verifySelectiveDisclosurePresentation(presentation, sdPkg.claimsRoot);
  assert.equal(verification.valid, true);
  assert.equal(verification.verifiedClaims.name, 'Elena Rostova');
  assert.equal(verification.verifiedClaims.degree, 'Ph.D. in Artificial Intelligence');
  assert.equal(verification.verifiedClaims.gpa, undefined);
});

// 5. Post-Quantum Hybrid Cryptography Tests
test('6. PQC: NIST ML-DSA + Ed25519 Hybrid Dual Signing and Verification', () => {
  const pqcKeys = generatePQCKeyPair();
  assert.ok(pqcKeys.hybridDid.startsWith('did:pqc:z'));
  assert.equal(pqcKeys.pqcPublicKeyHex.length, 64);

  const data = 'Post-Quantum Sovereign Certificate 2026';
  const hybridSig = signPQCHybrid(data, pqcKeys);
  assert.ok(hybridSig.combinedProofValue.startsWith('pqc1_'));

  const audit = verifyPQCHybrid(data, hybridSig, pqcKeys.classicalKeyPair, pqcKeys.pqcPublicKeyHex);
  assert.equal(audit.valid, true);
  assert.equal(audit.classicalValid, true);
  assert.equal(audit.pqcValid, true);
  assert.equal(audit.isQuantumSafe, true);

  // Verification directly with hybrid DID
  const auditDid = verifyPQCHybrid(data, hybridSig.combinedProofValue, pqcKeys.hybridDid);
  assert.equal(auditDid.valid, true);
});

// 6. Multi-Signature M-of-N Threshold Tests
test('7. MultiSig: M-of-N Threshold Signing and Verification (2-of-3)', () => {
  const deanKp = generateKeyPair();
  const chancellorKp = generateKeyPair();
  const registrarKp = generateKeyPair();

  const signers = [
    { did: deanKp.did, role: 'Dean', publicKeyHex: deanKp.publicKeyHex },
    { did: chancellorKp.did, role: 'Chancellor', publicKeyHex: chancellorKp.publicKeyHex },
    { did: registrarKp.did, role: 'Registrar', publicKeyHex: registrarKp.publicKeyHex }
  ];

  const policy = {
    requiredSignatures: 2,
    totalAuthorizedSigners: 3,
    authorizedSigners: signers
  };

  const unsignedVC = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:multisig-degree-001',
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: { id: 'did:web:harvard.edu', name: 'Harvard University' },
    validFrom: new Date().toISOString(),
    credentialSubject: { name: 'Alex Rivera', degree: 'M.Sc. Computer Science' }
  };

  const { canonicalHash } = MultiSigEngine.createMultiSigDraft(unsignedVC, policy);

  const sigDean = MultiSigEngine.signAsAuthority(canonicalHash, signers[0], deanKp);
  const sigChancellor = MultiSigEngine.signAsAuthority(canonicalHash, signers[1], chancellorKp);

  const multisigVC = MultiSigEngine.assembleMultiSigCredential(unsignedVC, policy, [sigDean, sigChancellor]);
  assert.equal(multisigVC.proof.type, 'MultiSigThresholdSignature2026');

  const audit = MultiSigEngine.verifyMultiSigCredential(multisigVC, policy);
  assert.equal(audit.valid, true);
  assert.equal(audit.verifiedCount, 2);
});

// 7. StatusList2021 Revocation Registry Tests
test('8. Revocation: StatusList2021 Bitstrings & Revocation Checks', () => {
  const statusList = new StatusList2021(10000);
  assert.equal(statusList.isRevoked(42), false);

  statusList.setStatus(42, true);
  statusList.setStatus(99, true);
  assert.equal(statusList.isRevoked(42), true);
  assert.equal(statusList.isRevoked(99), true);
  assert.equal(statusList.isRevoked(100), false);

  const encoded = statusList.encode();
  const restored = StatusList2021.decode(encoded, 10000);
  assert.equal(restored.isRevoked(42), true);
  assert.equal(restored.isRevoked(99), true);
  assert.equal(restored.isRevoked(100), false);
});

// 8. DID Resolution Tests
test('9. DID: Resolver for did:key, did:pqc, and did:web', async () => {
  const kp = generateKeyPair();
  const didDoc = await DIDResolver.resolve(kp.did);
  assert.equal(didDoc.id, kp.did);
  assert.equal(didDoc.verificationMethod[0].type, 'Ed25519VerificationKey2020');

  const pqcKp = generatePQCKeyPair();
  const pqcDoc = await DIDResolver.resolve(pqcKp.hybridDid);
  assert.equal(pqcDoc.id, pqcKp.hybridDid);
  assert.equal(pqcDoc.verificationMethod[0].type, 'ML-DSA-65-Ed25519-Hybrid-2026');

  const webDoc = await DIDResolver.resolve('did:web:stanford.edu');
  assert.equal(webDoc.id, 'did:web:stanford.edu');
});

// 9. Verifiable Credentials Engine (Single & Batch Issuance)
test('10. VC Engine: W3C VC 2.0 Single Issue, Batch Issue, and Verification', async () => {
  const kp = generateKeyPair();

  // 1. Single Issue
  const { credential, selectiveDisclosurePackage } = VerifiableCredentialsEngine.issue({
    type: ['UniversityDegreeCredential'],
    issuer: { id: kp.did, name: 'Stanford University' },
    credentialSubject: { name: 'Alex Rivera', title: 'M.Sc. CS', gpa: '3.98' },
    keyPair: kp,
    enableSelectiveDisclosure: true
  });

  assert.ok(credential.id.startsWith('urn:uuid:'));
  assert.ok(selectiveDisclosurePackage);

  const audit = await VerifiableCredentialsEngine.verify(credential);
  assert.equal(audit.valid, true);
  assert.equal(audit.signatureValid, true);

  // 2. Batch Issue
  const records = [
    { credentialSubject: { name: 'Student 1', degree: 'B.Sc.' } },
    { credentialSubject: { name: 'Student 2', degree: 'M.Sc.' } },
    { credentialSubject: { name: 'Student 3', degree: 'Ph.D.' } }
  ];

  const batch = await VerifiableCredentialsEngine.issueBatch({
    type: ['AcademicDegreeCredential'],
    issuer: { id: kp.did, name: 'MIT' },
    records,
    keyPair: kp,
    anchorToLedger: true
  });

  assert.equal(batch.credentials.length, 3);
  assert.ok(batch.merkleRoot.length === 64);
  assert.ok(batch.anchorReceipt.confirmed);

  for (const c of batch.credentials) {
    const v = await VerifiableCredentialsEngine.verify(c);
    assert.equal(v.valid, true);
    assert.equal(v.merkleProofValid, true);
    assert.equal(v.anchorValid, true);
  }
});

// 10. Templates & Verifiable PDF 2.0
test('11. PDF & Templates: Vector SVG and Verifiable PDF 2.0 with Steganographic Metadata', async () => {
  const kp = generateKeyPair();
  const { credential } = VerifiableCredentialsEngine.issue({
    type: ['UniversityDegreeCredential'],
    issuer: { id: kp.did, name: 'Stanford University' },
    credentialSubject: { name: 'Elena Rostova', title: 'Ph.D. in AI' },
    keyPair: kp
  });

  // SVG Certificate
  const svg = renderCertificateSvg({ credential, theme: 'academic-gold' });
  assert.ok(svg.includes('<svg'));
  assert.ok(svg.includes('Elena Rostova'));

  // PDF 2.0
  const pdfResult = generateVerifiablePdf(credential);
  assert.ok(pdfResult.pdfBuffer.length > 0);

  const extracted = extractVerifiablePdfProof(pdfResult.pdfBuffer);
  assert.equal(extracted.id, credential.id);

  const audit = await verifyPdfDocument(pdfResult.pdfBuffer);
  assert.equal(audit.valid, true);
  assert.equal(audit.isPdfValid, true);
  assert.equal(audit.credential?.credentialSubject?.name, 'Elena Rostova');
});

// 11. Persistent Credential Vault & Worker
test('12. Vault: Storage, Search, API Keys, Metrics, and Auto-Batch Anchoring', async () => {
  const tempDir = path.join(__dirname, '../data/test-vault-' + Date.now());
  const vault = new CredentialVault(tempDir);
  const kp = generateKeyPair();

  const { credential } = VerifiableCredentialsEngine.issue({
    type: ['UniversityDegreeCredential'],
    issuer: { id: kp.did, name: 'Harvard' },
    credentialSubject: { name: 'Marcus Vance', title: 'M.Sc. Robotics' },
    keyPair: kp
  });

  vault.saveCredential(credential);
  const found = vault.getCredential(credential.id);
  assert.ok(found);
  assert.equal(found.recipientName, 'Marcus Vance');

  const searchResults = vault.listCredentials({ search: 'Marcus' });
  assert.equal(searchResults.total, 1);
  assert.equal(searchResults.records[0].recipientName, 'Marcus Vance');

  const apiKey = vault.createApiKey('Workday HR', kp.did);
  assert.ok(apiKey.apiKey.startsWith('dt_live_'));

  const metrics = vault.getMetrics();
  assert.equal(metrics.totalCredentials, 1);
  assert.equal(metrics.totalAnchored, 0);

  // Trigger batch worker
  const anchorReceipt = await vault.executeAutoBatchAnchor();
  assert.ok(anchorReceipt);
  assert.equal(anchorReceipt.leafCount, 1);

  const updatedMetrics = vault.getMetrics();
  assert.equal(updatedMetrics.totalAnchored, 1);

  // Cleanup temp vault directory
  fs.rmSync(tempDir, { recursive: true, force: true });
});
