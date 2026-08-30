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
  CredentialVault,
  // Encryption
  encryptAESGCM,
  decryptAESGCM,
  deriveKeyHKDF,
  deriveKeyPBKDF2,
  zeroizeBuffer,
  // ZK Predicates
  proveRange,
  verifyRangeProof,
  proveSetMembership,
  verifySetMembershipProof,
  proveAgeAbove,
  verifyAgeProof,
  proveDateRange,
  verifyDateRangeProof,
  createCommitment,
  // KEM
  generateKEMKeyPair,
  encapsulateSecret,
  decapsulateSecret,
  sealCredentialForRecipient,
  unsealCredential,
  // PoP
  ProofOfPossessionProtocol,
  // HashChain
  TamperEvidentHashChain,
  // Shamir
  splitSecret,
  combineShares,
  // SD-JWT
  issueSDJWT,
  createSDJWTPresentation,
  verifySDJWTPresentation,
  // Trust Registry
  DecentralizedTrustRegistry,
  // Bloom Filter
  RevocationBloomFilter,
  // BBS+
  generateBBSKeyPair,
  signBBS,
  deriveBBSProof,
  verifyBBSProof,
  // Oracle
  CryptographicTSAOracle,
  // DIDComm
  packDIDCommMessage,
  unpackDIDCommMessage,
  // MMR
  MerkleMountainRange,
  // EIP-712
  generateSecp256k1KeyPair,
  signVcEIP712,
  verifyVcEIP712,
  // Social Recovery
  SocialRecoveryEngine,
  // ZK Non-Membership & Composite
  proveSetNonMembership,
  verifySetNonMembershipProof,
  proveCompositePredicate,
  verifyCompositePredicate,
  // MultiChain
  MultiChainLedgerAnchor,
  // Schema Validator
  SchemaValidator,
  // Cryptographic Accumulator
  CryptographicAccumulator,
  // Multi-Recipient JWE
  MultiRecipientJWE,
  // ZK Set Intersection
  proveSetIntersection,
  verifySetIntersectionProof,
  // BitstringStatusList2024
  BitstringStatusList2024,
  // DIF Presentation Exchange v2.0
  PresentationExchangeEngine,
  // Recursive ZK Graph
  provePredicateGraph,
  verifyPredicateGraph,
  // AnonCreds 2.0
  AnonCredsEngine,
  // DKG
  DKGEngine,
  // Solidity EVM Engine
  SolidityEngine,
  // Audit Bundle Engine
  AuditBundleEngine,
  // v6.0.0 / v9.0.0 Modules
  PaillierCryptosystem,
  ConfidentialClaimsEngine,
  JsonLdCanonicalizationEngine,
  TrustChainEngine,
  DualHybridKEMEngine,
  BadgeEngine,
  createDidJwk,
  createDidPeer0,
  createDidPeer2,
  PolicyEngine,
  BitstringStatusListAggregator,
  RingSignatureEngine,
  SparseMerkleTree,
  generateSMTVerifierContract
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

// 12. Fortress Authenticated Envelope Encryption Tests
test('13. Encryption: AES-256-GCM authenticated envelope encryption & tamper resistance', () => {
  const secretData = 'Confidential Diplomatic Credential Payload: Grade A+';
  const passphrase = 'SuperSecretVaultMasterPassphrase2026!';

  const encrypted = encryptAESGCM(secretData, passphrase, true);
  assert.equal(encrypted.algorithm, 'AES-256-GCM');
  assert.equal(encrypted.keyDerivation, 'PBKDF2-SHA512');
  assert.ok(encrypted.ciphertext.length > 0);
  assert.ok(encrypted.authTag.length === 32);

  const decrypted = decryptAESGCM(encrypted, passphrase);
  assert.equal(decrypted.toString('utf-8'), secretData);

  // Tamper test: Alter 1 character of ciphertext
  const tampered = { ...encrypted, ciphertext: encrypted.ciphertext.substring(0, 4) + 'AAAA' + encrypted.ciphertext.substring(8) };
  assert.throws(() => {
    decryptAESGCM(tampered, passphrase);
  }, /Decryption or cryptographic authentication tag verification failed/);

  // Wrong key test
  assert.throws(() => {
    decryptAESGCM(encrypted, 'WrongPassphrase!');
  }, /Decryption or cryptographic authentication tag verification failed/);
});

// 13. Zero-Knowledge Range & Membership Predicates
test('14. ZK Predicates: Zero-Knowledge Range Proofs and Set Membership Verification', () => {
  const actualGPA = 3.92;
  const { commitment, salt } = createCommitment(actualGPA);

  // Prove GPA >= 3.5 and GPA <= 4.0 without revealing 3.92
  const rangeProof = proveRange('gpa', actualGPA, salt, 3.5, 4.0);
  assert.equal(rangeProof.type, 'ZKRangePredicateProof2026');

  const rangeAudit = verifyRangeProof(rangeProof, commitment);
  assert.equal(rangeAudit.valid, true);

  // Fail when actual value outside range
  assert.throws(() => {
    proveRange('gpa', 3.2, salt, 3.5, 4.0);
  }, /outside range/);

  // ZK Set Membership: Prove university is accredited without revealing exact name
  const secretUniversity = 'Stanford University';
  const { commitment: uniCommitment, salt: uniSalt } = createCommitment(secretUniversity);
  const accreditedList = ['MIT', 'Stanford University', 'Harvard University', 'Oxford', 'Cambridge'];

  const memberProof = proveSetMembership('university', secretUniversity, uniSalt, accreditedList);
  assert.equal(memberProof.type, 'ZKSetMembershipProof2026');

  const memberAudit = verifySetMembershipProof(memberProof, accreditedList, uniCommitment);
  assert.equal(memberAudit.valid, true);

  // Verification fails if set changed
  const wrongList = ['MIT', 'Harvard University', 'Oxford'];
  const wrongAudit = verifySetMembershipProof(memberProof, wrongList, uniCommitment);
  assert.equal(wrongAudit.valid, false);
});

// 14. Post-Quantum Key Encapsulation (ML-KEM-768 / Kyber)
test('15. PQC KEM: NIST ML-KEM-768 + X25519 Hybrid Key Encapsulation & Sealed Delivery', () => {
  const recipientKeys = generateKEMKeyPair();
  assert.ok(recipientKeys.hybridRecipientId.startsWith('did:kem:z'));
  assert.equal(recipientKeys.x25519PublicKeyHex.length, 64);
  assert.equal(recipientKeys.publicKeyHex.length, 64);

  // Sender encapsulates secret
  const { sharedSecret: senderSecret, encapsulation } = encapsulateSecret(recipientKeys);
  assert.equal(senderSecret.length, 32);
  assert.ok(encapsulation.ciphertext.includes(':'));

  // Recipient decapsulates secret
  const recipientSecret = decapsulateSecret(encapsulation, recipientKeys);
  assert.equal(recipientSecret.length, 32);
  assert.deepEqual(senderSecret, recipientSecret);

  // End-to-end Quantum-Sealed Credential Delivery
  const confidentialCredential = {
    id: 'urn:uuid:quantum-sealed-vc-001',
    type: ['VerifiableCredential', 'GovernmentSecurityClearance'],
    credentialSubject: { clearanceLevel: 'TOP-SECRET-PQC' }
  };

  const sealed = sealCredentialForRecipient(confidentialCredential, recipientKeys);
  assert.ok(sealed.encryptedPayload.ciphertext.length > 0);

  const unsealed = unsealCredential(sealed, recipientKeys);
  assert.equal(unsealed.id, confidentialCredential.id);
  assert.equal(unsealed.credentialSubject.clearanceLevel, 'TOP-SECRET-PQC');
});

// 15. Proof of Possession Challenge-Response Protocol
test('16. Proof-of-Possession: Dynamic Challenge-Response Holder Binding', async () => {
  const issuerKp = generateKeyPair();
  const holderKp = generateKeyPair();

  const { credential } = VerifiableCredentialsEngine.issue({
    type: ['UniversityDegreeCredential'],
    issuer: { id: issuerKp.did, name: 'MIT' },
    credentialSubject: {
      id: holderKp.did, // Bound to Holder's sovereign DID
      name: 'Alex Rivera',
      degree: 'M.Sc. CS'
    },
    keyPair: issuerKp
  });

  // Verifier creates challenge
  const challenge = ProofOfPossessionProtocol.createChallenge('did:web:employer.com');
  assert.ok(challenge.challengeId.startsWith('pop_'));
  assert.equal(challenge.nonce.length, 64);

  // Holder creates presentation with private key signature
  const presentation = ProofOfPossessionProtocol.createPresentation(credential, challenge, holderKp);
  assert.equal(presentation.holderDid, holderKp.did);
  assert.ok(presentation.holderSignature.length === 128);

  // Verifier confirms both credential and holder ownership
  const audit = await ProofOfPossessionProtocol.verifyPresentation(presentation, 'did:web:employer.com');
  assert.equal(audit.valid, true);
  assert.equal(audit.credentialValid, true);
  assert.equal(audit.holderPossessionValid, true);

  // Thief tries to present stolen credential with thief's key
  const thiefKp = generateKeyPair();
  const thiefPresentation = ProofOfPossessionProtocol.createPresentation(credential, challenge, thiefKp);
  const thiefAudit = await ProofOfPossessionProtocol.verifyPresentation(thiefPresentation, 'did:web:employer.com');
  assert.equal(thiefAudit.valid, false);
  assert.ok(thiefAudit.errors.some(e => e.includes('Holder DID mismatch')));
});

// 16. Tamper-Evident Hash Chain Audit Ledger
test('17. HashChain: Tamper-Evident Forward-Secure Cryptographic Ledger', () => {
  const ledger = new TamperEvidentHashChain();
  const validatorKp = generateKeyPair();

  const signerFn = (hash) => signData(hash, validatorKp);

  const block1 = ledger.appendBlock('0x1111111111111111111111111111111111111111111111111111111111111111', 10, validatorKp.did, signerFn);
  const block2 = ledger.appendBlock('0x2222222222222222222222222222222222222222222222222222222222222222', 25, validatorKp.did, signerFn);
  const block3 = ledger.appendBlock('0x3333333333333333333333333333333333333333333333333333333333333333', 50, validatorKp.did, signerFn);

  assert.equal(ledger.getChain().length, 3);
  assert.equal(block2.previousBlockHash, block1.blockHash);
  assert.equal(block3.previousBlockHash, block2.blockHash);

  const integrity = ledger.verifyChainIntegrity((data, sig, did) => verifySignature(data, sig, did));
  assert.equal(integrity.valid, true);

  // Tamper detection: Modifying block data breaks the hash chain
  block2.leafCount = 999;
  const tamperedAudit = ledger.verifyChainIntegrity();
  assert.equal(tamperedAudit.valid, false);
  assert.equal(tamperedAudit.brokenIndex, 1);
});

// 17. Shamir's Secret Sharing (K-of-N Threshold Key Slicing)
test('18. Shamir: Split secret into 5 shares with threshold 3, and reconstruct from any 3 shares', () => {
  const masterKey = 'ed25519-priv-key-secret-99482710492817492817498172948712';
  const shares = splitSecret(masterKey, 5, 3);
  assert.equal(shares.length, 5);
  assert.equal(shares[0].threshold, 3);
  assert.equal(shares[0].totalShares, 5);

  // Reconstruct with shares [0, 2, 4] (3 shares)
  const reconstructed1 = combineShares([shares[0], shares[2], shares[4]]);
  assert.equal(reconstructed1.toString('utf-8'), masterKey);

  // Reconstruct with shares [1, 3, 4] (different 3 shares)
  const reconstructed2 = combineShares([shares[1], shares[3], shares[4]]);
  assert.equal(reconstructed2.toString('utf-8'), masterKey);

  // Fail if only 2 shares are provided (below threshold 3)
  assert.throws(() => {
    combineShares([shares[0], shares[1]]);
  }, /Insufficient shares/);
});

// 18. IETF SD-JWT Selective Disclosure Verification
test('19. SD-JWT: Issue SD-JWT with salted disclosures, selectively disclose claims, and verify', () => {
  const issuerKp = generateKeyPair();
  const claims = {
    given_name: 'Elena',
    family_name: 'Rostova',
    degree: 'Ph.D. in Computer Science',
    gpa: '3.98',
    national_id: 'US-992-019-338'
  };

  const sdPackage = issueSDJWT(claims, issuerKp, 'did:key:zSubject123');
  assert.ok(sdPackage.issuerJwt.startsWith('eyJ'));
  assert.equal(sdPackage.disclosures.length, 5);
  assert.ok(sdPackage.combinedSdJwt.includes('~'));

  // Holder selectively discloses only given_name and degree (hides GPA and national_id)
  const presentation = createSDJWTPresentation(sdPackage, ['given_name', 'degree']);
  
  const audit = verifySDJWTPresentation(presentation);
  assert.equal(audit.valid, true);
  assert.equal(audit.issuerDid, issuerKp.did);
  assert.equal(audit.disclosedClaims.given_name, 'Elena');
  assert.equal(audit.disclosedClaims.degree, 'Ph.D. in Computer Science');
  assert.equal(audit.disclosedClaims.gpa, undefined);
  assert.equal(audit.disclosedClaims.national_id, undefined);
});

// 19. Decentralized Trust Registry & Issuer Governance
test('20. Trust Registry: Issue authority accreditation and verify schema authorizations', () => {
  const govKp = generateKeyPair();
  const stanfordKp = generateKeyPair();
  const rogueKp = generateKeyPair();

  const registry = new DecentralizedTrustRegistry();

  // Government Authority issues accreditation to Stanford
  const stanfordAccreditation = DecentralizedTrustRegistry.issueAccreditation(
    stanfordKp.did,
    'Stanford University',
    'US-CA',
    ['UniversityDegreeCredential', 'HonoraryDegreeCredential'],
    365,
    'TIER_1_ACCREDITED',
    govKp
  );

  registry.registerAccreditation(stanfordAccreditation);

  // Verify Stanford is authorized to issue UniversityDegreeCredential
  const check1 = registry.verifyIssuerAuthorization(stanfordKp.did, 'UniversityDegreeCredential');
  assert.equal(check1.authorized, true);
  assert.equal(check1.accreditation.issuerName, 'Stanford University');

  // Verify Stanford is NOT authorized to issue MedicalLicenseCredential
  const check2 = registry.verifyIssuerAuthorization(stanfordKp.did, 'MedicalLicenseCredential');
  assert.equal(check2.authorized, false);
  assert.ok(check2.reason.includes('not authorized to issue schema'));

  // Rogue issuer is not registered
  const check3 = registry.verifyIssuerAuthorization(rogueKp.did, 'UniversityDegreeCredential');
  assert.equal(check3.authorized, false);
  assert.ok(check3.reason.includes('not registered'));
});

// 20. Space-Efficient Revocation Bloom Filter
test('21. Bloom Filter: High-speed revocation accumulator with cryptographic signature', () => {
  const issuerKp = generateKeyPair();
  const filter = new RevocationBloomFilter(4096, 5);

  filter.add('urn:uuid:revoked-degree-001');
  filter.add('urn:uuid:revoked-degree-002');
  filter.add('urn:uuid:revoked-license-009');

  const signedFilter = filter.sign(issuerKp);
  assert.equal(signedFilter.type, 'SignedRevocationBloomFilter2026');
  assert.equal(signedFilter.revokedCount, 3);

  // Check revoked credential
  const audit1 = RevocationBloomFilter.verifyAndCheck(signedFilter, 'urn:uuid:revoked-degree-001');
  assert.equal(audit1.signatureValid, true);
  assert.equal(audit1.isRevoked, true);

  // Check valid non-revoked credential
  const audit2 = RevocationBloomFilter.verifyAndCheck(signedFilter, 'urn:uuid:active-degree-888');
  assert.equal(audit2.signatureValid, true);
  assert.equal(audit2.isRevoked, false);
});

// 21. BBS+ Unlinkable Multi-Message Signatures & ZK Proofs
test('22. BBS+: Sign message vector, derive unlinkable ZK proof, and verify', () => {
  const bbsKp = generateBBSKeyPair(5);
  assert.ok(bbsKp.did.startsWith('did:bbs:z'));

  const messages = [
    'Alice Smith',
    'Stanford University',
    'Ph.D. Computer Science',
    'GPA: 3.98',
    'Clearance: TOP_SECRET'
  ];

  const sig = signBBS(messages, bbsKp);
  assert.equal(sig.type, 'BBSPlusSignature2026');
  assert.equal(sig.messageCount, 5);

  // Holder derives unlinkable proof for messages [1, 2] (Stanford, Ph.D.) hiding name, GPA, and Clearance
  const proof = deriveBBSProof(sig, messages, [1, 2], bbsKp, 'verifier-session-nonce-99');
  assert.equal(proof.type, 'BBSPlusZKProof2026');
  assert.deepEqual(proof.disclosedIndices, [1, 2]);

  const audit = verifyBBSProof(proof, bbsKp.did);
  assert.equal(audit.valid, true);
  assert.equal(audit.disclosedMessages[1], 'Stanford University');
  assert.equal(audit.disclosedMessages[2], 'Ph.D. Computer Science');
  assert.equal(audit.disclosedMessages[0], undefined);
  assert.equal(audit.disclosedMessages[3], undefined);

  // Tampering with disclosed messages must fail proof verification
  const tamperedProof = {
    ...proof,
    disclosedMessages: { ...proof.disclosedMessages, 1: 'Harvard University' }
  };
  const tamperedAudit = verifyBBSProof(tamperedProof, bbsKp.did);
  assert.equal(tamperedAudit.valid, false);
});

// 22a. ZK Age & Date Predicates
test('22b. ZK Predicates: Prove Age Above & Date Range without leaking raw dates', () => {
  // Test Age Above Proof (e.g. Born 2000-01-15, proving Age >= 21 relative to 2026-08-29)
  const ageProof = proveAgeAbove('birthDate', '2000-01-15', 21, undefined, '2026-08-29');
  assert.equal(ageProof.type, 'ZKAgePredicateProof2026');
  assert.equal(ageProof.minimumAgeYears, 21);

  const ageAudit = verifyAgeProof(ageProof);
  assert.equal(ageAudit.valid, true);

  // Failure when under required age
  assert.throws(() => {
    proveAgeAbove('birthDate', '2015-01-15', 21, undefined, '2026-08-29');
  }, /Subject does not meet age predicate/);

  // Test Date Range Proof
  const dateProof = proveDateRange('graduationDate', '2024-06-15', '2020-01-01', '2025-12-31');
  assert.equal(dateProof.type, 'ZKDatePredicateProof2026');
  assert.equal(dateProof.minDate, '2020-01-01');
  assert.equal(dateProof.maxDate, '2025-12-31');

  const dateAudit = verifyDateRangeProof(dateProof);
  assert.equal(dateAudit.valid, true);

  // Date outside range throws error
  assert.throws(() => {
    proveDateRange('graduationDate', '2028-06-15', '2020-01-01', '2025-12-31');
  }, /outside range/);
});

// 22. Cryptographic TSA Timestamp Authority & Multi-Oracle Quorum
test('23. Oracle: Issue RFC 3161 timestamp token and verify multi-oracle quorum', () => {
  const tsaKp = generateKeyPair();
  const oracle = new CryptographicTSAOracle(tsaKp);

  const documentData = 'Critical Quantum Verification Ledger Record 2026';
  const token = oracle.issueTimestampToken(documentData, 'client-nonce-001');

  assert.equal(token.type, 'DocuTrustTimestampToken2026');
  assert.equal(token.version, '2.0.0');
  assert.ok(token.unixTimeSeconds > 0);

  const audit = CryptographicTSAOracle.verifyTimestampToken(token, documentData);
  assert.equal(audit.valid, true);
  assert.ok(audit.ageSeconds >= 0);

  // Multi-Oracle Quorum Test
  const oracle1 = generateKeyPair();
  const oracle2 = generateKeyPair();
  const oracle3 = generateKeyPair();

  const quorum = CryptographicTSAOracle.createQuorumAttestation(
    token.targetDataHash,
    [oracle1, oracle2, oracle3],
    2
  );
  assert.equal(quorum.requiredQuorum, 2);

  const quorumAudit = CryptographicTSAOracle.verifyQuorumAttestation(quorum);
  assert.equal(quorumAudit.valid, true);
  assert.equal(quorumAudit.validSignaturesCount, 3);
});

// 23. DIDComm v2 Encrypted Messaging & Peer-to-Peer Agent Tunnel
test('24. DIDComm: Pack authenticated encrypted envelope and unpack by recipient', () => {
  const aliceKp = generateKeyPair();
  const bobKp = generateKeyPair();

  const msg = {
    id: 'msg-uuid-9901',
    type: 'https://docutrust.org/didcomm/credential-offer/v2',
    body: {
      degreeName: 'Master of Science in Cybersecurity',
      issuer: aliceKp.did,
      recipient: bobKp.did
    },
    from: aliceKp.did,
    to: [bobKp.did],
    created_time: Math.floor(Date.now() / 1000)
  };

  const envelope = packDIDCommMessage(msg, aliceKp, bobKp.publicKeyHex, bobKp.did);
  assert.ok(envelope.protected.length > 0);
  assert.ok(envelope.recipients[0].encrypted_key.length > 0);
  assert.ok(envelope.ciphertext.length > 0);

  // Bob unpacks and decrypts the envelope
  const unpacked = unpackDIDCommMessage(envelope, bobKp, aliceKp.did);
  assert.equal(unpacked.valid, true);
  assert.equal(unpacked.senderDid, aliceKp.did);
  assert.equal(unpacked.message.body.degreeName, 'Master of Science in Cybersecurity');
});

// 24. Merkle Mountain Range (MMR) High-Throughput Ledger
test('25. MMR: Streaming append, binary peak decomposition, and peak proof verification', () => {
  const mmr = new MerkleMountainRange();

  const item1 = mmr.append('Audit Log Entry #1: Key Rotation');
  const item2 = mmr.append('Audit Log Entry #2: Credential Issued');
  const item3 = mmr.append('Audit Log Entry #3: Revocation Bit Updated');
  const item4 = mmr.append('Audit Log Entry #4: Oracle TSA Signed');
  const item5 = mmr.append('Audit Log Entry #5: Multi-Sig Threshold Met');

  assert.equal(mmr.size, 5);
  const peaks = mmr.getPeaks();
  assert.ok(peaks.length > 0);

  const proof = mmr.getProof(2);
  assert.equal(proof.elementIndex, 2);
  assert.equal(proof.size, 5);
  assert.ok(proof.siblings.length > 0);

  const isProofValid = MerkleMountainRange.verifyProof(proof);
  assert.equal(isProofValid, true);

  // Tampered element hash should fail verification
  const tamperedProof = { ...proof, elementHash: proof.elementHash.slice(0, -2) + 'ff' };
  assert.equal(MerkleMountainRange.verifyProof(tamperedProof), false);
});

// 25. Security: XML & PDF Escaping Special Character Hardening
test('26. Security: SVG XML and PDF String Escaping for Special Characters', () => {
  const kp = generateKeyPair();
  const { credential: rawVc } = VerifiableCredentialsEngine.issue({
    keyPair: kp,
    issuer: { id: kp.did, name: 'Test Authority & Partners' },
    credentialSubject: {
      id: 'did:key:z6MrecipientSpecial',
      name: 'Alice & Bob <script>alert("xss")</script>',
      title: 'Ph.D. in Computer Science (AI & ML) \\ "Honors"'
    },
    type: ['SpecialCharCredential']
  });

  // Test SVG Escaping
  const svg = renderCertificateSvg({ credential: rawVc });
  assert.ok(svg.includes('Alice &amp; Bob &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'));
  assert.ok(!svg.includes('<script>alert'));

  // Test PDF Escaping
  const pdfResult = generateVerifiablePdf(rawVc);
  const pdfStr = pdfResult.pdfBuffer.toString('utf-8');
  assert.ok(pdfStr.includes('\\(AI & ML\\)'));
  assert.ok(pdfResult.documentHash.length === 64);

  // Verify PDF extraction still works perfectly with escaped chars
  const extracted = extractVerifiablePdfProof(pdfResult.pdfBuffer);
  assert.ok(extracted !== null);
  assert.equal(extracted.credentialSubject.name, 'Alice & Bob <script>alert("xss")</script>');
});

// 26. Cryptography: RFC 8785 Undefined Property Canonicalization and Base58 Edge Cases
test('27. Cryptography: RFC 8785 undefined property omission & Base58 empty buffer', () => {
  // Undefined property omission
  const objWithUndefined = { a: 1, b: undefined, c: 'hello' };
  const objWithoutUndefined = { a: 1, c: 'hello' };
  assert.equal(canonicalizeJson(objWithUndefined), canonicalizeJson(objWithoutUndefined));
  assert.equal(canonicalizeJson(objWithUndefined), '{"a":1,"c":"hello"}');

  // Base58 empty buffer and roundtrip
  assert.equal(encodeBase58(Buffer.alloc(0)), '');
  assert.deepEqual(decodeBase58(''), Buffer.alloc(0));

  const sampleBuf = Buffer.from('DocuTrust-v2.1.0-Sovereign', 'utf-8');
  assert.deepEqual(decodeBase58(encodeBase58(sampleBuf)), sampleBuf);
});

// 27. PDF: ISO 32000-1 Dynamic xref byte offset correctness
test('28. PDF: ISO 32000-1 dynamic xref table byte offset accuracy', () => {
  const kp = generateKeyPair();
  const { credential } = VerifiableCredentialsEngine.issue({
    keyPair: kp,
    issuer: { id: kp.did, name: 'DocuTrust ISO Test Authority' },
    credentialSubject: {
      id: 'did:key:z6Mstudent123',
      name: 'Dynamic Length Recipient Name with Extra Padding To Test Variable Offsets',
      degree: 'Master of Science in Cryptography'
    },
    type: ['DiplomaCredential']
  });

  const pdfResult = generateVerifiablePdf(credential);
  const pdfStr = pdfResult.pdfBuffer.toString('utf-8');

  // Verify xref table format and trailer
  assert.ok(pdfStr.includes('xref\n0 7\n0000000000 65535 f \n'));
  assert.ok(pdfStr.includes('trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n'));

  // Extract startxref offset and verify it points directly to "xref"
  const startXrefMatch = pdfStr.match(/startxref\s+(\d+)\s+%%EOF/);
  assert.ok(startXrefMatch, 'startxref offset exists');
  const startXrefPos = parseInt(startXrefMatch[1], 10);
  const xrefSubstring = pdfResult.pdfBuffer.subarray(startXrefPos, startXrefPos + 4).toString('utf-8');
  assert.equal(xrefSubstring, 'xref');
});

// 28. Verifiable Credentials: MultiSigThresholdSignature2026 Auto-Verification
test('29. Verifiable Credentials: Auto-verification of MultiSigThresholdSignature2026', async () => {
  const dean = generateKeyPair();
  const chancellor = generateKeyPair();
  const registrar = generateKeyPair();

  const policy = {
    requiredSignatures: 2,
    totalAuthorizedSigners: 3,
    authorizedSigners: [
      { did: dean.did, role: 'Dean', publicKeyHex: dean.publicKeyHex },
      { did: chancellor.did, role: 'Chancellor', publicKeyHex: chancellor.publicKeyHex },
      { did: registrar.did, role: 'Registrar', publicKeyHex: registrar.publicKeyHex }
    ]
  };

  const unsigned = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:multisig-vc-001',
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: dean.did,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: 'did:key:z6MstudentX',
      name: 'Student MultiSig Test',
      degree: 'B.Sc. Computer Engineering'
    }
  };

  const { canonicalHash } = MultiSigEngine.createMultiSigDraft(unsigned, policy);
  const sigDean = MultiSigEngine.signAsAuthority(canonicalHash, policy.authorizedSigners[0], dean);
  const sigChancellor = MultiSigEngine.signAsAuthority(canonicalHash, policy.authorizedSigners[1], chancellor);

  const multiSigVc = MultiSigEngine.assembleMultiSigCredential(unsigned, policy, [sigDean, sigChancellor]);
  assert.equal(multiSigVc.proof.type, 'MultiSigThresholdSignature2026');

  // Verify through general VerifiableCredentialsEngine.verify
  const result = await VerifiableCredentialsEngine.verify(multiSigVc);
  assert.equal(result.valid, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.errors.length, 0);
});

// 29. Credential Vault: Atomic persistence and sparse record searching
test('30. DB: CredentialVault atomic persistence and sparse record searching', () => {
  const tempDir = path.join(__dirname, 'vault-test-' + Date.now());
  const vault = new CredentialVault(tempDir);

  const kp = generateKeyPair();
  const { credential } = VerifiableCredentialsEngine.issue({
    keyPair: kp,
    issuer: { id: kp.did, name: 'Vault Org' },
    credentialSubject: { id: 'did:key:z6Mrec', name: 'Vault Recipient' },
    type: ['VaultCredential']
  });

  const record = vault.saveCredential(credential);
  assert.equal(record.id, credential.id);

  // Search by partial name
  const searchRes = vault.listCredentials({ search: 'recipient' });
  assert.equal(searchRes.total, 1);
  assert.equal(searchRes.records[0].recipientName, 'Vault Recipient');

  // Clean up
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// 30. DID: Deterministic resolution for did:kem and did:bbs
test('31. DID: Deterministic DIDResolver resolution for did:kem and did:bbs', async () => {
  // Test did:kem resolution
  const kemKeys = generateKEMKeyPair();
  const kemDoc = await DIDResolver.resolve(kemKeys.hybridRecipientId);
  assert.equal(kemDoc.id, kemKeys.hybridRecipientId);
  assert.equal(kemDoc.verificationMethod[0].type, 'ML-KEM-768-X25519-Hybrid-2026');
  assert.ok(kemDoc.verificationMethod[0].publicKeyMultibase);

  // Test did:bbs resolution
  const bbsKeys = generateBBSKeyPair(5);
  const bbsDoc = await DIDResolver.resolve(bbsKeys.did);
  assert.equal(bbsDoc.id, bbsKeys.did);
  assert.equal(bbsDoc.verificationMethod[0].type, 'BBSPlusVerificationKey2026');
});

// 31. Shamir: Duplicate share index and length validation
test('32. Shamir: Error handling for duplicate share indices and mismatched lengths', () => {
  const secret = 'TopSecretDocuTrustVaultKey';
  const shares = splitSecret(secret, 5, 3);

  // Attempt combine with duplicate shares
  const duplicateShares = [shares[0], shares[0], shares[1]];
  assert.throws(() => {
    combineShares(duplicateShares);
  }, /Duplicate share indices detected/);

  // Attempt combine with corrupted share length
  const corruptedShare = { ...shares[2], shareHex: shares[2].shareHex.slice(0, 10) };
  assert.throws(() => {
    combineShares([shares[0], shares[1], corruptedShare]);
  }, /Mismatched share lengths detected/);
});

// 32. SD-JWT: Standard DID sub claim format and presentation verification
test('33. SD-JWT: Standard W3C did:key subject DID and presentation integrity', () => {
  const kp = generateKeyPair();
  const claims = {
    holderName: 'Alexander Hayes',
    clearanceLevel: 'Top Secret / SCI',
    issueYear: 2026
  };

  const sdPkg = issueSDJWT(claims, kp);
  assert.ok(sdPkg.issuerDid.startsWith('did:key:z6M'));
  
  // Verify presentation
  const pres = createSDJWTPresentation(sdPkg, ['holderName', 'clearanceLevel']);
  const audit = verifySDJWTPresentation(pres);
  assert.equal(audit.valid, true);
  assert.equal(audit.disclosedClaims.holderName, 'Alexander Hayes');
  assert.equal(audit.disclosedClaims.clearanceLevel, 'Top Secret / SCI');
  assert.equal(audit.disclosedClaims.issueYear, undefined);
});

// 33. EIP-712 Ethereum Structured Credential Signing and Verification
test('34. EIP-712: Ethereum secp256k1 key generation, did:pkh resolution, EIP-712 VC signing and verification', async () => {
  const ethKey = generateSecp256k1KeyPair(1);
  assert.ok(ethKey.did.startsWith('did:pkh:eip155:1:0x'));
  assert.ok(ethKey.ethereumAddress.startsWith('0x'));

  // Test DID resolution for did:pkh
  const didDoc = await DIDResolver.resolve(ethKey.did);
  assert.equal(didDoc.id, ethKey.did);
  assert.equal(didDoc.verificationMethod[0].type, 'EcdsaSecp256k1RecoveryMethod2020');

  const unsignedVc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:eth-degree-001',
    type: ['VerifiableCredential', 'EthereumCertifiedDegree'],
    issuer: ethKey.did,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
      studentName: 'Vitalik Buterin',
      honor: 'Doctorate of Sovereign Cryptography'
    }
  };

  const signedVc = signVcEIP712(unsignedVc, ethKey);
  assert.equal(signedVc.proof.type, 'EthereumEip712Signature2026');
  assert.ok(signedVc.proof.signature.startsWith('0x'));

  // Direct EIP-712 verification
  const audit1 = verifyVcEIP712(signedVc);
  assert.equal(audit1.valid, true);
  assert.equal(audit1.signerAddress.toLowerCase(), ethKey.ethereumAddress.toLowerCase());

  // Verification via VerifiableCredentialsEngine.verify()
  const audit2 = await VerifiableCredentialsEngine.verify(signedVc);
  assert.equal(audit2.valid, true);
  assert.equal(audit2.signatureValid, true);
});

// 34. Social Recovery & Timelocked Escrow Protocol
test('35. Social Recovery: Setup, Guardian voting, Timelock expiration, and Owner Veto Protection', () => {
  const rootSecret = '0xfeedfacecafe0102030405060708090a0b0c0d0e0f1011121314151617181920';
  const ownerDid = 'did:key:z6Mowner123';
  const guardians = [
    { did: 'did:key:z6Mguardian1', name: 'Alice (Security Lead)' },
    { did: 'did:key:z6Mguardian2', name: 'Bob (VP Engineering)' },
    { did: 'did:key:z6Mguardian3', name: 'Charlie (Board Member)' },
    { did: 'did:key:z6Mguardian4', name: 'Diana (Legal Counsel)' }
  ];

  // 1. Setup 3-of-4 recovery
  const setup = SocialRecoveryEngine.setupRecovery(ownerDid, rootSecret, guardians, 3, 48);
  assert.equal(setup.guardians.length, 4);
  assert.equal(setup.rawShares.length, 4);
  assert.equal(setup.config.threshold, 3);

  // 2. Initiate recovery session
  let session = SocialRecoveryEngine.initiateRecovery(ownerDid, 'did:key:z6Mrequester', setup.config);
  assert.equal(session.status, 'PENDING_TIMELOCK');
  assert.equal(session.threshold, 3);

  // 3. Guardians cast votes
  session = SocialRecoveryEngine.castVote(session, guardians[0].did, setup.rawShares[0].index, setup.rawShares[0].shareHex);
  session = SocialRecoveryEngine.castVote(session, guardians[1].did, setup.rawShares[1].index, setup.rawShares[1].shareHex);
  session = SocialRecoveryEngine.castVote(session, guardians[2].did, setup.rawShares[2].index, setup.rawShares[2].shareHex);
  assert.equal(session.votes.length, 3);

  // 4. Timelock active check (without override, should block)
  const prematureFinalize = SocialRecoveryEngine.finalizeRecovery(session, false);
  assert.equal(prematureFinalize.status, 'TIMELOCK_ACTIVE');

  // 5. Finalize with timelock expired / simulated
  const successFinalize = SocialRecoveryEngine.finalizeRecovery(session, true);
  assert.equal(successFinalize.status, 'SUCCESS');
  assert.equal(successFinalize.reconstructedSecret, rootSecret);

  // 6. Test Owner Veto
  let vetoSession = SocialRecoveryEngine.initiateRecovery(ownerDid, 'did:key:z6Mmalicious', setup.config);
  vetoSession = SocialRecoveryEngine.castVote(vetoSession, guardians[0].did, setup.rawShares[0].index, setup.rawShares[0].shareHex);
  vetoSession = SocialRecoveryEngine.vetoRecovery(vetoSession, 'Malicious SIM swap detected');
  assert.equal(vetoSession.status, 'VETOED_BY_OWNER');

  const vetoFinalize = SocialRecoveryEngine.finalizeRecovery(vetoSession, true);
  assert.equal(vetoFinalize.status, 'VETOED');
});

// 35. ZK Set Non-Membership & Composite Predicates
test('36. ZK Predicates: Set Non-Membership & Composite Multi-Predicate Proof Verification', () => {
  const secretSubjectId = 'PASSPORT-US-991823';
  const { salt } = createCommitment(secretSubjectId);
  const sanctionsList = ['SANCTIONED-001', 'SANCTIONED-002', 'BLOCKED-USER-99'];

  // 1. Prove secretSubjectId is NOT in sanctionsList
  const nonMemberProof = proveSetNonMembership('passportId', secretSubjectId, salt, sanctionsList);
  assert.equal(nonMemberProof.type, 'ZKSetNonMembershipProof2026');

  const nonMemberAudit = verifySetNonMembershipProof(nonMemberProof, sanctionsList);
  assert.equal(nonMemberAudit.valid, true);

  // Should throw if value is in restricted list
  assert.throws(() => {
    proveSetNonMembership('passportId', 'SANCTIONED-001', salt, sanctionsList);
  }, /secretValue IS in the restricted set/);

  // 2. Composite Multi-Predicate Proof: Combine Range, Set Membership, Set Non-Membership, and Age
  const { salt: gpaSalt } = createCommitment(3.95);
  const rangeProof = proveRange('gpa', 3.95, gpaSalt, 3.5, 4.0);

  const { salt: uniSalt } = createCommitment('Stanford');
  const allowedUnis = ['MIT', 'Stanford', 'Oxford'];
  const memberProof = proveSetMembership('university', 'Stanford', uniSalt, allowedUnis);

  const ageProof = proveAgeAbove('birthDate', '2001-05-12', 21, undefined, '2026-08-29');

  const compositeProof = proveCompositePredicate([rangeProof, memberProof, nonMemberProof, ageProof]);
  assert.equal(compositeProof.type, 'ZKCompositePredicateProof2026');
  assert.equal(compositeProof.proofs.length, 4);

  const compositeAudit = verifyCompositePredicate(compositeProof, {
    allowedSets: { university: allowedUnis },
    restrictedSets: { passportId: sanctionsList }
  });
  assert.equal(compositeAudit.valid, true);
  assert.equal(compositeAudit.verifiedCount, 4);
});

// 36. MultiChain Ledger Anchor & Calldata Generation
test('37. MultiChain Anchor: EVM Calldata, Bitcoin OP_RETURN, Solana Anchor instruction generation', () => {
  const merkleRoot = '0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
  const batchCount = 1000;

  // 1. EVM Calldata
  const ethAnchor = MultiChainLedgerAnchor.formatAnchor('ethereum', merkleRoot, batchCount, 'DocuTrust Mainnet Batch');
  assert.equal(ethAnchor.chain, 'ethereum');
  assert.ok(ethAnchor.calldataHex.startsWith('0x892a4b12'));
  assert.ok(ethAnchor.explorerUrl.includes('etherscan.io'));

  // 2. Polygon Calldata
  const polyAnchor = MultiChainLedgerAnchor.formatAnchor('polygon', merkleRoot, batchCount);
  assert.equal(polyAnchor.chain, 'polygon');
  assert.ok(polyAnchor.calldataHex.startsWith('0x892a4b12'));

  // 3. Bitcoin OP_RETURN
  const btcAnchor = MultiChainLedgerAnchor.formatAnchor('bitcoin', merkleRoot, batchCount);
  assert.equal(btcAnchor.chain, 'bitcoin');
  assert.ok(btcAnchor.opReturnHex.startsWith('0x6a28'));
  assert.ok(btcAnchor.explorerUrl.includes('mempool.space'));

  // 4. Solana Anchor Instruction
  const solAnchor = MultiChainLedgerAnchor.formatAnchor('solana', merkleRoot, batchCount);
  assert.equal(solAnchor.chain, 'solana');
  assert.ok(solAnchor.instructionDataHex.startsWith('0x'));
  assert.ok(solAnchor.explorerUrl.includes('solscan.io'));
});

// 37. W3C VC JSON Schema Validation
test('38. Schema: JSON Schema Validator, canonical digest, and credential subject validation', () => {
  const universityDiplomaSchema = {
    $id: 'https://schema.docutrust.org/diploma-v1.json',
    type: 'object',
    required: ['studentId', 'degree', 'gpa', 'graduationDate'],
    properties: {
      studentId: { type: 'string', pattern: '^STU-\\d{5}$' },
      degree: { type: 'string', minLength: 3 },
      gpa: { type: 'number', minimum: 0.0, maximum: 4.0 },
      graduationDate: { type: 'string', format: 'date' },
      honors: { type: 'boolean' }
    },
    additionalProperties: false
  };

  const schemaHash = SchemaValidator.computeSchemaHash(universityDiplomaSchema);
  assert.equal(typeof schemaHash, 'string');
  assert.equal(schemaHash.length, 64);

  // 1. Valid subject
  const validSubject = {
    studentId: 'STU-12345',
    degree: 'B.S. in Computer Science',
    gpa: 3.85,
    graduationDate: '2026-05-20',
    honors: true
  };
  const validResult = SchemaValidator.validate(validSubject, universityDiplomaSchema);
  assert.equal(validResult.valid, true);
  assert.equal(validResult.errors.length, 0);

  // 2. Invalid subject (failing regex and out of range GPA)
  const invalidSubject = {
    studentId: 'INVALID_ID',
    degree: 'CS', // minLength 3
    gpa: 4.5, // max 4.0
    graduationDate: 'not-a-date',
    unknownField: 'malicious' // additionalProperties false
  };
  const invalidResult = SchemaValidator.validate(invalidSubject, universityDiplomaSchema);
  assert.equal(invalidResult.valid, false);
  assert.ok(invalidResult.errors.length >= 4);

  // 3. Credential Subject Helper
  const credential = {
    id: 'urn:uuid:test-cred',
    type: ['VerifiableCredential'],
    credentialSubject: validSubject
  };
  const credSubjectResult = SchemaValidator.validateCredentialSubject(credential, universityDiplomaSchema);
  assert.equal(credSubjectResult.valid, true);
});

// 38. Dynamic Cryptographic Accumulator (O(1) Revocation Witness)
test('39. Accumulator: Dynamic Cryptographic Accumulator add, delete, witness generation & O(1) verify', () => {
  const acc = new CryptographicAccumulator('acc-test-01');

  // Add members
  const member1 = 'did:key:z6Mku1111111111111111111111111111111111111111111';
  const member2 = 'did:key:z6Mku2222222222222222222222222222222222222222222';
  const member3 = 'did:key:z6Mku3333333333333333333333333333333333333333333';

  acc.add(member1);
  acc.addBatch([member2, member3]);

  const state = acc.exportState();
  assert.equal(state.memberCount, 3);

  // Create membership witness for member2
  const witness2 = acc.createWitness(member2);
  assert.equal(witness2.element, member2);

  // Verify witness in O(1) time
  const isValid = CryptographicAccumulator.verifyWitness(witness2, state.accumulator);
  assert.equal(isValid, true);

  // Delete member2 from accumulator
  acc.delete(member2);
  const updatedState = acc.exportState();
  assert.equal(updatedState.memberCount, 2);

  // Old witness for member2 should now be INVALID against updated accumulator state
  const isInvalidAfterDelete = CryptographicAccumulator.verifyWitness(witness2, updatedState.accumulator);
  assert.equal(isInvalidAfterDelete, false);

  // Witness for member1 recreated should verify against updated state
  const witness1 = acc.createWitness(member1);
  const isValidMember1 = CryptographicAccumulator.verifyWitness(witness1, updatedState.accumulator);
  assert.equal(isValidMember1, true);
});

// 39. Multi-Recipient JWE Confidential Asymmetric Encryption
test('40. JWE: Multi-Recipient JSON Web Encryption with ECDH-ES+A256KW and AES-256-GCM', () => {
  // Generate 2 distinct recipient identities
  const recipient1Kp = MultiRecipientJWE.generateRecipientKeyPair();
  const recipient2Kp = MultiRecipientJWE.generateRecipientKeyPair();
  const outsiderKp = MultiRecipientJWE.generateRecipientKeyPair();

  const confidentialPayload = {
    auditRecordId: 'AUDIT-99201',
    financialGrade: 'AAA+',
    internalNote: 'Classified Sovereign Verification Record'
  };

  const recipients = [
    { did: recipient1Kp.did, publicKey: recipient1Kp.publicKeyHex },
    { did: recipient2Kp.did, publicKey: recipient2Kp.publicKeyHex }
  ];

  // Encrypt payload for both recipients in a single General JWE envelope
  const jwe = MultiRecipientJWE.encrypt(confidentialPayload, recipients);
  assert.ok(jwe.protected);
  assert.equal(jwe.recipients.length, 2);
  assert.ok(jwe.ciphertext);
  assert.ok(jwe.tag);

  // Recipient 1 decrypts successfully
  const decrypted1 = MultiRecipientJWE.decrypt(jwe, recipient1Kp.did, recipient1Kp.privateKeyHex);
  assert.deepEqual(decrypted1.parsedJson, confidentialPayload);

  // Recipient 2 decrypts successfully
  const decrypted2 = MultiRecipientJWE.decrypt(jwe, recipient2Kp.did, recipient2Kp.privateKeyHex);
  assert.deepEqual(decrypted2.parsedJson, confidentialPayload);

  // Outsider fails to decrypt
  assert.throws(() => {
    MultiRecipientJWE.decrypt(jwe, outsiderKp.did, outsiderKp.privateKeyHex);
  }, /not authorized/);
});

// 40. ZK Set Intersection Predicates
test('41. ZK Predicates: Set Intersection Proof & Composite Verification', () => {
  const secretAccreditation = 'ACC-HEALTH-TIER-1';
  const { salt } = createCommitment(secretAccreditation);
  const recognizedCertifications = ['ACC-HEALTH-TIER-1', 'ACC-FINANCE-TIER-1', 'ACC-DEFENSE-TIER-1'];

  // Prove intersection in zero-knowledge
  const intersectionProof = proveSetIntersection('accreditation', secretAccreditation, salt, recognizedCertifications);
  assert.equal(intersectionProof.type, 'ZKSetIntersectionProof2026');

  const audit = verifySetIntersectionProof(intersectionProof, recognizedCertifications);
  assert.equal(audit.valid, true);

  // Fails with mismatched set
  const otherSet = ['ACC-ACADEMIC-ONLY'];
  const invalidAudit = verifySetIntersectionProof(intersectionProof, otherSet);
  assert.equal(invalidAudit.valid, false);

  // Verify in Composite Predicate
  const compositeProof = proveCompositePredicate([intersectionProof]);
  const compAudit = verifyCompositePredicate(compositeProof, {
    allowedSets: { accreditation: recognizedCertifications }
  });
  assert.equal(compAudit.valid, true);
});

// 41. W3C BitstringStatusList2024 Multi-State Revocation & Suspension
test('42. Revocation: W3C BitstringStatusList2024 with 2-bit multi-state and multibase encoding', () => {
  // Create 2-bit status list: 00=Valid, 01=Revoked, 10=Suspended, 11=Under Review
  const statusList = new BitstringStatusList2024(1000, 2, 'revocation');
  assert.equal(statusList.length, 1000);
  assert.equal(statusList.statusSize, 2);

  // Set various statuses
  statusList.setStatus(0, 0); // Valid
  statusList.setStatus(5, 1); // Revoked
  statusList.setStatus(12, 2); // Suspended
  statusList.setStatus(42, 3); // Custom/Under Review

  assert.equal(statusList.isValid(0), true);
  assert.equal(statusList.isRevoked(5), true);
  assert.equal(statusList.isSuspended(12), true);
  assert.equal(statusList.getStatus(42), 3);

  // Multibase serialization
  const encoded = statusList.encode(true);
  assert.ok(encoded.startsWith('u'));

  // Decoding
  const decoded = BitstringStatusList2024.decode(encoded, { length: 1000, statusSize: 2 });
  assert.equal(decoded.isValid(0), true);
  assert.equal(decoded.isRevoked(5), true);
  assert.equal(decoded.isSuspended(12), true);
  assert.equal(decoded.getStatus(42), 3);

  // W3C VC 2.0 Credential generation
  const issuerKp = generateKeyPair();
  const cred = statusList.generateCredential('https://registry.example.com/status/list-2024-01', issuerKp.did);
  assert.equal(cred.type.includes('BitstringStatusListCredential'), true);
  assert.equal(cred.credentialSubject.statusSize, 2);
  assert.equal(cred.credentialSubject.encodedList, encoded);

  const entry = BitstringStatusList2024.createEntry('https://registry.example.com/status/list-2024-01', 5, 'revocation', 2);
  assert.equal(entry.statusListIndex, '5');
  assert.equal(entry.statusSize, 2);
});

// 42. DIF Presentation Exchange v2.0 Engine
test('43. Presentation Exchange 2.0: Definition, constraints, submission, and evaluation', () => {
  const definition = PresentationExchangeEngine.createDefinition('def_kyc_and_degree', [
    {
      id: 'degree_descriptor',
      purpose: 'Verify higher education degree',
      schema: [{ uri: 'UniversityDegreeCredential' }],
      constraints: {
        fields: [
          {
            path: ['$.credentialSubject.degree', '$.degree'],
            filter: { type: 'string', minLength: 2 }
          }
        ]
      }
    }
  ], { name: 'Employment Application Verification' });

  assert.equal(definition.id, 'def_kyc_and_degree');
  assert.equal(definition.input_descriptors.length, 1);

  // Valid credential presentation
  const mockPresentation = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [
      {
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        credentialSubject: {
          id: 'did:key:z6MkuXYZ',
          name: 'Elena Rostova',
          degree: 'Master of Science in Cryptography'
        }
      }
    ]
  };

  const submission = PresentationExchangeEngine.createSubmission('def_kyc_and_degree', [
    {
      id: 'degree_descriptor',
      format: 'ldp_vc',
      path: '$.verifiableCredential[0]'
    }
  ]);

  const evalResult = PresentationExchangeEngine.evaluatePresentation(mockPresentation, definition, submission);
  assert.equal(evalResult.valid, true);
  assert.equal(evalResult.matchedDescriptors.length, 1);
  assert.equal(evalResult.matchedDescriptors[0], 'degree_descriptor');
  assert.ok(evalResult.auditHash.length === 64);

  // Mismatched presentation fails evaluation
  const failingPresentation = {
    type: ['VerifiablePresentation'],
    verifiableCredential: [
      {
        type: ['VerifiableCredential', 'DriverLicenseCredential'],
        credentialSubject: { licenseNumber: 'DL-99182' }
      }
    ]
  };
  const failResult = PresentationExchangeEngine.evaluatePresentation(failingPresentation, definition);
  assert.equal(failResult.valid, false);
  assert.equal(failResult.unmatchedDescriptors.includes('degree_descriptor'), true);
});

// 43. RSA Accumulator Non-Membership Witnesses
test('44. Accumulator: O(1) Non-Membership Witnesses via Bezout Extended Euclidean Algorithm', () => {
  const acc = new CryptographicAccumulator('acc_revocation_pool_002');
  acc.add('member_alice_001');
  acc.add('member_bob_002');
  acc.add('member_charlie_003');

  const state = acc.exportState();

  // Create non-membership witness for an element that was NEVER added
  const nonMember = 'outsider_eve_999';
  const nonMemWitness = acc.createNonMembershipWitness(nonMember);
  assert.equal(nonMemWitness.element, nonMember);
  assert.ok(nonMemWitness.d);
  assert.ok(nonMemWitness.b);

  // Constant-time verification
  const isValidNonMember = CryptographicAccumulator.verifyNonMembershipWitness(
    nonMemWitness,
    state.accumulator,
    state.generator,
    state.modulus
  );
  assert.equal(isValidNonMember, true);

  // Adding Eve makes the non-membership witness invalid
  acc.add(nonMember);
  const updatedState = acc.exportState();
  const isStillNonMember = CryptographicAccumulator.verifyNonMembershipWitness(
    nonMemWitness,
    updatedState.accumulator,
    updatedState.generator,
    updatedState.modulus
  );
  assert.equal(isStillNonMember, false);
});

// 44. Schema Composition & Advanced Formats
test('45. Schema: Composition with $defs, $ref, combinators (allOf, oneOf, not) & formats (uuid, ipv4)', () => {
  const compositeSchema = {
    $id: 'https://schema.docutrust.org/identity-v2',
    $defs: {
      EmailAddress: {
        type: 'string',
        format: 'email'
      },
      ServerEndpoint: {
        type: 'object',
        required: ['ip', 'uuid'],
        properties: {
          ip: { type: 'string', format: 'ipv4' },
          uuid: { type: 'string', format: 'uuid' }
        }
      }
    },
    type: 'object',
    required: ['user', 'contact'],
    properties: {
      user: {
        type: 'string',
        minLength: 3
      },
      contact: {
        $ref: '#/$defs/EmailAddress'
      },
      server: {
        $ref: '#/$defs/ServerEndpoint'
      },
      paymentOption: {
        oneOf: [
          { type: 'object', required: ['creditCard'], properties: { creditCard: { type: 'string' } } },
          { type: 'object', required: ['cryptoAddress'], properties: { cryptoAddress: { type: 'string', format: 'did' } } }
        ]
      }
    }
  };

  const validPayload = {
    user: 'alice_wonder',
    contact: 'alice@wonderland.org',
    server: {
      ip: '192.168.1.1',
      uuid: '123e4567-e89b-12d3-a456-426614174000'
    },
    paymentOption: {
      cryptoAddress: 'did:key:z6MkuXYZ'
    }
  };

  const validationResult = SchemaValidator.validate(validPayload, compositeSchema);
  assert.equal(validationResult.valid, true);
  assert.equal(validationResult.errors.length, 0);

  // Invalid payload (bad IPv4 and bad email)
  const invalidPayload = {
    user: 'al',
    contact: 'not-an-email',
    server: {
      ip: '999.999.999.999',
      uuid: 'invalid-uuid'
    },
    paymentOption: {
      creditCard: '1234',
      cryptoAddress: 'did:key:z6MkuXYZ' // Violates oneOf (both present)
    }
  };

  const invalidResult = SchemaValidator.validate(invalidPayload, compositeSchema);
  assert.equal(invalidResult.valid, false);
  assert.ok(invalidResult.errors.length >= 3);
});

// 45. Recursive ZK Predicate Graph Evaluator
test('46. ZK Predicates: Recursive boolean graph (AND, OR, NOT, THRESHOLD) across heterogeneous proofs', () => {
  // Generate individual ZK proofs
  const ageProof = proveAgeAbove('dateOfBirth', '2000-01-15', 21);
  const salaryRangeProof = proveRange('salary', 125000, createCommitment(125000).salt, 100000, 200000);
  const regionProof = proveSetMembership('country', 'CH', createCommitment('CH').salt, ['CH', 'DE', 'FR', 'AT']);

  // Build recursive graph: (Age >= 21 AND Salary in [100k, 200k]) OR Country in Allowed
  const graphRoot = {
    id: 'root_policy',
    operator: 'OR',
    children: [
      {
        id: 'financial_maturity_and',
        operator: 'AND',
        children: [
          { id: 'node_age', proof: ageProof },
          { id: 'node_salary', proof: salaryRangeProof }
        ]
      },
      {
        id: 'node_region',
        proof: regionProof
      }
    ]
  };

  const graphProof = provePredicateGraph('graph_access_policy_001', graphRoot);
  assert.equal(graphProof.type, 'ZKPredicateGraphProof2026');
  assert.ok(graphProof.graphRootHash);

  const evalResult = verifyPredicateGraph(graphProof, {
    allowedSets: { country: ['CH', 'DE', 'FR', 'AT'] }
  });

  assert.equal(evalResult.valid, true);
  assert.equal(evalResult.satisfiedNodes.includes('root_policy'), true);
  assert.equal(evalResult.satisfiedNodes.includes('financial_maturity_and'), true);
  assert.equal(evalResult.satisfiedNodes.includes('node_age'), true);
  assert.equal(evalResult.satisfiedNodes.includes('node_salary'), true);
});

// 46. Unified VerifiableCredentialsEngine with PQC Hybrid Verification
test('47. VerifiableCredentialsEngine: Unified verification of Post-Quantum ML-DSA-65 hybrid credentials', async () => {
  const pqcKeys = generatePQCKeyPair();
  const res = VerifiableCredentialsEngine.issue({
    type: ['UniversityDegreeCredential'],
    issuer: { id: pqcKeys.hybridDid, name: 'Quantum University' },
    credentialSubject: {
      id: 'did:key:z6MkuBobStudent999',
      degree: 'M.Sc. Quantum Computing',
      gpa: 4.0
    },
    keyPair: pqcKeys.classicalKeyPair,
    enablePQC: true
  });

  assert.equal(res.credential.proof.type, 'ML-DSA-65-Ed25519-Hybrid-2026');
  assert.ok(res.credential.proof.proofValue.startsWith('pqc1_'));

  const audit = await VerifiableCredentialsEngine.verify(res.credential, {
    expectedPublicKeyHex: pqcKeys.classicalKeyPair.publicKeyHex
  });

  assert.equal(audit.valid, true);
  assert.equal(audit.signatureValid, true);
  assert.equal(audit.isQuantumSafe, true);
  assert.equal(audit.errors.length, 0);
});

// 47. Unified VerifiableCredentialsEngine with BitstringStatusList2024
test('48. VerifiableCredentialsEngine: Status checking with BitstringStatusList2024 (valid, suspended, revoked)', async () => {
  const issuerKeys = generateKeyPair();
  const statusList = new BitstringStatusList2024(100, 2, 'revocation'); // 2-bit: 0=valid, 1=revoked, 2=suspended
  statusList.setStatus(10, 1); // Index 10 is revoked
  statusList.setStatus(20, 2); // Index 20 is suspended
  statusList.setStatus(30, 0); // Index 30 is valid

  const statusListCredential = statusList.generateCredential(
    'https://example.edu/status/2026',
    issuerKeys.did
  );

  // Credential 1: Valid
  const validVc = VerifiableCredentialsEngine.issue({
    type: ['EmploymentCredential'],
    issuer: { id: issuerKeys.did, name: 'Tech Corp' },
    credentialSubject: { employeeId: 'E-101', role: 'Engineer' },
    credentialStatus: {
      id: 'https://example.edu/status/2026#30',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: 30,
      statusSize: 2,
      statusListCredential: 'https://example.edu/status/2026'
    },
    keyPair: issuerKeys
  }).credential;

  const validAudit = await VerifiableCredentialsEngine.verify(validVc, {
    statusListCredential
  });
  assert.equal(validAudit.valid, true);
  assert.equal(validAudit.isRevoked, false);
  assert.equal(validAudit.isSuspended, false);

  // Credential 2: Revoked
  const revokedVc = VerifiableCredentialsEngine.issue({
    type: ['EmploymentCredential'],
    issuer: { id: issuerKeys.did, name: 'Tech Corp' },
    credentialSubject: { employeeId: 'E-102', role: 'Intern' },
    credentialStatus: {
      id: 'https://example.edu/status/2026#10',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: 10,
      statusSize: 2,
      statusListCredential: 'https://example.edu/status/2026'
    },
    keyPair: issuerKeys
  }).credential;

  const revokedAudit = await VerifiableCredentialsEngine.verify(revokedVc, {
    statusListCredential
  });
  assert.equal(revokedAudit.valid, false);
  assert.equal(revokedAudit.isRevoked, true);

  // Credential 3: Suspended
  const suspendedVc = VerifiableCredentialsEngine.issue({
    type: ['EmploymentCredential'],
    issuer: { id: issuerKeys.did, name: 'Tech Corp' },
    credentialSubject: { employeeId: 'E-103', role: 'Contractor' },
    credentialStatus: {
      id: 'https://example.edu/status/2026#20',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: 20,
      statusSize: 2,
      statusListCredential: 'https://example.edu/status/2026'
    },
    keyPair: issuerKeys
  }).credential;

  const suspendedAudit = await VerifiableCredentialsEngine.verify(suspendedVc, {
    statusListCredential
  });
  assert.equal(suspendedAudit.valid, false);
  assert.equal(suspendedAudit.isSuspended, true);
});

// 48. Prototype Pollution Defense
test('49. Security: sanitizeJsonPayload strips prototype pollution attacks recursively', () => {
  const maliciousInput = JSON.parse('{"valid": "data", "__proto__": {"polluted": true}, "nested": {"constructor": {"prototype": {"isAdmin": true}}}}');
  const cleaned = sanitizeJsonPayload(maliciousInput);

  assert.equal(cleaned.valid, 'data');
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(({}).polluted, undefined);
  assert.equal(cleaned.__proto__, undefined);
  assert.equal(cleaned.nested.constructor, undefined);
  assert.equal(({}).isAdmin, undefined);
});

// 50. AnonCreds 2.0 Blind Issuance & Presentation
test('50. AnonCreds 2.0: Blind request, blind issuance, unblinding, presentation, and verification', () => {
  const issuerEdKp = generateKeyPair();
  const issuerBbsKp = generateBBSKeyPair(10);
  const issuerKeys = {
    issuerDid: issuerEdKp.did,
    publicKeyHex: issuerEdKp.publicKeyHex,
    privateKeyHex: issuerEdKp.privateKeyHex,
    bbsKeyPair: issuerBbsKp,
    schemaId: 'schema:degree:2026'
  };

  // 1. Holder generates master secret and creates blind request
  const { masterSecret } = AnonCredsEngine.generateHolderMasterSecret();
  const { request, blindingFactor } = AnonCredsEngine.createBlindRequest(
    masterSecret,
    'schema:degree:2026',
    issuerEdKp.did
  );

  assert.equal(request.type, 'AnonCredsBlindRequest2026');
  assert.equal(AnonCredsEngine.verifyBlindRequest(request), true);

  // 2. Issuer blind signs claims
  const claims = {
    recipientName: 'Alice Henderson',
    degree: 'M.S. Cybersecurity',
    gpa: '3.95',
    graduationYear: 2026
  };
  const blindCred = AnonCredsEngine.issueBlindCredential(request, claims, issuerKeys, issuerEdKp);
  assert.equal(blindCred.type, 'AnonCredsBlindCredential2026');
  assert.equal(blindCred.blindedCommitment, request.blindedSecretCommitment);

  // 3. Holder unblinds credential
  const anonCred = AnonCredsEngine.unblindCredential(blindCred, masterSecret, blindingFactor);
  assert.equal(anonCred.id, blindCred.id);

  // 4. Holder presents with selective disclosure (disclosing degree and gpa, hiding name and year)
  const presentationNonce = 'verifier-challenge-nonce-777';
  const presentation = AnonCredsEngine.createPresentation(
    anonCred,
    masterSecret,
    ['degree', 'gpa'],
    presentationNonce
  );

  assert.equal(presentation.type, 'AnonCredsPresentation2026');
  assert.deepEqual(presentation.disclosedClaims, {
    degree: 'M.S. Cybersecurity',
    gpa: '3.95'
  });

  // 5. Verifier verifies presentation
  const audit = AnonCredsEngine.verifyPresentation(
    presentation,
    presentationNonce,
    issuerEdKp.did
  );

  assert.equal(audit.valid, true);
  assert.equal(audit.masterSecretVerified, true);
  assert.equal(audit.errors.length, 0);
});

// 51. FROST DKG Ceremony & Threshold Signing
test('51. DKG: Ceremony setup, share signing, aggregation, and group verification (2-of-3)', () => {
  const participants = [
    { name: 'Node 1 (Alpha)' },
    { name: 'Node 2 (Beta)' },
    { name: 'Node 3 (Gamma)' }
  ];

  // 1. Run DKG Ceremony
  const dkgSetup = DKGEngine.runDKGCeremony(participants, 2);
  assert.equal(dkgSetup.threshold, 2);
  assert.equal(dkgSetup.totalParticipants, 3);
  assert.ok(dkgSetup.groupDid.startsWith('did:dkg:z'));

  // 2. Generate partial signatures for message from Participant 1 and Participant 3
  const message = 'Batch Merkle Root: 0x9f83...2026';
  const share1 = DKGEngine.signShare(1, dkgSetup.participants[0].privateShareHex, dkgSetup.participants[0].did, message);
  const share3 = DKGEngine.signShare(3, dkgSetup.participants[2].privateShareHex, dkgSetup.participants[2].did, message);

  // 3. Aggregate threshold signature
  const aggregated = DKGEngine.aggregateSignatures(
    dkgSetup.groupPublicKeyHex,
    dkgSetup.groupDid,
    2,
    [share1, share3]
  );

  assert.equal(aggregated.type, 'DKGThresholdEd25519Signature2026');
  assert.deepEqual(aggregated.participatingSigners, [1, 3]);

  // 4. Verify aggregated signature
  const verifyResult = DKGEngine.verifyAggregatedSignature(aggregated, message, dkgSetup.groupPublicKeyHex);
  assert.equal(verifyResult.valid, true);
});

// 52. Solidity EVM Contract Generator & Calldata
test('52. Solidity: DocuTrustVerifier.sol generation & EVM ABI calldata encoding & Merkle proof validation', () => {
  const solCode = SolidityEngine.generateVerifierContract({ contractName: 'EnterpriseDocuTrustVerifier' });
  assert.ok(solCode.includes('contract EnterpriseDocuTrustVerifier'));
  assert.ok(solCode.includes('function verifyCredentialOnChain'));

  const leaves = [
    sha256Hex('credential-1'),
    sha256Hex('credential-2'),
    sha256Hex('credential-3'),
    sha256Hex('credential-4')
  ];
  const tree = new MerkleTree(leaves);
  const root = tree.getRoot();
  const proof = tree.getProof(0);

  const calldata = SolidityEngine.encodeVerificationCalldata(leaves[0], proof.auditPath, root);
  assert.ok(calldata.calldataHex.startsWith('0x'));
  assert.equal(calldata.methodSignature, 'verifyCredentialOnChain(bytes32,bytes32[],bytes32)');

  const localValid = MerkleTree.verifyProof(null, proof, root);
  assert.equal(localValid, true);
});

// 53. Cryptographic Audit Bundle Packaging (.dtbundle)
test('53. Cryptographic Audit Bundle: Signed .dtbundle generation, verification, and compliance report', () => {
  const signerKp = generateKeyPair();
  const hc = new TamperEvidentHashChain();
  hc.appendBlock(sha256Hex('root1'), 10, signerKp.did, h => signData(h, signerKp));
  hc.appendBlock(sha256Hex('root2'), 25, signerKp.did, h => signData(h, signerKp));

  const mmr = new MerkleMountainRange();
  mmr.append('leaf-1');
  mmr.append('leaf-2');

  const bundle = AuditBundleEngine.createAuditBundle({
    organization: 'Acme Federal Trust',
    signerKeyPair: signerKp,
    hashchain: hc,
    mmr,
    credentials: [{ id: 'cred-1', jcsCanonicalHash: sha256Hex('c1') }]
  });

  assert.equal(bundle.type, 'DocuTrustAuditBundle2026');
  assert.equal(bundle.manifest.organization, 'Acme Federal Trust');

  const audit = AuditBundleEngine.verifyAuditBundle(bundle, signerKp.publicKeyHex);
  assert.equal(audit.valid, true);
  assert.equal(audit.signatureValid, true);
  assert.equal(audit.hashchainValid, true);
  assert.equal(audit.tsaTimestampValid, true);

  const report = AuditBundleEngine.generateComplianceReport(bundle, audit);
  assert.ok(report.includes('Acme Federal Trust'));
  assert.ok(report.includes('PASSED'));
});

// 54. W3C DataIntegrityProof Suites
test('54. W3C DataIntegrityProof: Issuance with eddsa-jcs-2022 & ml-dsa-65-2026 and verification', async () => {
  const issuerKp = generateKeyPair();

  // 1. eddsa-jcs-2022
  const vcEd = VerifiableCredentialsEngine.issueDataIntegrity({
    issuer: { id: issuerKp.did, name: 'DocuTrust Authority' },
    credentialSubject: { student: 'Bob', cert: 'B.S. Mathematics' },
    cryptosuite: 'eddsa-jcs-2022',
    keyPair: issuerKp
  });

  assert.equal(vcEd.proof.type, 'DataIntegrityProof');
  assert.equal(vcEd.proof.cryptosuite, 'eddsa-jcs-2022');

  const auditEd = await VerifiableCredentialsEngine.verify(vcEd);
  assert.equal(auditEd.valid, true);
  assert.equal(auditEd.signatureValid, true);

  // 2. ml-dsa-65-2026 PQC
  const vcPqc = VerifiableCredentialsEngine.issueDataIntegrity({
    issuer: { id: issuerKp.did, name: 'Quantum Authority' },
    credentialSubject: { scientist: 'Eve', clearance: 'COSMIC' },
    cryptosuite: 'ml-dsa-65-2026',
    keyPair: issuerKp
  });

  assert.equal(vcPqc.proof.type, 'DataIntegrityProof');
  assert.equal(vcPqc.proof.cryptosuite, 'ml-dsa-65-2026');

  const auditPqc = await VerifiableCredentialsEngine.verify(vcPqc);
  assert.equal(auditPqc.valid, true);
  assert.equal(auditPqc.isQuantumSafe, true);
});

// 51. Paillier Homomorphic Cryptosystem Engine
test('51. Confidential: Paillier Cryptosystem encryption, decryption, and homomorphic addition', () => {
  const keys = PaillierCryptosystem.generateKeyPair(128);
  assert.ok(keys.publicKey.n);
  assert.ok(keys.lambda);

  const m1 = 1500n;
  const m2 = 3500n;

  const c1 = PaillierCryptosystem.encrypt(m1, keys.publicKey);
  const c2 = PaillierCryptosystem.encrypt(m2, keys.publicKey);

  const decrypted1 = PaillierCryptosystem.decrypt(c1, keys);
  assert.equal(decrypted1, m1);

  // Homomorphic addition: cSum = (c1 * c2) mod n^2
  const cSum = PaillierCryptosystem.add(c1, c2, keys.publicKey);
  const decryptedSum = PaillierCryptosystem.decrypt(cSum, keys);
  assert.equal(decryptedSum, 5000n);

  // Scalar multiplication: cMul = (c1 ^ 3) mod n^2
  const cMul = PaillierCryptosystem.multiplyScalar(c1, 3n, keys.publicKey);
  const decryptedMul = PaillierCryptosystem.decrypt(cMul, keys);
  assert.equal(decryptedMul, 4500n);
});

// 52. Confidential Claims & ZK Threshold Proofs
test('52. Confidential: Encrypted claims, homomorphic batch summation, and ZK range threshold proofs', () => {
  const keys = PaillierCryptosystem.generateKeyPair(128);

  const encSalary = ConfidentialClaimsEngine.encryptClaim('salary', 120000, keys.publicKey);
  const encBonus = ConfidentialClaimsEngine.encryptClaim('bonus', 30000, keys.publicKey);

  assert.equal(encSalary.claimKey, 'salary');
  assert.equal(encSalary.algorithm, 'PaillierHomomorphic2026');

  const decSalary = PaillierCryptosystem.decrypt(encSalary.ciphertextHex, keys);
  assert.equal(decSalary, 120000n);

  // Homomorphic sum of claims
  const sumClaim = ConfidentialClaimsEngine.homomorphicSum([encSalary.ciphertextHex, encBonus.ciphertextHex], keys.publicKey);
  const decSum = PaillierCryptosystem.decrypt(sumClaim.resultCiphertextHex, keys);
  assert.equal(decSum, 150000n);

  // ZK Threshold Proof: Prove salary >= 100,000 without revealing salary
  const proof = ConfidentialClaimsEngine.proveThreshold('salary', 120000, 100000, 'gte', keys.publicKey);
  assert.equal(proof.isSatisfied, true);
  assert.equal(proof.operator, 'gte');

  const isProofValid = ConfidentialClaimsEngine.verifyThresholdProof(proof);
  assert.equal(isProofValid, true);

  // Negative test: Invalid threshold
  const failProof = ConfidentialClaimsEngine.proveThreshold('salary', 120000, 200000, 'gte', keys.publicKey);
  assert.equal(failProof.isSatisfied, false);
});

// 53. W3C URDNA2015 JSON-LD RDF Canonicalization
test('53. JSON-LD: W3C URDNA2015 deterministic N-Quads conversion and dataset digest calculation', () => {
  const doc = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:credential-alpha-01",
    "type": ["VerifiableCredential", "IdentityCredential"],
    "issuer": "did:key:z6Mku7V2K3pB58X9zW",
    "credentialSubject": {
      "id": "did:key:z6MkpTHR8VNsBxYAAWH",
      "name": "Alice Developer",
      "country": "Switzerland"
    }
  };

  const canonicalNQuads = JsonLdCanonicalizationEngine.canonicalize(doc);
  assert.ok(canonicalNQuads.includes('Alice Developer'));
  
  const digest = JsonLdCanonicalizationEngine.digest(doc);
  assert.equal(digest.length, 64);

  // Re-ordering JSON keys must result in the exact same canonical output and digest
  const reorderedDoc = {
    "issuer": "did:key:z6Mku7V2K3pB58X9zW",
    "type": ["VerifiableCredential", "IdentityCredential"],
    "credentialSubject": {
      "country": "Switzerland",
      "name": "Alice Developer",
      "id": "did:key:z6MkpTHR8VNsBxYAAWH"
    },
    "id": "urn:uuid:credential-alpha-01",
    "@context": ["https://www.w3.org/2018/credentials/v1"]
  };

  const canonical2 = JsonLdCanonicalizationEngine.canonicalize(reorderedDoc);
  assert.equal(canonical2, canonicalNQuads);
  assert.equal(JsonLdCanonicalizationEngine.digest(reorderedDoc), digest);
});

// 54. W3C Linked Data Signatures 2020 Suite
test('54. JSON-LD: Linked Data Signature creation and tamper-evident verification', () => {
  const issuerKp = generateKeyPair();
  const doc = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:doc-signed-001",
    "type": ["VerifiableCredential", "MembershipCredential"],
    "issuer": issuerKp.did,
    "credentialSubject": {
      "id": "did:key:z6MkpTHR8VNsBxYAAWH",
      "membershipLevel": "DiamondTier"
    }
  };

  const signed = JsonLdCanonicalizationEngine.signJsonLd(doc, issuerKp, { type: 'JsonLdSignature2020' });
  assert.ok(signed.proof);
  assert.equal(signed.proof.type, 'JsonLdSignature2020');
  assert.ok(signed.proof.proofValue);

  const verification = JsonLdCanonicalizationEngine.verifyJsonLd(signed, issuerKp.publicKeyHex);
  assert.equal(verification.valid, true);

  // Tamper detection: modifying a property should invalidate the signature
  const tampered = JSON.parse(JSON.stringify(signed));
  tampered.credentialSubject.membershipLevel = 'BronzeTier';
  const tamperedVerification = JsonLdCanonicalizationEngine.verifyJsonLd(tampered, issuerKp.publicKeyHex);
  assert.equal(tamperedVerification.valid, false);
});

// 55. Hierarchical Verifiable Trust Chains & Delegation Proofs
test('55. TrustChain: Multi-hop delegation tokens, depth constraints, and trust path validation', () => {
  const rootKp = generateKeyPair();
  const registrarKp = generateKeyPair();
  const deptKp = generateKeyPair();

  // Root accredits Registrar
  const token1 = TrustChainEngine.createDelegationToken({
    delegatorKeyPair: rootKp,
    delegateDid: registrarKp.did,
    maxDepth: 2,
    allowedCredentialTypes: ['UniversityDegreeCredential', 'DoctoralDiploma']
  });

  assert.equal(token1.delegatorDid, rootKp.did);
  assert.equal(token1.delegateDid, registrarKp.did);
  assert.equal(token1.constraints.maxDepth, 2);

  // Registrar delegates to Department
  const token2 = TrustChainEngine.createDelegationToken({
    delegatorKeyPair: registrarKp,
    delegateDid: deptKp.did,
    maxDepth: 1,
    allowedCredentialTypes: ['UniversityDegreeCredential']
  });

  // Department issues final leaf credential
  const leafVc = VerifiableCredentialsEngine.issue({
    type: ['UniversityDegreeCredential'],
    issuer: { id: deptKp.did, name: 'Physics Department' },
    credentialSubject: { student: 'Alice', degree: 'B.Sc. Quantum Computing' },
    keyPair: deptKp
  }).credential;

  // Verify valid chain from Root -> Registrar -> Dept
  const chainResult = TrustChainEngine.verifyTrustChain({
    delegationTokens: [token1, token2],
    rootAuthorityDid: rootKp.did,
    leafIssuerDid: deptKp.did,
    targetCredentialType: 'UniversityDegreeCredential',
    maxAllowedDepth: 3
  });

  assert.equal(chainResult.valid, true);
  assert.equal(chainResult.rootAuthorityDid, rootKp.did);
  assert.equal(chainResult.leafIssuerDid, deptKp.did);
  assert.equal(chainResult.chainDepth, 2);

  // Test failure on mismatched root
  const fakeRootKp = generateKeyPair();
  const unaccreditedResult = TrustChainEngine.verifyTrustChain({
    delegationTokens: [token1, token2],
    rootAuthorityDid: fakeRootKp.did,
    leafIssuerDid: deptKp.did,
    targetCredentialType: 'UniversityDegreeCredential',
    maxAllowedDepth: 3
  });
  assert.equal(unaccreditedResult.valid, false);
});

// 56. Post-Quantum Dual Hybrid KEM Armor Engine
test('56. Quantum Armor: Dual Hybrid KEM (Classical + ML-KEM-768 Kyber) sealing and unsealing', () => {
  const recipientKeys = DualHybridKEMEngine.generateDualKeyPair();
  assert.ok(recipientKeys.classicalPublicKeyHex);
  assert.ok(recipientKeys.pqcPublicKeyHex);

  const payload = {
    secretMission: 'Operation Quantum Shield',
    classification: 'TOP SECRET',
    coordinates: { lat: 46.2044, lng: 6.1432 }
  };

  const envelope = DualHybridKEMEngine.sealCredential(payload, recipientKeys.hybridPublicKey);
  assert.equal(envelope.type, 'DocuTrustQuantumSealedEnvelope2026');
  assert.equal(envelope.ciphertextBundle.algorithm, 'X25519-ML-KEM-768-HKDF-SHA512');
  assert.ok(envelope.ciphertextBundle.classicalEphemeralPub);
  assert.ok(envelope.ciphertextBundle.pqcEncapsulation.ciphertext);

  // Decapsulate & Decrypt
  const unsealed = DualHybridKEMEngine.unsealCredential(envelope, recipientKeys.hybridSecretKey);
  assert.deepEqual(unsealed, payload);

  // Tamper detection: modifying ciphertext must fail GCM auth tag check
  const tamperedEnvelope = JSON.parse(JSON.stringify(envelope));
  const ctBytes = Buffer.from(tamperedEnvelope.encryptedPayload.ciphertext, 'hex');
  ctBytes[0] ^= 0xff;
  tamperedEnvelope.encryptedPayload.ciphertext = ctBytes.toString('hex');

  assert.throws(() => {
    DualHybridKEMEngine.unsealCredential(tamperedEnvelope, recipientKeys.hybridSecretKey);
  });
});

// 57. Batch Accumulator Membership Witnessing
test('57. Accumulator: Constant-size batch membership witness creation and O(1) verification', () => {
  const acc = new CryptographicAccumulator('batch-acc-test-01');
  const elements = ['cred-alice-101', 'cred-bob-102', 'cred-charlie-103', 'cred-dave-104', 'cred-eve-105'];

  acc.addBatch(elements);
  const state = acc.exportState();

  // Prover creates batch witness for subset of elements
  const subset = ['cred-alice-101', 'cred-charlie-103', 'cred-eve-105'];
  const batchWitness = acc.createBatchWitness(subset);

  assert.deepEqual(batchWitness.elements, subset);
  assert.ok(batchWitness.witness);
  assert.ok(batchWitness.productPrimeHex);

  // Verifier validates batch witness against current accumulator in O(1) verification space
  const isValid = CryptographicAccumulator.verifyBatchWitness(batchWitness, state.accumulator);
  assert.equal(isValid, true);

  // Tamper check: modifying subset elements should invalidate witness
  const tamperedWitness = { ...batchWitness, elements: ['cred-alice-101', 'cred-bob-102', 'cred-eve-105'] };
  const isTamperedValid = CryptographicAccumulator.verifyBatchWitness(tamperedWitness, state.accumulator);
  assert.equal(isTamperedValid, false);
});

// 58. Paillier Homomorphic Subtraction & Weighted Linear Combinations
test('58. Confidential: Paillier homomorphic subtraction and weighted linear combinations', () => {
  const keyPair = PaillierCryptosystem.generateKeyPair(256);
  const pubKey = keyPair.publicKey;

  // 1. Homomorphic Subtraction: E(500) - E(150) = E(350)
  const c1 = PaillierCryptosystem.encrypt(500n, pubKey);
  const c2 = PaillierCryptosystem.encrypt(150n, pubKey);
  const cDiff = PaillierCryptosystem.subtract(c1, c2, pubKey);

  const decryptedDiff = PaillierCryptosystem.decrypt(cDiff, keyPair);
  assert.equal(decryptedDiff, 350n);

  // 2. Weighted Linear Combination: 3 * E(40) + 2 * E(25) - 1 * E(10) = 120 + 50 - 10 = 160
  const cA = PaillierCryptosystem.encrypt(40n, pubKey);
  const cB = PaillierCryptosystem.encrypt(25n, pubKey);
  const cC = PaillierCryptosystem.encrypt(10n, pubKey);

  const linResult = ConfidentialClaimsEngine.evaluateLinearCombination([
    { ciphertext: cA, weight: 3 },
    { ciphertext: cB, weight: 2 },
    { ciphertext: cC, weight: -1 }
  ], pubKey);

  assert.equal(linResult.operation, 'linear_combination');
  assert.equal(linResult.operandsCount, 3);

  const decryptedLin = PaillierCryptosystem.decrypt(linResult.resultCiphertextHex, keyPair);
  assert.equal(decryptedLin, 160n);
});

// 59. TrustChain Revocation Checking and Normalized DID Handling
test('59. TrustChain: Delegation token revocation checking and normalized DID resolution', () => {
  const rootKp = generateKeyPair();
  const delegateKp = generateKeyPair();

  const token = TrustChainEngine.createDelegationToken({
    delegatorKeyPair: rootKp,
    delegateDid: `${delegateKp.did}#key-1`,
    maxDepth: 1,
    allowedCredentialTypes: ['*']
  });

  // Valid verification with normalized DID
  const validCheck = TrustChainEngine.verifyTrustChain({
    delegationTokens: [token],
    rootAuthorityDid: rootKp.did,
    leafIssuerDid: delegateKp.did
  });
  assert.equal(validCheck.valid, true);

  // Revoked verification: specifying token ID in revokedTokenIds must fail
  const revokedCheck = TrustChainEngine.verifyTrustChain({
    delegationTokens: [token],
    rootAuthorityDid: rootKp.did,
    leafIssuerDid: delegateKp.did,
    revokedTokenIds: [token.id]
  });
  assert.equal(revokedCheck.valid, false);
  assert.ok(revokedCheck.errors.some(e => e.includes('has been revoked')));
});

// 60. did:jwk Encoding, Decoding & Resolution
test('60. DID: did:jwk encoding, decoding, and deterministic W3C DID document resolution', async () => {
  const ed25519Jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
  };

  // Encode JWK into did:jwk
  const did = DIDResolver.encodeDidJwk(ed25519Jwk);
  assert.ok(did.startsWith('did:jwk:'));

  // Decode back to JWK
  const decodedJwk = DIDResolver.decodeDidJwk(did);
  assert.equal(decodedJwk.kty, 'OKP');
  assert.equal(decodedJwk.crv, 'Ed25519');
  assert.equal(decodedJwk.x, ed25519Jwk.x);

  // Resolve into W3C DID Document
  const doc = await DIDResolver.resolve(did);
  assert.equal(doc.id, did);
  assert.equal(doc.verificationMethod.length, 1);
  assert.equal(doc.verificationMethod[0].type, 'Ed25519VerificationKey2020');
  assert.deepEqual(doc.verificationMethod[0].publicKeyJwk, ed25519Jwk);
  assert.ok(doc.assertionMethod.includes(`${did}#0`));
});

// 61. Verifiable SVG Digital Badge Engine
test('61. Badge: Verifiable SVG digital badge rendering, embedded metadata extraction, and tamper-evident verification', async () => {
  const issuerKp = generateKeyPair();
  const subjectKp = generateKeyPair();

  const { credential } = VerifiableCredentialsEngine.issue({
    issuer: { id: issuerKp.did },
    type: ['VerifiableCredential'],
    credentialSubject: {
      id: subjectKp.did,
      degree: 'Master of Quantum Cryptography',
      name: 'Alice Turing',
      honors: 'Summa Cum Laude'
    },
    keyPair: issuerKp
  });

  // Render SVG badge with academic-gold theme
  const svg = BadgeEngine.renderBadgeSvg(credential, {
    theme: 'academic-gold',
    badgeTitle: 'Master of Quantum Cryptography',
    recipientName: 'Alice Turing'
  });

  assert.ok(svg.includes('<svg'));
  assert.ok(svg.includes('<metadata>'));
  assert.ok(svg.includes('DOCUTRUST SOVEREIGN VERIFIABLE BADGE'));
  assert.ok(svg.includes('Master of Quantum Cryptography'));
  assert.ok(svg.includes('Alice Turing'));

  // Extract embedded credential
  const extractedCred = BadgeEngine.extractCredentialFromSvg(svg);
  assert.equal(extractedCred.id, credential.id);
  assert.equal(extractedCred.credentialSubject.degree, 'Master of Quantum Cryptography');

  // Verify badge authenticity
  const verifyResult = await BadgeEngine.verifyBadgeSvg(svg);
  assert.equal(verifyResult.valid, true);
  assert.equal(verifyResult.issuer, issuerKp.did);
  assert.ok(verifyResult.canonicalHash.length === 64);

  // Tamper detection: modifying SVG metadata breaks verification
  const tamperedSvg = svg.replace('Master of Quantum Cryptography', 'Ph.D. in Hacking');
  // If we tamper the embedded credential payload base64:
  const tamperedPayloadSvg = svg.replace(/<docutrust:credential[^>]*>([A-Za-z0-9+/=]+)<\/docutrust:credential>/, (match, b64) => {
    const raw = Buffer.from(b64, 'base64').toString('utf8');
    const tampered = raw.replace('Master of Quantum Cryptography', 'Fake Degree');
    return `<docutrust:credential xmlns:docutrust="https://docutrust.org/schema/badge/v1" format="w3c-vc-2.0" encoding="base64">${Buffer.from(tampered).toString('base64')}</docutrust:credential>`;
  });

  const tamperedResult = await BadgeEngine.verifyBadgeSvg(tamperedPayloadSvg);
  assert.equal(tamperedResult.valid, false);
});

// 67. Sovereign Policy-as-Proof & Governance Rule Engine (DocuTrust v9.0.0)
test('67. Sovereign Policy Engine: evaluate AST conditions and verify signed receipt', () => {
  const evaluatorKp = generateKeyPair();
  const issuerKp = generateKeyPair();

  const credential = {
    id: 'urn:uuid:credential-v9-policy-test',
    type: ['VerifiableCredential', 'AccreditedEngineerCredential'],
    issuer: issuerKp.did,
    validFrom: new Date(Date.now() - 3600000).toISOString(),
    credentialSubject: {
      id: 'did:key:holder123',
      name: 'Dr. Evelyn Reed',
      age: 32,
      jurisdiction: 'EU',
      clearanceLevel: 4,
      skills: ['cryptography', 'distributed-systems', 'zero-knowledge'],
      status: 'active'
    }
  };

  const policy = {
    id: 'policy-sovereign-clearance-v9',
    name: 'Critical Infrastructure Clearance Policy',
    version: '1.0.0',
    allowedIssuers: [issuerKp.did],
    requiredCredentialTypes: ['AccreditedEngineerCredential'],
    maxCredentialAgeSeconds: 86400,
    condition: {
      operator: 'and',
      conditions: [
        { field: 'credentialSubject.age', operator: 'gte', value: 21 },
        { field: 'credentialSubject.jurisdiction', operator: 'in', value: ['US', 'EU', 'UK'] },
        { field: 'credentialSubject.clearanceLevel', operator: 'gte', value: 3 },
        { field: 'credentialSubject.skills', operator: 'contains', value: 'cryptography' },
        {
          operator: 'or',
          conditions: [
            { field: 'credentialSubject.status', operator: 'eq', value: 'active' },
            { field: 'credentialSubject.provisional', operator: 'eq', value: true }
          ]
        }
      ]
    }
  };

  const result = PolicyEngine.evaluate(credential, policy, { evaluatorKeyPair: evaluatorKp });
  assert.equal(result.passed, true);
  assert.equal(result.errors.length, 0);
  assert.ok(result.receipt);
  assert.equal(result.receipt.policyId, 'policy-sovereign-clearance-v9');

  // Verify receipt cryptographically
  const receiptValid = PolicyEngine.verifyReceipt(result.receipt, evaluatorKp.publicKeyHex);
  assert.equal(receiptValid, true);

  // Negative evaluation test
  const failingCredential = {
    ...credential,
    credentialSubject: {
      ...credential.credentialSubject,
      clearanceLevel: 2 // Fails >= 3
    }
  };

  const failingResult = PolicyEngine.evaluate(failingCredential, policy);
  assert.equal(failingResult.passed, false);
  assert.ok(failingResult.errors.length > 0);
});

// 68. W3C did:peer Method 0 (Inception Key)
test('68. W3C did:peer Method 0: deterministic generation and document resolution', async () => {
  const kp = generateKeyPair();
  const peerDid = createDidPeer0(kp.publicKeyHex);
  assert.ok(peerDid.startsWith('did:peer:0z'));

  const doc = await DIDResolver.resolve(peerDid);
  assert.equal(doc.id, peerDid);
  assert.equal(doc.verificationMethod.length, 1);
  assert.equal(doc.verificationMethod[0].publicKeyHex, kp.publicKeyHex);
  assert.equal(doc.verificationMethod[0].type, 'Ed25519VerificationKey2020');
});

// 69. W3C did:peer Method 2 (Multiple Keys & Service Endpoints)
test('69. W3C did:peer Method 2: deterministic multi-key and service resolution', async () => {
  const vKp = generateKeyPair();
  const eKp = generateKeyPair();
  const endpoint = 'https://agents.docutrust.org/didcomm';

  const peerDid2 = createDidPeer2({
    verificationKeyHex: vKp.publicKeyHex,
    encryptionKeyHex: eKp.publicKeyHex,
    serviceEndpoint: endpoint
  });

  assert.ok(peerDid2.startsWith('did:peer:2.V'));
  assert.ok(peerDid2.includes('.E'));
  assert.ok(peerDid2.includes('.S'));

  const doc = await DIDResolver.resolve(peerDid2);
  assert.equal(doc.id, peerDid2);
  assert.equal(doc.verificationMethod.length, 2);
  assert.equal(doc.keyAgreement.length, 1);
  assert.equal(doc.service.length, 1);
  assert.equal(doc.service[0].serviceEndpoint, endpoint);
});

// 70. Enterprise Bitstring Status List Aggregator
test('70. Bitstring Status List Aggregator: sharded multi-partition management & root computation', () => {
  const aggregator = new BitstringStatusListAggregator(1000, 1, 'revocation');

  // Set status across multiple partitions
  aggregator.setStatus(50, 1);     // Partition 0, local index 50 -> Revoked
  aggregator.setStatus(1250, 1);   // Partition 1, local index 250 -> Revoked
  aggregator.setStatus(3500, 1);   // Partition 3, local index 500 -> Revoked

  const s0 = aggregator.getStatus(50);
  assert.equal(s0.partitionIndex, 0);
  assert.equal(s0.isRevoked, true);

  const s1 = aggregator.getStatus(1250);
  assert.equal(s1.partitionIndex, 1);
  assert.equal(s1.isRevoked, true);

  const sClean = aggregator.getStatus(100);
  assert.equal(sClean.isValid, true);
  assert.equal(sClean.isRevoked, false);

  const root = aggregator.computeAggregatedStatusRoot();
  assert.ok(typeof root === 'string' && root.length === 64);
});

// 71. EVM Solidity Sovereign Trust Registry Smart Contract Generator
test('71. SolidityEngine: generateRegistryContract emits DocuTrustRegistry.sol', () => {
  const code = SolidityEngine.generateRegistryContract({
    contractName: 'DocuTrustEnterpriseRegistry',
    solidityVersion: '^0.8.24'
  });

  assert.ok(code.includes('contract DocuTrustEnterpriseRegistry'));
  assert.ok(code.includes('registerIssuer'));
  assert.ok(code.includes('revokeIssuer'));
  assert.ok(code.includes('updateRevocationRoot'));
  assert.ok(code.includes('isIssuerAccredited'));
});

// 72. Open Badges 3.0 & Verifiable SVG Themes (obsidian-noir and royal-amethyst)
test('72. BadgeEngine: render obsidian-noir and royal-amethyst themes with validFrom fallback', async () => {
  const issuerKp = generateKeyPair();
  const { credential } = VerifiableCredentialsEngine.issue({
    type: ['VerifiableCredential', 'SecurityClearanceBadge'],
    issuer: { id: issuerKp.did },
    credentialSubject: {
      id: 'did:key:holder999',
      name: 'Agent Cipher',
      title: 'Top Secret Level 5'
    },
    keyPair: issuerKp
  });

  const svgNoir = BadgeEngine.renderBadgeSvg(credential, {
    theme: 'obsidian-noir',
    badgeTitle: 'Top Secret Level 5',
    recipientName: 'Agent Cipher'
  });
  assert.ok(svgNoir.includes('#09090b'));
  assert.ok(svgNoir.includes('Agent Cipher'));

  const verifyNoir = await BadgeEngine.verifyBadgeSvg(svgNoir);
  assert.equal(verifyNoir.valid, true);

  const svgAmethyst = BadgeEngine.renderBadgeSvg(credential, {
    theme: 'royal-amethyst',
    badgeTitle: 'Top Secret Level 5',
    recipientName: 'Agent Cipher'
  });
  assert.ok(svgAmethyst.includes('#2e1065'));

  const verifyAmethyst = await BadgeEngine.verifyBadgeSvg(svgAmethyst);
  assert.equal(verifyAmethyst.valid, true);
});

// 73. Cryptographic Linkable Ring Signatures (LSAG) (DocuTrust v10.0.0)
test('73. Linkable Ring Signatures (LSAG): 1-of-N anonymous signing, key image linkability, and loop verification', () => {
  // Generate 4 keypairs for the ring
  const kp1 = generateKeyPair();
  const kp2 = generateKeyPair();
  const kp3 = generateKeyPair();
  const kp4 = generateKeyPair();

  const ring = [kp1.publicKeyHex, kp2.publicKeyHex, kp3.publicKeyHex, kp4.publicKeyHex];
  const payload = { vote: 'PROPOSAL_DAO_UPGRADE_10', ballotId: 'urn:uuid:ballot-2026-99' };

  // Signer 3 (kp3) signs anonymously on behalf of the 4-member ring
  const sig = RingSignatureEngine.sign({
    message: payload,
    ring,
    signerPrivateKeyHex: kp3.privateKeyHex,
    signerPublicKeyHex: kp3.publicKeyHex
  });

  assert.equal(sig.type, 'DocuTrustLinkableRingSignature2026');
  assert.equal(sig.ring.length, 4);
  assert.equal(sig.responses.length, 4);
  assert.ok(sig.keyImage.length === 64);

  // Verification succeeds without revealing signer index
  const verifyResult = RingSignatureEngine.verify({
    message: payload,
    signature: sig
  });
  assert.equal(verifyResult.valid, true);
  assert.equal(verifyResult.ringSize, 4);
  assert.equal(verifyResult.isDoubleAction, false);

  // Key image double-action check
  const usedKeyImages = new Set([sig.keyImage]);
  const doubleActionResult = RingSignatureEngine.verify({
    message: payload,
    signature: sig,
    usedKeyImages
  });
  assert.equal(doubleActionResult.valid, false);
  assert.equal(doubleActionResult.isDoubleAction, true);
});

// 74. 256-bit Sparse Merkle Tree (SMT) Key Transparency & Revocation
test('74. Sparse Merkle Tree (SMT): inclusion proofs, non-membership proofs, and audit verification', () => {
  const smt = new SparseMerkleTree(256);

  const key1 = sha256Hex('did:key:alice_key_v1');
  const val1 = sha256Hex('STATUS_ACTIVE_2026');
  const key2 = sha256Hex('did:key:bob_key_v1');
  const val2 = sha256Hex('STATUS_REVOKED_2026');
  const uninsertedKey = sha256Hex('did:key:charlie_unregistered');

  smt.set(key1, val1);
  smt.set(key2, val2);

  const root = smt.getRoot();
  assert.ok(typeof root === 'string' && root.length === 64);
  assert.equal(smt.get(key1), val1);
  assert.equal(smt.get(key2), val2);
  assert.equal(smt.get(uninsertedKey), null);

  // Inclusion Proof for Key 1
  const proof1 = smt.prove(key1);
  assert.equal(proof1.exists, true);
  assert.equal(proof1.value, val1);
  const isValid1 = SparseMerkleTree.verifyProof(proof1, root);
  assert.equal(isValid1, true);

  // Non-Membership Proof for uninserted key
  const proofNonMember = smt.prove(uninsertedKey);
  assert.equal(proofNonMember.exists, false);
  const isValidNonMember = SparseMerkleTree.verifyProof(proofNonMember, root);
  assert.equal(isValidNonMember, true);
});

// 75. Extended Sovereign Policy Engine (Temporal Windows & Array Quantifiers)
test('75. PolicyEngine: evaluate valid_between, epoch_within, type_is, and array quantifiers (all_of, any_of)', () => {
  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:test-temporal-cred',
    type: ['VerifiableCredential', 'AuditReportCredential'],
    validFrom: '2026-06-15T12:00:00Z',
    credentialSubject: {
      id: 'did:key:z6MkuSubject',
      auditScore: 95,
      findings: [
        { severity: 'low', resolved: true },
        { severity: 'info', resolved: true }
      ],
      complianceTags: ['GDPR', 'SOC2', 'ISO27001']
    }
  };

  const policy = {
    id: 'policy:temporal-audit-v10',
    name: 'Advanced Temporal & Array Audit Policy',
    version: '10.0.0',
    condition: {
      operator: 'and',
      conditions: [
        {
          field: 'validFrom',
          operator: 'valid_between',
          value: ['2026-01-01T00:00:00Z', '2026-12-31T23:59:59Z']
        },
        {
          field: 'credentialSubject.auditScore',
          operator: 'type_is',
          value: 'number'
        },
        {
          field: 'credentialSubject.findings',
          operator: 'all_of',
          itemCondition: {
            field: 'resolved',
            operator: 'eq',
            value: true
          }
        },
        {
          field: 'credentialSubject.complianceTags',
          operator: 'contains',
          value: 'SOC2'
        }
      ]
    }
  };

  const result = PolicyEngine.evaluate(credential, policy);
  assert.equal(result.passed, true);
  assert.equal(result.errors.length, 0);
});

// 76. EVM Solidity SMT Verifier Smart Contract Generator
test('76. SolidityEngine: generateSMTVerifierContract emits DocuTrustSMTVerifier.sol', () => {
  const code = generateSMTVerifierContract({
    contractName: 'DocuTrustEnterpriseSMT',
    solidityVersion: '^0.8.24'
  });

  assert.ok(code.includes('contract DocuTrustEnterpriseSMT'));
  assert.ok(code.includes('computeLeafHash'));
  assert.ok(code.includes('verifySMTProof'));
  assert.ok(code.includes('SMTProofVerified'));
});

// 77. Native Universal DID Verification in verifySignature (did:peer:0 and did:jwk)
test('77. verifySignature: native public key parsing for did:peer:0 and did:jwk', () => {
  const kp = generateKeyPair();
  const message = 'DocuTrust Universal Verification 2026';
  const sig = signData(message, kp);

  // did:peer:0 verification
  const peer0 = createDidPeer0(kp.publicKeyHex);
  const isPeer0Valid = verifySignature(message, sig, peer0);
  assert.equal(isPeer0Valid, true);

  // did:jwk verification
  const jwk = createDidJwk(kp.publicKeyHex);
  const isJwkValid = verifySignature(message, sig, jwk);
  assert.equal(isJwkValid, true);
});



