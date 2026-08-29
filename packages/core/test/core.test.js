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
  MerkleMountainRange
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




