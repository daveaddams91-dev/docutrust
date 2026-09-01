const test = require('node:test');
const assert = require('node:assert/strict');
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const core = require('@docutrust/core');

const cliPath = path.join(__dirname, '../bin/docutrust.js');
const tempDir = path.join(__dirname, 'temp-' + Date.now());

test('CLI Suite', async (t) => {
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  t.after(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const keysFile = path.join(tempDir, 'issuer-keys.json');
  const pqcKeysFile = path.join(tempDir, 'pqc-keys.json');
  const subjectFile = path.join(tempDir, 'subject.json');
  const vcFile = path.join(tempDir, 'issued-vc.json');
  const batchDir = path.join(tempDir, 'batch-out');
  const csvFile = path.join(tempDir, 'students.csv');

  await t.test('1. docutrust keygen generates Ed25519 keypair file', () => {
    const out = execSync(`node "${cliPath}" keygen --out "${keysFile}"`).toString();
    assert.ok(out.includes('KeyPair generated'));
    assert.ok(fs.existsSync(keysFile));

    const keys = JSON.parse(fs.readFileSync(keysFile, 'utf-8'));
    assert.ok(keys.did.startsWith('did:key:z6M'));
    assert.equal(keys.publicKeyHex.length, 64);
  });

  await t.test('2. docutrust pqc-keygen generates ML-DSA hybrid keys', () => {
    const out = execSync(`node "${cliPath}" pqc-keygen --out "${pqcKeysFile}"`).toString();
    assert.ok(out.includes('Post-Quantum Hybrid KeyPair saved'));
    assert.ok(fs.existsSync(pqcKeysFile));

    const keys = JSON.parse(fs.readFileSync(pqcKeysFile, 'utf-8'));
    assert.ok(keys.hybridDid.startsWith('did:pqc:z'));
  });

  await t.test('3. docutrust issue creates a signed W3C credential', () => {
    fs.writeFileSync(subjectFile, JSON.stringify({
      credentialType: 'UniversityDegreeCredential',
      subject: {
        name: 'Elena Rostova',
        degree: 'Ph.D. in Computer Science',
        year: '2026'
      }
    }), 'utf-8');

    const out = execSync(`node "${cliPath}" issue --subject "${subjectFile}" --key "${keysFile}" --out "${vcFile}"`).toString();
    assert.ok(out.includes('successfully issued'));
    assert.ok(fs.existsSync(vcFile));

    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    assert.equal(vc.credentialSubject.name, 'Elena Rostova');
    assert.equal(vc.proof.type, 'Ed25519Signature2020');
  });

  await t.test('4. docutrust verify verifies issued credential offline', () => {
    const out = execSync(`node "${cliPath}" verify --vc "${vcFile}"`).toString();
    assert.ok(out.includes('VALID (Cryptographically Verified)'));
  });

  await t.test('5. docutrust batch issues credentials from CSV with Merkle root', () => {
    fs.writeFileSync(csvFile, 'name,degree,year,gpa\nAlice,B.Sc.,2026,3.9\nBob,M.Sc.,2026,3.8\n', 'utf-8');
    const out = execSync(`node "${cliPath}" batch --csv "${csvFile}" --key "${keysFile}" --out "${batchDir}"`).toString();
    assert.ok(out.includes('Batch issuance complete'));
    assert.ok(fs.existsSync(batchDir));
  });

  await t.test('6. docutrust demo executes full 10-second wizard', () => {
    const out = execSync(`node "${cliPath}" demo`).toString();
    assert.ok(out.includes('10-Second Quickstart Demo Wizard'));
    assert.ok(out.includes('100% CRYPTOGRAPHICALLY AUTHENTIC'));
  });

  const encFile = path.join(tempDir, 'encrypted.json');
  const decFile = path.join(tempDir, 'decrypted.json');
  await t.test('7. docutrust encrypt and decrypt with AES-256-GCM', () => {
    const outEnc = execSync(`node "${cliPath}" encrypt --in "${subjectFile}" --pass "TestSecretPass123!" --out "${encFile}"`).toString();
    assert.ok(outEnc.includes('File encrypted with AES-256-GCM'));
    assert.ok(fs.existsSync(encFile));

    const outDec = execSync(`node "${cliPath}" decrypt --in "${encFile}" --pass "TestSecretPass123!" --out "${decFile}"`).toString();
    assert.ok(outDec.includes('File decrypted and saved'));
    assert.ok(fs.existsSync(decFile));

    const orig = JSON.parse(fs.readFileSync(subjectFile, 'utf-8'));
    const dec = JSON.parse(fs.readFileSync(decFile, 'utf-8'));
    assert.deepEqual(orig, dec);
  });

  const zkFile = path.join(tempDir, 'zk-proof.json');
  await t.test('8. docutrust zk-range generates Zero-Knowledge Range Proof', () => {
    const out = execSync(`node "${cliPath}" zk-range --key gpa --val 3.92 --min 3.5 --max 4.0 --out "${zkFile}"`).toString();
    assert.ok(out.includes('ZK Range Proof generated'));
    assert.ok(fs.existsSync(zkFile));
    const proof = JSON.parse(fs.readFileSync(zkFile, 'utf-8'));
    assert.equal(proof.type, 'ZKRangePredicateProof2026');
  });

  const kemFile = path.join(tempDir, 'kem-keys.json');
  await t.test('9. docutrust kem-keygen generates ML-KEM-768 hybrid keypair', () => {
    const out = execSync(`node "${cliPath}" kem-keygen --out "${kemFile}"`).toString();
    assert.ok(out.includes('ML-KEM-768 KeyPair generated'));
    assert.ok(fs.existsSync(kemFile));
    const kemKeys = JSON.parse(fs.readFileSync(kemFile, 'utf-8'));
    assert.ok(kemKeys.hybridRecipientId.startsWith('did:kem:z'));
  });

  const popFile = path.join(tempDir, 'pop-challenge.json');
  await t.test('10. docutrust pop-challenge creates challenge nonce', () => {
    const out = execSync(`node "${cliPath}" pop-challenge --audience did:web:verifier.com --out "${popFile}"`).toString();
    assert.ok(out.includes('Proof-of-Possession challenge created'));
    assert.ok(fs.existsSync(popFile));
    const chal = JSON.parse(fs.readFileSync(popFile, 'utf-8'));
    assert.ok(chal.challengeId.startsWith('pop_'));
  });

  const sharesDir = path.join(tempDir, 'shares-test');
  const reconstructedKeyFile = path.join(tempDir, 'reconstructed-key.txt');
  await t.test('11. docutrust shamir-split and shamir-combine', () => {
    const secretFile = path.join(tempDir, 'secret-to-split.txt');
    fs.writeFileSync(secretFile, 'MasterVaultRootKeyPassphrase2026!', 'utf-8');

    const outSplit = execSync(`node "${cliPath}" shamir-split --key "${secretFile}" --shares 5 --threshold 3 --out "${sharesDir}"`).toString();
    assert.ok(outSplit.includes('Secret split into'));
    assert.ok(fs.existsSync(path.join(sharesDir, 'share-1.json')));

    // Delete 2 shares (shares 4 and 5) to test threshold 3 recovery
    fs.unlinkSync(path.join(sharesDir, 'share-4.json'));
    fs.unlinkSync(path.join(sharesDir, 'share-5.json'));

    const outCombine = execSync(`node "${cliPath}" shamir-combine --shares-dir "${sharesDir}" --out "${reconstructedKeyFile}"`).toString();
    assert.ok(outCombine.includes('Secret reconstructed and saved'));
    assert.equal(fs.readFileSync(reconstructedKeyFile, 'utf-8'), 'MasterVaultRootKeyPassphrase2026!');
  });

  const sdJwtFile = path.join(tempDir, 'sd-jwt.json');
  await t.test('12. docutrust to-sd-jwt and verify-sd-jwt', () => {
    const claimsFile = path.join(tempDir, 'claims-sd.json');
    fs.writeFileSync(claimsFile, JSON.stringify({ name: 'Elena Rostova', title: 'Director of Security' }), 'utf-8');

    const outIssue = execSync(`node "${cliPath}" to-sd-jwt --claims "${claimsFile}" --key "${keysFile}" --out "${sdJwtFile}"`).toString();
    assert.ok(outIssue.includes('IETF SD-JWT issued and saved'));
    assert.ok(fs.existsSync(sdJwtFile));

    const outVerify = execSync(`node "${cliPath}" verify-sd-jwt --sd-jwt "${sdJwtFile}"`).toString();
    assert.ok(outVerify.includes('VALID'));
    assert.ok(outVerify.includes('Elena Rostova'));
  });

  const bbsSigFile = path.join(tempDir, 'bbs-sig.json');
  const bbsProofFile = path.join(tempDir, 'bbs-proof.json');
  await t.test('13. docutrust bbs-issue, bbs-prove, and bbs-verify', () => {
    const messagesFile = path.join(tempDir, 'bbs-messages.json');
    fs.writeFileSync(messagesFile, JSON.stringify(['Elena Rostova', 'MIT', 'Ph.D. Quantum Computing']), 'utf-8');

    const outIssue = execSync(`node "${cliPath}" bbs-issue --messages "${messagesFile}" --out "${bbsSigFile}"`).toString();
    assert.ok(outIssue.includes('BBS+ multi-message signature issued'));
    assert.ok(fs.existsSync(bbsSigFile));

    const outProve = execSync(`node "${cliPath}" bbs-prove --sig "${bbsSigFile}" --indices 1,2 --out "${bbsProofFile}"`).toString();
    assert.ok(outProve.includes('BBS+ unlinkable ZK proof derived'));
    assert.ok(fs.existsSync(bbsProofFile));

    const outVerify = execSync(`node "${cliPath}" bbs-verify --proof "${bbsProofFile}"`).toString();
    assert.ok(outVerify.includes('CRYPTOGRAPHICALLY VALID'));
    assert.ok(outVerify.includes('MIT'));
  });

  const tsaTokenFile = path.join(tempDir, 'tsa-token.json');
  await t.test('14. docutrust oracle-timestamp generates timestamp token', () => {
    const dataFile = path.join(tempDir, 'audit-target.txt');
    fs.writeFileSync(dataFile, 'Critical Immutable Blockchain Transaction 2026', 'utf-8');

    const outTSA = execSync(`node "${cliPath}" oracle-timestamp --data "${dataFile}" --out "${tsaTokenFile}"`).toString();
    assert.ok(outTSA.includes('TSA Timestamp Token issued'));
    assert.ok(fs.existsSync(tsaTokenFile));
    const token = JSON.parse(fs.readFileSync(tsaTokenFile, 'utf-8'));
    assert.equal(token.type, 'DocuTrustTimestampToken2026');
  });

  const didcommMsgFile = path.join(tempDir, 'didcomm-msg.json');
  const didcommEnvFile = path.join(tempDir, 'didcomm-env.json');
  const didcommDecFile = path.join(tempDir, 'didcomm-dec.json');
  await t.test('15. docutrust didcomm-pack and didcomm-unpack', () => {
    const keysData = JSON.parse(fs.readFileSync(keysFile, 'utf-8'));
    fs.writeFileSync(didcommMsgFile, JSON.stringify({ id: 'msg-01', type: 'https://docutrust.org/didcomm/ping', body: { text: 'Hello Secure Agent' }, to: [keysData.did] }), 'utf-8');

    const outPack = execSync(`node "${cliPath}" didcomm-pack --msg "${didcommMsgFile}" --key "${keysFile}" --recipient-pub "${keysData.publicKeyHex}" --recipient-did "${keysData.did}" --out "${didcommEnvFile}"`).toString();
    assert.ok(outPack.includes('DIDComm v2 encrypted envelope packed'));
    assert.ok(fs.existsSync(didcommEnvFile));

    const outUnpack = execSync(`node "${cliPath}" didcomm-unpack --envelope "${didcommEnvFile}" --key "${keysFile}" --out "${didcommDecFile}"`).toString();
    assert.ok(outUnpack.includes('DIDComm v2 envelope decrypted'));
    assert.ok(fs.existsSync(didcommDecFile));
    const decrypted = JSON.parse(fs.readFileSync(didcommDecFile, 'utf-8'));
    assert.equal(decrypted.valid, true);
    assert.equal(decrypted.message.body.text, 'Hello Secure Agent');
  });

  const mmrFile = path.join(tempDir, 'mmr-entry.json');
  await t.test('16. docutrust mmr-append appends to Merkle Mountain Range', () => {
    const outMMR = execSync(`node "${cliPath}" mmr-append --leaf "Audit Leaf Stream #1" --out "${mmrFile}"`).toString();
    assert.ok(outMMR.includes('Merkle Mountain Range element appended'));
    assert.ok(fs.existsSync(mmrFile));
  });

  const zkAgeFile = path.join(tempDir, 'zk-age-proof.json');
  await t.test('17. docutrust zk-age generates Zero-Knowledge Age Predicate Proof', () => {
    const out = execSync(`node "${cliPath}" zk-age --dob 2000-01-01 --min-age 21 --ref-date 2026-08-29 --out "${zkAgeFile}"`).toString();
    assert.ok(out.includes('ZK Age Predicate Proof generated'));
    assert.ok(fs.existsSync(zkAgeFile));
    const proof = JSON.parse(fs.readFileSync(zkAgeFile, 'utf-8'));
    assert.equal(proof.type, 'ZKAgePredicateProof2026');
    assert.equal(proof.minimumAgeYears, 21);
  });

  const zkDateFile = path.join(tempDir, 'zk-date-proof.json');
  await t.test('18. docutrust zk-date generates Zero-Knowledge Date Range Proof', () => {
    const out = execSync(`node "${cliPath}" zk-date --date 2024-06-15 --min 2020-01-01 --max 2026-12-31 --out "${zkDateFile}"`).toString();
    assert.ok(out.includes('ZK Date Range Proof generated'));
    assert.ok(fs.existsSync(zkDateFile));
    const proof = JSON.parse(fs.readFileSync(zkDateFile, 'utf-8'));
    assert.equal(proof.type, 'ZKDatePredicateProof2026');
    assert.equal(proof.minDate, '2020-01-01');
    assert.equal(proof.maxDate, '2026-12-31');
  });

  const ethKeyFile = path.join(tempDir, 'eth-keys.json');
  const ethVcFile = path.join(tempDir, 'eth-vc.json');
  const ethSignedVcFile = path.join(tempDir, 'eth-signed-vc.json');
  await t.test('19. docutrust keygen-secp256k1, eip712-sign, and eip712-verify', () => {
    const outKeygen = execSync(`node "${cliPath}" keygen-secp256k1 --chain 1 --out "${ethKeyFile}"`).toString();
    assert.ok(outKeygen.includes('Ethereum secp256k1 KeyPair generated'));
    assert.ok(fs.existsSync(ethKeyFile));

    const ethKeys = JSON.parse(fs.readFileSync(ethKeyFile, 'utf-8'));
    fs.writeFileSync(ethVcFile, JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:cli-eth-01',
      issuer: ethKeys.did,
      credentialSubject: { id: 'did:pkh:eip155:1:0x999', recipient: 'Satoshi' }
    }), 'utf-8');

    const outSign = execSync(`node "${cliPath}" eip712-sign --vc "${ethVcFile}" --key "${ethKeyFile}" --out "${ethSignedVcFile}"`).toString();
    assert.ok(outSign.includes('EIP-712 Structured VC signed'));
    assert.ok(fs.existsSync(ethSignedVcFile));

    const outVerify = execSync(`node "${cliPath}" eip712-verify --vc "${ethSignedVcFile}"`).toString();
    assert.ok(outVerify.includes('VALID'));
    assert.ok(outVerify.includes(ethKeys.ethereumAddress.toLowerCase()));
  });

  const recoveryConfigFile = path.join(tempDir, 'social-recovery.json');
  await t.test('20. docutrust social-recovery-setup generates guardian config and shares', () => {
    const guardiansFile = path.join(tempDir, 'guardians.json');
    fs.writeFileSync(guardiansFile, JSON.stringify([
      { did: 'did:key:zG1', name: 'Alice' },
      { did: 'did:key:zG2', name: 'Bob' },
      { did: 'did:key:zG3', name: 'Charlie' }
    ]), 'utf-8');

    const out = execSync(`node "${cliPath}" social-recovery-setup --secret "VaultRootSecretKey" --guardians "${guardiansFile}" --threshold 2 --hours 48 --out "${recoveryConfigFile}"`).toString();
    assert.ok(out.includes('Social Recovery configured'));
    assert.ok(fs.existsSync(recoveryConfigFile));
    const setup = JSON.parse(fs.readFileSync(recoveryConfigFile, 'utf-8'));
    assert.equal(setup.guardians.length, 3);
    assert.equal(setup.config.threshold, 2);
  });

  const zkNonMemFile = path.join(tempDir, 'zk-non-membership.json');
  await t.test('21. docutrust zk-non-membership generates restricted-set exclusion proof', () => {
    const out = execSync(`node "${cliPath}" zk-non-membership --key passportId --val USER-VALID --restricted "BLOCKED-1,BLOCKED-2" --out "${zkNonMemFile}"`).toString();
    assert.ok(out.includes('ZK Non-Membership Proof saved'));
    assert.ok(fs.existsSync(zkNonMemFile));
    const proof = JSON.parse(fs.readFileSync(zkNonMemFile, 'utf-8'));
    assert.equal(proof.type, 'ZKSetNonMembershipProof2026');
  });

  const anchorPayloadFile = path.join(tempDir, 'multichain-anchor.json');
  await t.test('22. docutrust multichain-anchor formats calldata for EVM/Solana/Bitcoin', () => {
    const root = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const out = execSync(`node "${cliPath}" multichain-anchor --chain polygon --root "${root}" --count 500 --out "${anchorPayloadFile}"`).toString();
    assert.ok(out.includes('MultiChain Anchor payload generated'));
    assert.ok(fs.existsSync(anchorPayloadFile));
    const payload = JSON.parse(fs.readFileSync(anchorPayloadFile, 'utf-8'));
    assert.equal(payload.chain, 'polygon');
    assert.ok(payload.calldataHex.startsWith('0x892a4b12'));
  });

  const schemaFile = path.join(tempDir, 'schema.json');
  const dataValidFile = path.join(tempDir, 'data-valid.json');
  await t.test('23. docutrust schema-validate and schema-hash', () => {
    fs.writeFileSync(schemaFile, JSON.stringify({
      $id: 'https://schema.docutrust.org/badge.json',
      type: 'object',
      required: ['badgeCode'],
      properties: { badgeCode: { type: 'string', pattern: '^SEC-\\d+$' } }
    }), 'utf-8');

    fs.writeFileSync(dataValidFile, JSON.stringify({ badgeCode: 'SEC-402' }), 'utf-8');

    const outHash = execSync(`node "${cliPath}" schema-hash --schema "${schemaFile}"`).toString();
    assert.ok(outHash.includes('RFC 8785 Canonical Schema Hash'));

    const outVal = execSync(`node "${cliPath}" schema-validate --data "${dataValidFile}" --schema "${schemaFile}"`).toString();
    assert.ok(outVal.includes('Schema validation PASSED'));
  });

  const jweKey1File = path.join(tempDir, 'jwe-k1.json');
  const jweKey2File = path.join(tempDir, 'jwe-k2.json');
  const jwePayloadFile = path.join(tempDir, 'jwe-payload.json');
  const jweRecipientsFile = path.join(tempDir, 'jwe-recipients.json');
  const jweEncryptedFile = path.join(tempDir, 'jwe-enc.json');
  await t.test('24. docutrust jwe-keygen, jwe-encrypt, and jwe-decrypt', () => {
    execSync(`node "${cliPath}" jwe-keygen --out "${jweKey1File}"`);
    execSync(`node "${cliPath}" jwe-keygen --out "${jweKey2File}"`);
    const k1 = JSON.parse(fs.readFileSync(jweKey1File, 'utf-8'));
    const k2 = JSON.parse(fs.readFileSync(jweKey2File, 'utf-8'));

    fs.writeFileSync(jwePayloadFile, JSON.stringify({ confidentialData: 'SovereignAuditPayload2026' }), 'utf-8');
    fs.writeFileSync(jweRecipientsFile, JSON.stringify([
      { did: k1.did, publicKey: k1.publicKeyHex },
      { did: k2.did, publicKey: k2.publicKeyHex }
    ]), 'utf-8');

    const outEnc = execSync(`node "${cliPath}" jwe-encrypt --payload "${jwePayloadFile}" --recipients "${jweRecipientsFile}" --out "${jweEncryptedFile}"`).toString();
    assert.ok(outEnc.includes('Multi-Recipient JWE encrypted'));
    assert.ok(fs.existsSync(jweEncryptedFile));

    const outDec = execSync(`node "${cliPath}" jwe-decrypt --jwe "${jweEncryptedFile}" --did "${k1.did}" --key "${k1.privateKeyHex}"`).toString();
    assert.ok(outDec.includes('Decryption SUCCESS'));
    assert.ok(outDec.includes('SovereignAuditPayload2026'));
  });

  const zkInterFile = path.join(tempDir, 'zk-intersection.json');
  await t.test('25. docutrust zk-intersection generates set intersection proof', () => {
    const out = execSync(`node "${cliPath}" zk-intersection --key clearance --val LEVEL-5 --target "LEVEL-4,LEVEL-5,LEVEL-6" --out "${zkInterFile}"`).toString();
    assert.ok(out.includes('ZK Set Intersection Proof saved'));
    assert.ok(fs.existsSync(zkInterFile));
    const proof = JSON.parse(fs.readFileSync(zkInterFile, 'utf-8'));
    assert.equal(proof.type, 'ZKSetIntersectionProof2026');
  });

  const accWitnessFile = path.join(tempDir, 'acc-witness.json');
  const accNonMemWitnessFile = path.join(tempDir, 'acc-nonmem-witness.json');
  await t.test('26. docutrust accumulator commands (create, add, witness, verify, non-membership)', () => {
    const accId = 'cli_acc_test_suite';
    const createOut = execSync(`node "${cliPath}" accumulator-create --id "${accId}"`).toString();
    assert.ok(createOut.includes('Dynamic Cryptographic Accumulator initialized'));

    const addOut = execSync(`node "${cliPath}" accumulator-add --id "${accId}" --elements "member_alpha,member_beta"`).toString();
    assert.ok(addOut.includes('Added 2 element(s)'));
    const storeObj = JSON.parse(addOut.slice(addOut.indexOf('{')));

    // Membership witness
    execSync(`node "${cliPath}" accumulator-witness --id "${accId}" --element "member_alpha" --out "${accWitnessFile}"`);
    assert.ok(fs.existsSync(accWitnessFile));

    const verifyOut = execSync(`node "${cliPath}" accumulator-verify --witness "${accWitnessFile}" --acc "${storeObj.accumulator}"`).toString();
    assert.ok(verifyOut.includes('VALID'));

    // Non-membership witness
    execSync(`node "${cliPath}" accumulator-non-membership-witness --id "${accId}" --element "outsider_gamma" --out "${accNonMemWitnessFile}"`);
    assert.ok(fs.existsSync(accNonMemWitnessFile));

    const verifyNonMemOut = execSync(`node "${cliPath}" accumulator-verify-non-membership --witness "${accNonMemWitnessFile}" --acc "${storeObj.accumulator}"`).toString();
    assert.ok(verifyNonMemOut.includes('VALID'));
  });

  const slFile = path.join(tempDir, 'statuslist2024.json');
  await t.test('27. docutrust statuslist-create, statuslist-check, and statuslist-update', () => {
    execSync(`node "${cliPath}" statuslist-create --length 1000 --size 2 --purpose revocation --out "${slFile}"`);
    assert.ok(fs.existsSync(slFile));

    const checkOut = execSync(`node "${cliPath}" statuslist-check --list "${slFile}" --index 15 --size 2`).toString();
    assert.ok(checkOut.includes('Status at index 15:') && checkOut.includes('Valid: true'));

    execSync(`node "${cliPath}" statuslist-update --list "${slFile}" --index 15 --status 1 --size 2 --out "${slFile}"`);
    const checkAfterUpdate = execSync(`node "${cliPath}" statuslist-check --list "${slFile}" --index 15 --size 2`).toString();
    assert.ok(checkAfterUpdate.includes('Status at index 15:') && checkAfterUpdate.includes('Revoked: true'));
  });

  const peDefFile = path.join(tempDir, 'pe-def.json');
  const peDescFile = path.join(tempDir, 'pe-desc.json');
  const presFile = path.join(tempDir, 'presentation.json');
  await t.test('28. docutrust pe-definition-create and pe-evaluate', () => {
    fs.writeFileSync(peDescFile, JSON.stringify([
      {
        id: 'university_degree_desc',
        schema: [{ uri: 'UniversityDegreeCredential' }],
        constraints: {
          fields: [{ path: ['$.credentialSubject.degree'] }]
        }
      }
    ]), 'utf-8');

    execSync(`node "${cliPath}" pe-definition-create --id "employment_def" --descriptors "${peDescFile}" --name "Employment Check" --out "${peDefFile}"`);
    assert.ok(fs.existsSync(peDefFile));

    fs.writeFileSync(presFile, JSON.stringify({
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
          credentialSubject: { degree: 'M.Sc. Cybersecurity' }
        }
      ]
    }), 'utf-8');

    const evalOut = execSync(`node "${cliPath}" pe-evaluate --presentation "${presFile}" --definition "${peDefFile}"`).toString();
    assert.ok(evalOut.includes('Presentation Exchange Evaluation PASSED'));
  });

  const zkMemProofFile = path.join(tempDir, 'zk-mem-proof.json');
  const zkCompFile = path.join(tempDir, 'zk-comp-proof.json');
  await t.test('29. docutrust zk-membership and zk-composite', () => {
    execSync(`node "${cliPath}" zk-membership --key role --val AUDITOR --allowed "ADMIN,AUDITOR,DEV" --out "${zkMemProofFile}"`);
    assert.ok(fs.existsSync(zkMemProofFile));

    execSync(`node "${cliPath}" zk-composite --proofs "${zkMemProofFile},${zkInterFile}" --out "${zkCompFile}"`);
    assert.ok(fs.existsSync(zkCompFile));
    const compProof = JSON.parse(fs.readFileSync(zkCompFile, 'utf-8'));
    assert.equal(compProof.type, 'ZKCompositePredicateProof2026');
    assert.equal(compProof.proofs.length, 2);
  });

  const zkGraphProofFile = path.join(tempDir, 'zk-graph-proof.json');
  const zkGraphRootFile = path.join(tempDir, 'zk-graph-root.json');
  await t.test('30. docutrust zk-graph-prove, zk-graph-verify, and schema-validate-credential', () => {
    const memProof = JSON.parse(fs.readFileSync(zkMemProofFile, 'utf-8'));
    fs.writeFileSync(zkGraphRootFile, JSON.stringify({
      id: 'root_policy',
      operator: 'AND',
      children: [
        { id: 'leaf_mem', proof: memProof }
      ]
    }), 'utf-8');

    execSync(`node "${cliPath}" zk-graph-prove --id "graph_cli_01" --root "${zkGraphRootFile}" --out "${zkGraphProofFile}"`);
    assert.ok(fs.existsSync(zkGraphProofFile));

    const verifyOut = execSync(`node "${cliPath}" zk-graph-verify --proof "${zkGraphProofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));

    // schema-validate-credential
    const diplomaSchemaFile = path.join(tempDir, 'diploma-schema.json');
    fs.writeFileSync(diplomaSchemaFile, JSON.stringify({
      $id: 'https://schema.docutrust.org/diploma.json',
      type: 'object',
      required: ['name', 'degree'],
      properties: {
        name: { type: 'string' },
        degree: { type: 'string' },
        year: { type: 'string' }
      }
    }), 'utf-8');
    const valCredOut = execSync(`node "${cliPath}" schema-validate-credential --credential "${vcFile}" --schema "${diplomaSchemaFile}"`).toString();
    assert.ok(valCredOut.includes('PASSED'));
  });

  const anonReqFile = path.join(tempDir, 'anon-req.json');
  const anonClaimsFile = path.join(tempDir, 'anon-claims.json');
  const anonCredFile = path.join(tempDir, 'anon-cred.json');
  const anonUnblindFile = path.join(tempDir, 'anon-unblind.json');
  const anonPresFile = path.join(tempDir, 'anon-pres.json');
  await t.test('31. docutrust anoncreds commands (request, issue, unblind, derive-proof, verify)', () => {
    fs.writeFileSync(anonClaimsFile, JSON.stringify({ studentName: 'Alice', degree: 'Ph.D. Quantum Computing' }), 'utf-8');

    // 1. Blind Request
    const reqOut = execSync(`node "${cliPath}" anoncreds-blind-request --schema "schema:degree" --issuer "did:key:zIssuer" --out "${anonReqFile}"`).toString();
    assert.ok(reqOut.includes('Blind Request generated'));
    const reqData = JSON.parse(fs.readFileSync(anonReqFile, 'utf-8'));

    // 2. Blind Issue
    const issueOut = execSync(`node "${cliPath}" anoncreds-blind-issue --req "${anonReqFile}" --claims "${anonClaimsFile}" --key "${keysFile}" --out "${anonCredFile}"`).toString();
    assert.ok(issueOut.includes('Blind Credential issued'));

    // 3. Unblind
    const unblindOut = execSync(`node "${cliPath}" anoncreds-unblind --cred "${anonCredFile}" --secret "${reqData.masterSecret}" --blinding "${reqData.blindingFactor}" --out "${anonUnblindFile}"`).toString();
    assert.ok(unblindOut.includes('unblinded'));

    // 4. Derive Proof
    const nonce = 'cli-test-nonce-123';
    const deriveOut = execSync(`node "${cliPath}" anoncreds-derive-proof --cred "${anonUnblindFile}" --secret "${reqData.masterSecret}" --reveal "degree" --nonce "${nonce}" --out "${anonPresFile}"`).toString();
    assert.ok(deriveOut.includes('ZK Presentation derived'));

    // 5. Verify Presentation
    const keys = JSON.parse(fs.readFileSync(keysFile, 'utf-8'));
    const verifyOut = execSync(`node "${cliPath}" anoncreds-verify --pres "${anonPresFile}" --nonce "${nonce}" --issuer "${keys.did}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  const dkgCeremonyFile = path.join(tempDir, 'dkg-ceremony.json');
  const dkgShare1SigFile = path.join(tempDir, 'dkg-s1.json');
  const dkgShare2SigFile = path.join(tempDir, 'dkg-s2.json');
  const dkgAggSigFile = path.join(tempDir, 'dkg-agg.json');
  await t.test('32. docutrust dkg commands (setup, sign-share, aggregate, verify)', () => {
    // 1. Setup Ceremony (2-of-3)
    const setupOut = execSync(`node "${cliPath}" dkg-setup --nodes 3 --threshold 2 --out "${dkgCeremonyFile}"`).toString();
    assert.ok(setupOut.includes('DKG Ceremony completed'));
    const ceremony = JSON.parse(fs.readFileSync(dkgCeremonyFile, 'utf-8'));

    // 2. Sign Shares
    const msg = 'Ledger Root Hash 0x123456';
    execSync(`node "${cliPath}" dkg-sign-share --index 1 --share "${ceremony.participants[0].privateShareHex}" --did "${ceremony.participants[0].did}" --msg "${msg}" --out "${dkgShare1SigFile}"`);
    execSync(`node "${cliPath}" dkg-sign-share --index 2 --share "${ceremony.participants[1].privateShareHex}" --did "${ceremony.participants[1].did}" --msg "${msg}" --out "${dkgShare2SigFile}"`);

    // 3. Aggregate
    const aggOut = execSync(`node "${cliPath}" dkg-aggregate --pub "${ceremony.groupPublicKeyHex}" --did "${ceremony.groupDid}" --threshold 2 --shares "${dkgShare1SigFile},${dkgShare2SigFile}" --out "${dkgAggSigFile}"`).toString();
    assert.ok(aggOut.includes('Aggregated FROST signature created'));

    // 4. Verify
    const verifyOut = execSync(`node "${cliPath}" dkg-verify --sig "${dkgAggSigFile}" --msg "${msg}" --pub "${ceremony.groupPublicKeyHex}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  const solVerifierFile = path.join(tempDir, 'CustomVerifier.sol');
  const merkleProofFile = path.join(tempDir, 'merkle-proof.json');
  await t.test('33. docutrust solidity commands (export-verifier, calldata)', () => {
    // 1. Export Verifier
    const expOut = execSync(`node "${cliPath}" solidity-export-verifier --name "CustomVerifier" --out "${solVerifierFile}"`).toString();
    assert.ok(expOut.includes('Solidity Verifier Smart Contract exported'));
    assert.ok(fs.existsSync(solVerifierFile));

    // 2. Calldata encoding
    fs.writeFileSync(merkleProofFile, JSON.stringify([
      { position: 'left', data: '0000000000000000000000000000000000000000000000000000000000000001' }
    ]), 'utf-8');
    const callOut = execSync(`node "${cliPath}" solidity-calldata --leaf "0000000000000000000000000000000000000000000000000000000000000002" --proof "${merkleProofFile}" --root "0000000000000000000000000000000000000000000000000000000000000003"`).toString();
    assert.ok(callOut.includes('calldataHex'));
  });

  const auditBundleFile = path.join(tempDir, 'audit.dtbundle');
  await t.test('34. docutrust audit-bundle commands (create, verify)', () => {
    // 1. Create
    const createOut = execSync(`node "${cliPath}" audit-bundle-create --org "DocuTrust Global" --key "${keysFile}" --out "${auditBundleFile}"`).toString();
    assert.ok(createOut.includes('.dtbundle'));
    assert.ok(fs.existsSync(auditBundleFile));

    // 2. Verify
    const keys = JSON.parse(fs.readFileSync(keysFile, 'utf-8'));
    const verifyOut = execSync(`node "${cliPath}" audit-bundle-verify --bundle "${auditBundleFile}" --pub "${keys.publicKeyHex}"`).toString();
    assert.ok(verifyOut.includes('PASSED'));
  });

  const diClaimsFile = path.join(tempDir, 'di-claims.json');
  const diVcFile = path.join(tempDir, 'di-vc.json');
  await t.test('35. docutrust dataintegrity commands (issue, verify)', () => {
    fs.writeFileSync(diClaimsFile, JSON.stringify({ employee: 'Bob', clearance: 'TopSecret' }), 'utf-8');

    // 1. Issue
    const issueOut = execSync(`node "${cliPath}" dataintegrity-issue --claims "${diClaimsFile}" --key "${keysFile}" --suite "eddsa-jcs-2022" --out "${diVcFile}"`).toString();
    assert.ok(issueOut.includes('DataIntegrityProof VC issued'));
    assert.ok(fs.existsSync(diVcFile));

    // 2. Verify
    const verifyOut = execSync(`node "${cliPath}" dataintegrity-verify --vc "${diVcFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  const confKeyFile = path.join(tempDir, 'conf-key.json');
  const confClaimFile = path.join(tempDir, 'conf-claim.json');
  const confProofFile = path.join(tempDir, 'conf-proof.json');
  await t.test('36. docutrust confidential commands (keygen, encrypt, sum, threshold-prove, threshold-verify)', () => {
    // 1. Keygen
    const keygenOut = execSync(`node "${cliPath}" confidential-keygen --bits 128 --out "${confKeyFile}"`).toString();
    assert.ok(keygenOut.includes('Paillier') && keygenOut.includes('Homomorphic KeyPair'));
    assert.ok(fs.existsSync(confKeyFile));

    // 2. Encrypt
    const encOut = execSync(`node "${cliPath}" confidential-encrypt --key salary --val 125000 --pub "${confKeyFile}" --out "${confClaimFile}"`).toString();
    assert.ok(encOut.includes('Homomorphic claim'));
    assert.ok(fs.existsSync(confClaimFile));

    // 3. Prove Threshold
    const proveOut = execSync(`node "${cliPath}" confidential-threshold-prove --key salary --val 125000 --threshold 100000 --op gte --pub "${confKeyFile}" --out "${confProofFile}"`).toString();
    assert.ok(proveOut.includes('Proof generated'));
    assert.ok(fs.existsSync(confProofFile));

    // 4. Verify Threshold
    const verifyOut = execSync(`node "${cliPath}" confidential-threshold-verify --proof "${confProofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  const jsonldDocFile = path.join(tempDir, 'jsonld-doc.json');
  const jsonldSignedFile = path.join(tempDir, 'jsonld-signed.json');
  await t.test('37. docutrust jsonld commands (canonicalize, sign, verify)', () => {
    fs.writeFileSync(jsonldDocFile, JSON.stringify({
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "urn:uuid:cli-jsonld-01",
      "type": ["VerifiableCredential"],
      "issuer": "did:key:z6Mku7V2K3pB58X9zW",
      "credentialSubject": { "name": "Eve Developer", "role": "Architect" }
    }), 'utf-8');

    // 1. Canonicalize
    const canonOut = execSync(`node "${cliPath}" jsonld-canonicalize --in "${jsonldDocFile}"`).toString();
    assert.ok(canonOut.includes('Dataset Digest (SHA-256):'));

    // 2. Sign
    const signOut = execSync(`node "${cliPath}" jsonld-sign --in "${jsonldDocFile}" --key "${keysFile}" --out "${jsonldSignedFile}"`).toString();
    assert.ok(signOut.includes('Linked Data Document signed'));
    assert.ok(fs.existsSync(jsonldSignedFile));

    // 3. Verify
    const keys = JSON.parse(fs.readFileSync(keysFile, 'utf-8'));
    const verifyOut = execSync(`node "${cliPath}" jsonld-verify --in "${jsonldSignedFile}" --pub "${keys.publicKeyHex}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  const rootKeyFile = path.join(tempDir, 'root-key.json');
  const regKeyFile = path.join(tempDir, 'reg-key.json');
  const delTokenFile = path.join(tempDir, 'del-token.json');
  await t.test('38. docutrust trustchain commands (create-token, verify-token, verify-chain)', () => {
    execSync(`node "${cliPath}" keygen --out "${rootKeyFile}"`);
    execSync(`node "${cliPath}" keygen --out "${regKeyFile}"`);
    const regKeys = JSON.parse(fs.readFileSync(regKeyFile, 'utf-8'));

    // 1. Create Delegation Token
    const createOut = execSync(`node "${cliPath}" trustchain-create-token --key "${rootKeyFile}" --delegate "${regKeys.did}" --types "UniversityDegreeCredential,*" --depth 2 --out "${delTokenFile}"`).toString();
    assert.ok(createOut.includes('Delegation Token created'));
    assert.ok(fs.existsSync(delTokenFile));

    // 2. Verify Delegation Token
    const rootKeys = JSON.parse(fs.readFileSync(rootKeyFile, 'utf-8'));
    const verifyOut = execSync(`node "${cliPath}" trustchain-verify-token --token "${delTokenFile}" --pub "${rootKeys.publicKeyHex}"`).toString();
    assert.ok(verifyOut.includes('VALID'));

    // 3. Verify Trust Chain
    const chainOut = execSync(`node "${cliPath}" trustchain-verify-chain --tokens "${delTokenFile}" --root "${rootKeys.did}" --issuer "${regKeys.did}"`).toString();
    assert.ok(chainOut.includes('VALID'));
  });

  const armorKeyFile = path.join(tempDir, 'armor-key.json');
  const secretDataFile = path.join(tempDir, 'secret-data.json');
  const sealedEnvFile = path.join(tempDir, 'sealed-env.json');
  const unsealedFile = path.join(tempDir, 'unsealed.json');
  await t.test('39. docutrust quantum-armor commands (keygen, seal, unseal)', () => {
    // 1. Keygen
    const keygenOut = execSync(`node "${cliPath}" quantum-armor-keygen --out "${armorKeyFile}"`).toString();
    assert.ok(keygenOut.includes('Dual Hybrid KEM KeyPair generated'));
    assert.ok(fs.existsSync(armorKeyFile));

    // 2. Seal
    fs.writeFileSync(secretDataFile, JSON.stringify({ mission: 'Artemis IV', clearance: 'L5' }), 'utf-8');
    const sealOut = execSync(`node "${cliPath}" quantum-armor-seal --in "${secretDataFile}" --key "${armorKeyFile}" --out "${sealedEnvFile}"`).toString();
    assert.ok(sealOut.includes('Quantum-Sealed Envelope created'));
    assert.ok(fs.existsSync(sealedEnvFile));

    // 3. Unseal
    const unsealOut = execSync(`node "${cliPath}" quantum-armor-unseal --in "${sealedEnvFile}" --key "${armorKeyFile}" --out "${unsealedFile}"`).toString();
    assert.ok(unsealOut.includes('Envelope unsealed'));
    assert.ok(fs.existsSync(unsealedFile));

    const unsealed = JSON.parse(fs.readFileSync(unsealedFile, 'utf-8'));
    assert.equal(unsealed.mission, 'Artemis IV');
  });

  const batchWitFile = path.join(tempDir, 'batch-witness.json');
  await t.test('40. docutrust accumulator batch-witness and verify-batch', () => {
    // 1. Create accumulator
    execSync(`node "${cliPath}" accumulator-create --id batch-cli-acc --elements "doc-1,doc-2,doc-3"`);

    // 2. Generate batch witness
    const witOut = execSync(`node "${cliPath}" accumulator-batch-witness --id batch-cli-acc --elements "doc-1,doc-3" --out "${batchWitFile}"`).toString();
    assert.ok(witOut.includes('Batch Membership Witness saved'));
    assert.ok(fs.existsSync(batchWitFile));

    // 3. Verify batch witness
    const verifyOut = execSync(`node "${cliPath}" accumulator-verify-batch --witness "${batchWitFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  const paillierKeyFile = path.join(tempDir, 'paillier-key.json');
  const claimAFile = path.join(tempDir, 'claim-a.json');
  const claimBFile = path.join(tempDir, 'claim-b.json');
  const lincombFile = path.join(tempDir, 'lincomb.json');
  await t.test('41. docutrust confidential-linear-combination', () => {
    execSync(`node "${cliPath}" confidential-keygen --bits 256 --out "${paillierKeyFile}"`);
    execSync(`node "${cliPath}" confidential-encrypt --key salary --value 100 --pub "${paillierKeyFile}" --out "${claimAFile}"`);
    execSync(`node "${cliPath}" confidential-encrypt --key bonus --value 20 --pub "${paillierKeyFile}" --out "${claimBFile}"`);

    const linOut = execSync(`node "${cliPath}" confidential-linear-combination --terms "${claimAFile}:2,${claimBFile}:3" --pub "${paillierKeyFile}" --out "${lincombFile}"`).toString();
    assert.ok(linOut.includes('Homomorphic linear combination computed'));
    assert.ok(fs.existsSync(lincombFile));
  });

  const jwkKeyFile = path.join(tempDir, 'jwk-key.json');
  const badgeCredFile = path.join(tempDir, 'badge-cred.json');
  const badgeSvgFile = path.join(tempDir, 'badge.svg');
  await t.test('42. docutrust did-jwk and badge commands (badge-render, badge-verify)', () => {
    // 1. did-jwk
    fs.writeFileSync(jwkKeyFile, JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    }), 'utf-8');
    const jwkOut = execSync(`node "${cliPath}" did-jwk --jwk "${jwkKeyFile}"`).toString();
    assert.ok(jwkOut.includes('did:jwk:'));

    // 2. Issue credential for badge
    const badgeSubjectFile = path.join(tempDir, 'badge-subject.json');
    fs.writeFileSync(badgeSubjectFile, JSON.stringify({
      credentialType: 'DegreeCredential',
      subject: {
        id: 'did:key:z6MkuStudent',
        degree: 'MSc Cryptography',
        recipient: 'Alice'
      }
    }), 'utf-8');
    execSync(`node "${cliPath}" issue --subject "${badgeSubjectFile}" --key "${keysFile}" --out "${badgeCredFile}"`);

    // 3. badge-render
    const renderOut = execSync(`node "${cliPath}" badge-render --credential "${badgeCredFile}" --theme emerald-cert --title "MSc Cryptography" --recipient "Alice" --out "${badgeSvgFile}"`).toString();
    assert.ok(renderOut.includes('Verifiable SVG Badge generated'));
    assert.ok(fs.existsSync(badgeSvgFile));

    // 4. badge-verify
    const verifyOut = execSync(`node "${cliPath}" badge-verify --svg "${badgeSvgFile}"`).toString();
    assert.ok(verifyOut.includes('AUTHENTIC & VALID'));
  });

  const policyFile = path.join(tempDir, 'policy.json');
  const policyOutFile = path.join(tempDir, 'policy-out.json');
  const didPeer0Out = path.join(tempDir, 'did-peer-0.json');
  const didPeer2Out = path.join(tempDir, 'did-peer-2.json');
  const registrySolFile = path.join(tempDir, 'DocuTrustGov.sol');
  const slPart1File = path.join(tempDir, 'sl-part1.json');
  const slPart2File = path.join(tempDir, 'sl-part2.json');

  await t.test('43. docutrust v9.0.0 commands (policy-evaluate, policy-verify-receipt, did-peer-create, solidity-export-registry, statuslist-aggregate-check)', () => {
    // 1. policy-evaluate and policy-verify-receipt
    fs.writeFileSync(policyFile, JSON.stringify({
      id: 'policy-clearance-v9',
      name: 'Security Clearance Check',
      condition: {
        operator: 'and',
        conditions: [
          { field: 'credentialSubject.degree', operator: 'contains', value: 'Cryptography' }
        ]
      }
    }), 'utf-8');

    const polEvalOut = execSync(`node "${cliPath}" policy-evaluate --payload "${badgeCredFile}" --policy "${policyFile}" --key "${keysFile}" --out "${policyOutFile}"`).toString();
    assert.ok(polEvalOut.includes('Policy Evaluation PASSED'));
    assert.ok(fs.existsSync(policyOutFile));

    const evalResult = JSON.parse(fs.readFileSync(policyOutFile, 'utf-8'));
    assert.strictEqual(evalResult.passed, true);
    assert.ok(evalResult.receipt);

    const receiptFile = path.join(tempDir, 'receipt.json');
    fs.writeFileSync(receiptFile, JSON.stringify(evalResult.receipt), 'utf-8');

    const receiptVerifyOut = execSync(`node "${cliPath}" policy-verify-receipt --receipt "${receiptFile}"`).toString();
    assert.ok(receiptVerifyOut.includes('AUTHENTIC & VALID'));

    // 2. did-peer-create
    const peer0Out = execSync(`node "${cliPath}" did-peer-create --method 0 --out "${didPeer0Out}"`).toString();
    assert.ok(peer0Out.includes('did:peer:0z'));
    assert.ok(fs.existsSync(didPeer0Out));

    const peer2Out = execSync(`node "${cliPath}" did-peer-create --method 2 --service "https://service.docutrust.org" --out "${didPeer2Out}"`).toString();
    assert.ok(peer2Out.includes('did:peer:2.V'));
    assert.ok(fs.existsSync(didPeer2Out));

    // 3. solidity-export-registry
    const solOut = execSync(`node "${cliPath}" solidity-export-registry --name DocuTrustGov --out "${registrySolFile}"`).toString();
    assert.ok(solOut.includes('Solidity Trust Registry smart contract exported'));
    assert.ok(fs.existsSync(registrySolFile));
    const solCode = fs.readFileSync(registrySolFile, 'utf-8');
    assert.ok(solCode.includes('contract DocuTrustGov'));
    assert.ok(solCode.includes('registerIssuer'));

    // 4. statuslist-aggregate-check
    const bsl1 = new core.BitstringStatusList2024(1000, 1, 'revocation');
    const bsl2 = new core.BitstringStatusList2024(1000, 1, 'revocation');
    bsl2.setStatus(5, 1);

    const sl1 = { id: 'urn:sl:1', partitionIndex: 0, partitionSize: 1000, encodedList: bsl1.encode(true) };
    const sl2 = { id: 'urn:sl:2', partitionIndex: 1, partitionSize: 1000, encodedList: bsl2.encode(true) };
    fs.writeFileSync(slPart1File, JSON.stringify(sl1), 'utf-8');
    fs.writeFileSync(slPart2File, JSON.stringify(sl2), 'utf-8');

    const coreAggregator = new core.BitstringStatusListAggregator();
    coreAggregator.addPartition(sl1);
    coreAggregator.addPartition(sl2);
    const expectedRoot = coreAggregator.getAggregateRoot();

    const aggOut = execSync(`node "${cliPath}" statuslist-aggregate-check --root "${expectedRoot}" --lists "${slPart1File},${slPart2File}"`).toString();
    assert.ok(aggOut.includes('Status List Multi-Partition Root matches'));
  });

  await t.test('29. docutrust version displays v19.0.0', () => {
    const out1 = execSync(`node "${cliPath}" version`).toString().trim();
    assert.equal(out1, '19.0.0');

    const out2 = execSync(`node "${cliPath}" --version`).toString().trim();
    assert.equal(out2, '19.0.0');

    const out3 = execSync(`node "${cliPath}" -v`).toString().trim();
    assert.equal(out3, '19.0.0');
  });

  await t.test('30. docutrust ringsig-sign and ringsig-verify (Linkable Ring Signatures)', () => {
    const kp1 = core.generateKeyPair();
    const kp2 = core.generateKeyPair();
    const kp3 = core.generateKeyPair();

    const ringList = `${kp1.publicKeyHex},${kp2.publicKeyHex},${kp3.publicKeyHex}`;
    const voteMsg = 'PROPOSAL_GLOBAL_PRIVACY_V10';
    const sigOut = path.join(tempDir, 'ringsig.json');

    const signOut = execSync(`node "${cliPath}" ringsig-sign --msg "${voteMsg}" --ring "${ringList}" --key "${kp2.privateKeyHex}" --pub "${kp2.publicKeyHex}" --out "${sigOut}"`).toString();
    assert.ok(signOut.includes('Linkable Ring Signature generated'));
    assert.ok(fs.existsSync(sigOut));

    const verifyOut = execSync(`node "${cliPath}" ringsig-verify --msg "${voteMsg}" --sig "${sigOut}"`).toString();
    assert.ok(verifyOut.includes('VALID & ANONYMOUS'));
    assert.ok(verifyOut.includes('Ring Size: 3 participants'));
  });

  await t.test('31. docutrust smt-set, smt-prove, smt-verify (256-bit Sparse Merkle Trees)', () => {
    const stateFile = path.join(tempDir, 'smt-test-state.json');
    const proofFile = path.join(tempDir, 'smt-test-proof.json');

    const setOut = execSync(`node "${cliPath}" smt-set --key "did:key:alice_10" --val "ACTIVE_STATUS" --state "${stateFile}"`).toString();
    assert.ok(setOut.includes('SMT updated. New Root:'));

    const proveOut = execSync(`node "${cliPath}" smt-prove --key "did:key:alice_10" --state "${stateFile}" --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('SMT Inclusion proof saved'));
    assert.ok(fs.existsSync(proofFile));

    const verifyOut = execSync(`node "${cliPath}" smt-verify --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('CRYPTOGRAPHICALLY VALID'));
    assert.ok(verifyOut.includes('INCLUDED'));
  });

  await t.test('32. docutrust solidity-export-smt generates DocuTrustSMTVerifier.sol', () => {
    const smtSolFile = path.join(tempDir, 'DocuTrustSMTVerifier.sol');
    const out = execSync(`node "${cliPath}" solidity-export-smt --name DocuTrustSMTVerifier --out "${smtSolFile}"`).toString();
    assert.ok(out.includes('Solidity SMT Verifier smart contract exported'));
    assert.ok(fs.existsSync(smtSolFile));

    const code = fs.readFileSync(smtSolFile, 'utf-8');
    assert.ok(code.includes('contract DocuTrustSMTVerifier'));
    assert.ok(code.includes('verifySMTProof'));
  });

  await t.test('33. docutrust slhdsa-keygen, slhdsa-sign, and slhdsa-verify', () => {
    const slhKpFile = path.join(tempDir, 'slh-keypair.json');
    const slhSigFile = path.join(tempDir, 'slh-sig.json');
    const message = 'SLH-DSA CLI Test Message';

    const keygenOut = execSync(`node "${cliPath}" slhdsa-keygen --out "${slhKpFile}"`).toString();
    assert.ok(keygenOut.includes('SLH-DSA-SHA2-128s KeyPair generated'));
    assert.ok(fs.existsSync(slhKpFile));

    const signOut = execSync(`node "${cliPath}" slhdsa-sign --msg "${message}" --key "${slhKpFile}" --out "${slhSigFile}"`).toString();
    assert.ok(signOut.includes('Message signed with NIST FIPS 205 SLH-DSA'));
    assert.ok(fs.existsSync(slhSigFile));

    const verifyOut = execSync(`node "${cliPath}" slhdsa-verify --msg "${message}" --sig "${slhSigFile}" --pub "${slhKpFile}"`).toString();
    assert.ok(verifyOut.includes('100% CRYPTOGRAPHICALLY AUTHENTIC'));
  });

  await t.test('34. docutrust webauthn-keygen, webauthn-assert, and webauthn-verify', () => {
    const passkeyFile = path.join(tempDir, 'passkey.json');
    const assertFile = path.join(tempDir, 'assertion.json');
    const challenge = 'cli-passkey-challenge-77';

    const keygenOut = execSync(`node "${cliPath}" webauthn-keygen --rp "cli.docutrust.id" --out "${passkeyFile}"`).toString();
    assert.ok(keygenOut.includes('WebAuthn P-256 Passkey KeyPair generated'));
    assert.ok(fs.existsSync(passkeyFile));

    const assertOut = execSync(`node "${cliPath}" webauthn-assert --challenge "${challenge}" --key "${passkeyFile}" --rp "cli.docutrust.id" --out "${assertFile}"`).toString();
    assert.ok(assertOut.includes('Hardware WebAuthn Passkey Assertion created'));
    assert.ok(fs.existsSync(assertFile));

    const verifyOut = execSync(`node "${cliPath}" webauthn-verify --assertion "${assertFile}" --challenge "${challenge}" --pub "${passkeyFile}" --rp "cli.docutrust.id"`).toString();
    assert.ok(verifyOut.includes('AUTHENTIC'));
    assert.ok(verifyOut.includes('User Present (UP): YES'));
  });

  await t.test('35. docutrust crosschain-bridge, crosschain-sign, and crosschain-verify', () => {
    const msgFile = path.join(tempDir, 'bridge-msg.json');
    const sigFile = path.join(tempDir, 'relayer-sig.json');
    const attestFile = path.join(tempDir, 'bridge-attestation.json');
    const relayerKpFile = path.join(tempDir, 'relayer-keys.json');

    execSync(`node "${cliPath}" keygen --out "${relayerKpFile}"`);
    const relayerKp = JSON.parse(fs.readFileSync(relayerKpFile, 'utf-8'));

    const bridgeOut = execSync(`node "${cliPath}" crosschain-bridge --source 1 --dest 42161 --nonce 10 --root "${'0x' + 'c'.repeat(64)}" --payload "${'0x' + 'd'.repeat(64)}" --out "${msgFile}"`).toString();
    assert.ok(bridgeOut.includes('Cross-Chain Bridge Message constructed'));

    const signOut = execSync(`node "${cliPath}" crosschain-sign --msg "${msgFile}" --relayer "${relayerKpFile}" --out "${sigFile}"`).toString();
    assert.ok(signOut.includes('Relayer signed cross-chain message'));

    const msg = JSON.parse(fs.readFileSync(msgFile, 'utf-8'));
    const sig = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
    const attestation = core.CrossChainBridgeEngine.assembleAttestation(msg, [sig], 1);
    fs.writeFileSync(attestFile, JSON.stringify(attestation, null, 2), 'utf-8');

    const verifyOut = execSync(`node "${cliPath}" crosschain-verify --attestation "${attestFile}" --relayers "${relayerKp.publicKeyHex}"`).toString();
    assert.ok(verifyOut.includes('VALID & QUORUM SATISFIED'));
  });

  await t.test('36. docutrust groth16-setup, groth16-prove, and groth16-verify', () => {
    const vkFile = path.join(tempDir, 'circuit.vk.json');
    const proofFile = path.join(tempDir, 'circuit.proof.json');

    const setupOut = execSync(`node "${cliPath}" groth16-setup --circuit "IdentityCompliance" --inputs 2 --out "${vkFile}"`).toString();
    assert.ok(setupOut.includes('Groth16 Verification Key generated'));

    const proveOut = execSync(`node "${cliPath}" groth16-prove --circuit "IdentityCompliance" --inputs "100,200" --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('Zero-Knowledge Groth16 Proof generated'));

    const verifyOut = execSync(`node "${cliPath}" groth16-verify --proof "${proofFile}" --vk "${vkFile}"`).toString();
    assert.ok(verifyOut.includes('CRYPTOGRAPHICALLY VALID'));
  });

  await t.test('37. docutrust solidity-export-bridge and solidity-export-groth16', () => {
    const bridgeSol = path.join(tempDir, 'DocuTrustBridgeRelayer.sol');
    const grothSol = path.join(tempDir, 'DocuTrustGroth16Verifier.sol');

    const bOut = execSync(`node "${cliPath}" solidity-export-bridge --out "${bridgeSol}"`).toString();
    assert.ok(bOut.includes('Solidity Cross-Chain Bridge Relayer smart contract exported'));
    assert.ok(fs.existsSync(bridgeSol));

    const gOut = execSync(`node "${cliPath}" solidity-export-groth16 --out "${grothSol}"`).toString();
    assert.ok(gOut.includes('Solidity Groth16 Verifier smart contract exported'));
    assert.ok(fs.existsSync(grothSol));
  });

  await t.test('38. docutrust trustscore-eval & trustscore-verify', () => {
    const credFile = path.join(tempDir, 'score-cred.json');
    const evalKeyFile = path.join(tempDir, 'eval-keys.json');
    const receiptFile = path.join(tempDir, 'score-receipt.json');

    execSync(`node "${cliPath}" keygen --out "${evalKeyFile}"`);
    const cred = {
      id: 'urn:uuid:cred-cli-001',
      issuer: 'did:key:z6MkuIssuer',
      validFrom: new Date().toISOString(),
      proof: { type: 'Ed25519Signature2020', proofValue: 'signature' }
    };
    fs.writeFileSync(credFile, JSON.stringify(cred, null, 2), 'utf-8');

    const evalOut = execSync(`node "${cliPath}" trustscore-eval --credential "${credFile}" --min-score 500 --key "${evalKeyFile}" --out "${receiptFile}"`).toString();
    assert.ok(evalOut.includes('Trust & Risk Score Evaluation Completed'));
    assert.ok(fs.existsSync(receiptFile));

    const verifyOut = execSync(`node "${cliPath}" trustscore-verify --receipt "${receiptFile}" --evaluator-key "${evalKeyFile}"`).toString();
    assert.ok(verifyOut.includes('DocuTrust Risk Receipt is'));
    assert.ok(verifyOut.includes('CRYPTOGRAPHICALLY VALID'));
  });

  await t.test('39. docutrust compute-run & compute-verify', () => {
    const progFile = path.join(tempDir, 'prog.json');
    const inputFile = path.join(tempDir, 'inputs.json');
    const proverKeyFile = path.join(tempDir, 'prover-keys.json');
    const receiptFile = path.join(tempDir, 'compute-receipt.json');

    execSync(`node "${cliPath}" keygen --out "${proverKeyFile}"`);
    const prog = {
      programId: 'CLIComputeTest',
      version: '1.0.0',
      instructions: [
        { op: 'ADD', args: ['$x', '$y'], outputVar: 'sum' },
        { op: 'THRESHOLD_CHECK', args: ['$sum', 50], outputVar: 'isAbove50' }
      ]
    };
    fs.writeFileSync(progFile, JSON.stringify(prog, null, 2), 'utf-8');
    fs.writeFileSync(inputFile, JSON.stringify({ x: 30, y: 40 }, null, 2), 'utf-8');

    const runOut = execSync(`node "${cliPath}" compute-run --program "${progFile}" --inputs "${inputFile}" --key "${proverKeyFile}" --out "${receiptFile}"`).toString();
    assert.ok(runOut.includes('Verifiable Compute execution finished'));
    assert.ok(fs.existsSync(receiptFile));

    const verifyOut = execSync(`node "${cliPath}" compute-verify --receipt "${receiptFile}" --prover-key "${proverKeyFile}" --inputs "${inputFile}"`).toString();
    assert.ok(verifyOut.includes('Verifiable Compute Receipt is'));
    assert.ok(verifyOut.includes('CRYPTOGRAPHICALLY VALID'));
  });

  await t.test('40. docutrust vanish-issue & vanish-verify', () => {
    const claimsFile = path.join(tempDir, 'vanish-claims.json');
    const issuerKeyFile = path.join(tempDir, 'vanish-issuer-keys.json');
    const outFile = path.join(tempDir, 'vanish-out.json');

    execSync(`node "${cliPath}" keygen --out "${issuerKeyFile}"`);
    fs.writeFileSync(claimsFile, JSON.stringify({ secretCode: 'SECRET-CLI-123' }, null, 2), 'utf-8');

    const issueOut = execSync(`node "${cliPath}" vanish-issue --claims "${claimsFile}" --key "${issuerKeyFile}" --subject "did:key:z6MkuSubject" --ttl 600 --out "${outFile}"`).toString();
    assert.ok(issueOut.includes('Ephemeral Vanish Token issued successfully'));
    assert.ok(fs.existsSync(outFile));

    const tokenData = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    const verifyOut = execSync(`node "${cliPath}" vanish-verify --token "${outFile}" --ephemeral-key "${tokenData.ephemeralKey}" --issuer-key "${issuerKeyFile}"`).toString();
    assert.ok(verifyOut.includes('ACTIVE & VALID'));
    assert.ok(verifyOut.includes('SECRET-CLI-123'));
  });

  await t.test('41. docutrust statesync-delta & statesync-verify', () => {
    const baseFile = path.join(tempDir, 'sync-base.json');
    const targetFile = path.join(tempDir, 'sync-target.json');
    const relayerKeyFile = path.join(tempDir, 'sync-relayer-keys.json');
    const deltaFile = path.join(tempDir, 'sync-delta.json');
    const updatedStateFile = path.join(tempDir, 'sync-updated.json');

    execSync(`node "${cliPath}" keygen --out "${relayerKeyFile}"`);
    const baseState = { 'did:key:z1': { entityDid: 'did:key:z1', status: 'ACTIVE', accreditationLevel: 1, updatedEpoch: 1000, metadataHash: '00' } };
    const targetState = { ...baseState, 'did:key:z2': { entityDid: 'did:key:z2', status: 'ACTIVE', accreditationLevel: 2, updatedEpoch: 2000, metadataHash: '11' } };

    fs.writeFileSync(baseFile, JSON.stringify(baseState, null, 2), 'utf-8');
    fs.writeFileSync(targetFile, JSON.stringify(targetState, null, 2), 'utf-8');

    const deltaOut = execSync(`node "${cliPath}" statesync-delta --base "${baseFile}" --target "${targetFile}" --key "${relayerKeyFile}" --out "${deltaFile}"`).toString();
    assert.ok(deltaOut.includes('StateSync Delta Proof generated successfully'));
    assert.ok(fs.existsSync(deltaFile));

    const verifyOut = execSync(`node "${cliPath}" statesync-verify --base "${baseFile}" --delta "${deltaFile}" --relayer-key "${relayerKeyFile}" --out "${updatedStateFile}"`).toString();
    assert.ok(verifyOut.includes('AUTHENTICATED & RECONCILED'));
    assert.ok(fs.existsSync(updatedStateFile));
  });

  await t.test('42. docutrust solidity-export-universal', () => {
    const universalSol = path.join(tempDir, 'DocuTrustUniversalVerifier.sol');
    const uOut = execSync(`node "${cliPath}" solidity-export-universal --out "${universalSol}"`).toString();
    assert.ok(uOut.includes('Master Universal EVM Solidity Smart Contract exported'));
    assert.ok(fs.existsSync(universalSol));
  });

  await t.test('43. docutrust zk-aggregate & zk-verify-recursive', () => {
    const aggKeyFile = path.join(tempDir, 'agg-keys.json');
    const proofsFile = path.join(tempDir, 'zk-subproofs.json');
    const recProofFile = path.join(tempDir, 'zk-rec-proof.json');

    execSync(`node "${cliPath}" keygen --out "${aggKeyFile}"`);
    const subProofs = [
      { proofId: 'sub-1', proofType: 'Range', claim: 'salary', publicInputs: { min: 50000 }, proofData: {}, proverDid: 'did:key:z1' },
      { proofId: 'sub-2', proofType: 'Set', claim: 'role', publicInputs: { role: 'admin' }, proofData: {}, proverDid: 'did:key:z2' }
    ];
    fs.writeFileSync(proofsFile, JSON.stringify(subProofs, null, 2), 'utf-8');

    const aggOut = execSync(`node "${cliPath}" zk-aggregate --proofs "${proofsFile}" --key "${aggKeyFile}" --depth 1 --evm --out "${recProofFile}"`).toString();
    assert.ok(aggOut.includes('Recursive ZK Aggregated Proof generated successfully'));
    assert.ok(fs.existsSync(recProofFile));

    const verifyOut = execSync(`node "${cliPath}" zk-verify-recursive --proof "${recProofFile}" --key "${aggKeyFile}"`).toString();
    assert.ok(verifyOut.includes('Recursive ZK Proof is'));
    assert.ok(verifyOut.includes('CRYPTOGRAPHICALLY VALID'));
  });

  await t.test('44. docutrust lattice-init, lattice-accumulate, lattice-prove & lattice-verify', () => {
    const issuerKeyFile = path.join(tempDir, 'lattice-issuer-keys.json');
    const latticeStateFile = path.join(tempDir, 'lattice-state.json');
    const revsFile = path.join(tempDir, 'lattice-revs.json');
    const proofFile = path.join(tempDir, 'lattice-proof.json');

    execSync(`node "${cliPath}" keygen --out "${issuerKeyFile}"`);
    const issuerData = JSON.parse(fs.readFileSync(issuerKeyFile, 'utf-8'));

    const initOut = execSync(`node "${cliPath}" lattice-init --id lat-cli-101 --issuer "${issuerData.did}" --shards 4 --out "${latticeStateFile}"`).toString();
    assert.ok(initOut.includes('Revocation Lattice initialized successfully'));
    assert.ok(fs.existsSync(latticeStateFile));

    fs.writeFileSync(revsFile, JSON.stringify(['cred-revoked-001', 'cred-revoked-002']), 'utf-8');
    const accOut = execSync(`node "${cliPath}" lattice-accumulate --state "${latticeStateFile}" --revocations "${revsFile}" --advance`).toString();
    assert.ok(accOut.includes('Revocation Lattice updated successfully'));

    // Prove active credential
    const proveActiveOut = execSync(`node "${cliPath}" lattice-prove --state "${latticeStateFile}" --credential "cred-active-999" --key "${issuerKeyFile}" --out "${proofFile}"`).toString();
    assert.ok(proveActiveOut.includes('Revocation Lattice Proof generated'));
    assert.ok(proveActiveOut.includes('ACTIVE'));

    const verifyOut = execSync(`node "${cliPath}" lattice-verify --proof "${proofFile}" --key "${issuerKeyFile}"`).toString();
    assert.ok(verifyOut.includes('CRYPTOGRAPHICALLY AUTHENTIC'));
    assert.ok(verifyOut.includes('NOT REVOKED (VALID)'));
  });

  await t.test('45. docutrust agent-attest & agent-verify', () => {
    const agentKeyFile = path.join(tempDir, 'agent-keys.json');
    const payloadFile = path.join(tempDir, 'agent-payload.json');
    const attestationFile = path.join(tempDir, 'agent-attestation.json');

    execSync(`node "${cliPath}" keygen --out "${agentKeyFile}"`);
    const payload = {
      modelCard: { modelName: 'DocuTrust-Autonomous-Auditor', modelVersion: '1.0.0', weightsDigest: 'sha256:abc' },
      promptText: 'Audit the smart contract and check compliance',
      executionTrace: [{ step: 1, tool: 'scanVulnerabilities', result: '0 issues found' }],
      outputArtifact: { approved: true, riskScore: 0.05 },
      guardrailPolicyId: 'sovereign-ai-safety-v1',
      guardrailPassed: true
    };
    fs.writeFileSync(payloadFile, JSON.stringify(payload, null, 2), 'utf-8');

    const attestOut = execSync(`node "${cliPath}" agent-attest --payload "${payloadFile}" --key "${agentKeyFile}" --out "${attestationFile}"`).toString();
    assert.ok(attestOut.includes('AI Agent Action Attestation issued successfully'));
    assert.ok(fs.existsSync(attestationFile));

    const verifyOut = execSync(`node "${cliPath}" agent-verify --attestation "${attestationFile}" --key "${agentKeyFile}"`).toString();
    assert.ok(verifyOut.includes('AI Agent Attestation is'));
    assert.ok(verifyOut.includes('VERIFIED & TAMPER-FREE'));
    assert.ok(verifyOut.includes('COMPLIANT'));
  });

  await t.test('46. docutrust vrf-beacon, vrf-verify, oracle-feed & oracle-verify-feed', () => {
    const oKey1 = path.join(tempDir, 'oracle-key-1.json');
    const oKey2 = path.join(tempDir, 'oracle-key-2.json');
    const beaconFile = path.join(tempDir, 'vrf-beacon.json');
    const feedFile = path.join(tempDir, 'oracle-feed.json');

    execSync(`node "${cliPath}" keygen --out "${oKey1}"`);
    execSync(`node "${cliPath}" keygen --out "${oKey2}"`);

    // 1. Create VRF Beacon
    const beaconOut = execSync(`node "${cliPath}" vrf-beacon --epoch 10 --seed "lottery-seed" --keys "${oKey1},${oKey2}" --threshold 2 --out "${beaconFile}"`).toString();
    assert.ok(beaconOut.includes('VRF Randomness Beacon saved'));
    assert.ok(fs.existsSync(beaconFile));

    // 2. Verify VRF Beacon
    const verifyBeaconOut = execSync(`node "${cliPath}" vrf-verify --beacon "${beaconFile}"`).toString();
    assert.ok(verifyBeaconOut.includes('VERIFIED & CONSENSUS-VALIDATED'));

    // 3. Oracle Feed
    const feedOut = execSync(`node "${cliPath}" oracle-feed --feed-id "eth-usd" --key "ETH_PRICE" --val "3500.50" --signers "${oKey1},${oKey2}" --quorum 2 --out "${feedFile}"`).toString();
    assert.ok(feedOut.includes('Oracle Data Feed saved'));
    assert.ok(fs.existsSync(feedFile));

    // 4. Verify Oracle Feed
    const verifyFeedOut = execSync(`node "${cliPath}" oracle-verify-feed --feed "${feedFile}" --keys "${oKey1},${oKey2}"`).toString();
    assert.ok(verifyFeedOut.includes('VERIFIED & CONSENSUS-VALIDATED'));
  });

  await t.test('47. docutrust zk-compile-dsl, zk-dsl-prove & zk-dsl-verify', () => {
    const dslAstFile = path.join(tempDir, 'dsl-ast.json');
    const subjectFile = path.join(tempDir, 'dsl-subject.json');
    const proverKey = path.join(tempDir, 'dsl-prover-key.json');
    const proofFile = path.join(tempDir, 'dsl-proof.json');

    execSync(`node "${cliPath}" keygen --out "${proverKey}"`);
    fs.writeFileSync(subjectFile, JSON.stringify({ age: 25, income: 80000, jurisdiction: 'US' }), 'utf-8');

    const expr = "age >= 21 AND income >= 50000 AND jurisdiction == 'US'";

    // 1. Compile
    const compileOut = execSync(`node "${cliPath}" zk-compile-dsl --expr "${expr}" --out "${dslAstFile}"`).toString();
    assert.ok(compileOut.includes('ZK-DSL AST compiled and saved'));
    assert.ok(fs.existsSync(dslAstFile));

    // 2. Prove
    const proveOut = execSync(`node "${cliPath}" zk-dsl-prove --expr "${expr}" --subject "${subjectFile}" --key "${proverKey}" --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('Zero-Knowledge DSL Proof saved'));
    assert.ok(fs.existsSync(proofFile));

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" zk-dsl-verify --proof "${proofFile}" --key "${proverKey}" --expr "${expr}"`).toString();
    assert.ok(verifyOut.includes('Zero-Knowledge DSL Proof is'));
    assert.ok(verifyOut.includes('VALID & SATISFIED'));
  });

  await t.test('48. docutrust aibom-create & aibom-verify', () => {
    const certKey = path.join(tempDir, 'aibom-cert-key.json');
    const manifestFile = path.join(tempDir, 'aibom-manifest.json');
    const receiptFile = path.join(tempDir, 'aibom-receipt.json');

    execSync(`node "${cliPath}" keygen --out "${certKey}"`);

    const manifest = {
      modelId: 'dt-gpt-gov-7b',
      modelName: 'DocuTrust Governance LLM',
      architecture: 'transformer',
      parametersCount: '7B',
      quantization: 'fp16',
      layers: [
        {
          layerIndex: 0,
          layerName: 'embed.weight',
          tensorShape: [32000, 4096],
          dataType: 'float16',
          tensorDigestHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
        },
        {
          layerIndex: 1,
          layerName: 'layer0.attn.q_proj.weight',
          tensorShape: [4096, 4096],
          dataType: 'float16',
          tensorDigestHex: 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
        }
      ]
    };
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), 'utf-8');

    // 1. Create Receipt
    const createOut = execSync(`node "${cliPath}" aibom-create --manifest "${manifestFile}" --key "${certKey}" --out "${receiptFile}"`).toString();
    assert.ok(createOut.includes('AI-BOM Receipt saved'));
    assert.ok(fs.existsSync(receiptFile));

    // 2. Verify Receipt
    const verifyOut = execSync(`node "${cliPath}" aibom-verify --receipt "${receiptFile}" --key "${certKey}"`).toString();
    assert.ok(verifyOut.includes('AI-BOM Receipt is'));
    assert.ok(verifyOut.includes('AUTHENTIC & MERKLE-VERIFIED'));
  });

  await t.test('49. docutrust pqc-falcon-keygen, pqc-falcon-sign & pqc-falcon-verify', () => {
    const falconKeyFile = path.join(tempDir, 'falcon-key.json');
    const sigFile = path.join(tempDir, 'falcon-sig.json');

    // 1. KeyGen
    const keygenOut = execSync(`node "${cliPath}" pqc-falcon-keygen --level 512 --out "${falconKeyFile}"`).toString();
    assert.ok(keygenOut.includes('Falcon-512 KeyPair saved'));
    assert.ok(fs.existsSync(falconKeyFile));

    // 2. Sign
    const msg = 'Post-quantum high-assurance intelligence data';
    const signOut = execSync(`node "${cliPath}" pqc-falcon-sign --data "${msg}" --key "${falconKeyFile}" --out "${sigFile}"`).toString();
    assert.ok(signOut.includes('Falcon signature saved'));
    assert.ok(fs.existsSync(sigFile));

    const sigData = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" pqc-falcon-verify --data "${msg}" --sig "${sigData.signatureHex}" --key "${falconKeyFile}"`).toString();
    assert.ok(verifyOut.includes('Falcon Signature is'));
    assert.ok(verifyOut.includes('VALID'));
  });

  await t.test('50. docutrust pq-ratchet-keygen, init, encrypt & decrypt', () => {
    const bobKeyFile = path.join(tempDir, 'bob-ratchet-key.json');
    const aliceSessionFile = path.join(tempDir, 'alice-session.json');
    const bobSessionFile = path.join(tempDir, 'bob-session.json');
    const msgFile = path.join(tempDir, 'ratchet-msg.json');
    const decryptedFile = path.join(tempDir, 'ratchet-decrypted.json');

    // 1. Keygen
    const keygenOut = execSync(`node "${cliPath}" pq-ratchet-keygen --out "${bobKeyFile}"`).toString();
    assert.ok(keygenOut.includes('PQ Ratchet KeyPair saved'));
    assert.ok(fs.existsSync(bobKeyFile));

    // 2. Init Initiator & Responder
    const aliceInitOut = execSync(`node "${cliPath}" pq-ratchet-init --bob "${bobKeyFile}" --out "${aliceSessionFile}"`).toString();
    assert.ok(aliceInitOut.includes('Initiator Session saved'));

    const bobInitOut = execSync(`node "${cliPath}" pq-ratchet-init --key "${bobKeyFile}" --out "${bobSessionFile}"`).toString();
    assert.ok(bobInitOut.includes('Responder Session saved'));

    // 3. Encrypt
    const dataFile = path.join(tempDir, 'ratchet-input.json');
    fs.writeFileSync(dataFile, JSON.stringify({ secretDoc: 'doc-7749', clearance: 'Level-5' }), 'utf-8');
    const encOut = execSync(`node "${cliPath}" pq-ratchet-encrypt --session "${aliceSessionFile}" --data "${dataFile}" --out "${msgFile}"`).toString();
    assert.ok(encOut.includes('Encrypted message saved'));
    assert.ok(fs.existsSync(msgFile));

    // 4. Decrypt
    const decOut = execSync(`node "${cliPath}" pq-ratchet-decrypt --session "${bobSessionFile}" --message "${msgFile}" --out "${decryptedFile}"`).toString();
    assert.ok(decOut.includes('Decrypted payload saved'));
    assert.ok(fs.existsSync(decryptedFile));

    const plain = JSON.parse(fs.readFileSync(decryptedFile, 'utf-8'));
    assert.equal(plain.secretDoc, 'doc-7749');
  });

  await t.test('51. docutrust poly-srs, poly-commit, poly-prove & poly-verify', () => {
    const srsFile = path.join(tempDir, 'poly-srs.json');
    const commitFile = path.join(tempDir, 'poly-commit.json');
    const proofFile = path.join(tempDir, 'poly-proof.json');

    // 1. SRS
    const srsOut = execSync(`node "${cliPath}" poly-srs --degree 16 --out "${srsFile}"`).toString();
    assert.ok(srsOut.includes('Structured Reference String'));
    assert.ok(fs.existsSync(srsFile));

    // 2. Commit: P(x) = 3 + 2x + 5x^2
    const commitOut = execSync(`node "${cliPath}" poly-commit --srs "${srsFile}" --coeffs "[3,2,5]" --out "${commitFile}"`).toString();
    assert.ok(commitOut.includes('Polynomial commitment saved'));
    assert.ok(fs.existsSync(commitFile));

    // 3. Prove: point = 4
    const proveOut = execSync(`node "${cliPath}" poly-prove --srs "${srsFile}" --coeffs "[3,2,5]" --point 4 --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('evaluation proof saved'));
    assert.ok(fs.existsSync(proofFile));

    // 4. Verify
    const verifyOut = execSync(`node "${cliPath}" poly-verify --srs "${srsFile}" --commit "${commitFile}" --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  await t.test('52. docutrust tee-quote & tee-verify', () => {
    const measFile = path.join(tempDir, 'tee-meas.json');
    const quoteFile = path.join(tempDir, 'tee-quote.json');

    const measurements = {
      mrEnclave: 'b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff01',
      mrSigner: '223344556677889900aabbccddeeff11223344556677889900aabbccddeeff22',
      isvProdId: 1,
      isvSvn: 2
    };
    fs.writeFileSync(measFile, JSON.stringify(measurements, null, 2), 'utf-8');

    // 1. Generate Quote
    const quoteOut = execSync(`node "${cliPath}" tee-quote --measurements "${measFile}" --data "DocuTrust-TEE-Workload" --out "${quoteFile}"`).toString();
    assert.ok(quoteOut.includes('Attestation Quote saved'));
    assert.ok(fs.existsSync(quoteFile));

    // 2. Verify Quote
    const verifyOut = execSync(`node "${cliPath}" tee-verify --quote "${quoteFile}" --mr-enclave "${measurements.mrEnclave}"`).toString();
    assert.ok(verifyOut.includes('AUTHENTIC & ENCLAVE-VERIFIED'));
  });

  await t.test('53. docutrust ibc-packet-commit, ibc-merkle-proof & ibc-verify-proof', () => {
    const packetFile = path.join(tempDir, 'ibc-packet.json');
    const commitFile = path.join(tempDir, 'ibc-commit.json');
    const proofFile = path.join(tempDir, 'ibc-proof.json');

    const packet = {
      sequence: 1,
      sourcePort: 'transfer',
      sourceChannel: 'channel-0',
      destinationPort: 'transfer',
      destinationChannel: 'channel-1',
      data: { token: 'TRUST', amount: 5000 },
      timeoutHeight: { revisionNumber: 1, revisionHeight: 1000 },
      timeoutTimestamp: Math.floor(Date.now() / 1000) + 3600
    };
    fs.writeFileSync(packetFile, JSON.stringify(packet, null, 2), 'utf-8');

    // 1. Packet Commit
    const commitOut = execSync(`node "${cliPath}" ibc-packet-commit --packet "${packetFile}" --out "${commitFile}"`).toString();
    assert.ok(commitOut.includes('Packet Commitment saved'));
    assert.ok(fs.existsSync(commitFile));

    const commitData = JSON.parse(fs.readFileSync(commitFile, 'utf-8'));

    // 2. Merkle Proof
    const proofOut = execSync(`node "${cliPath}" ibc-merkle-proof --key "${commitData.commitmentPath}" --value "${commitData.commitmentBytesHex}" --out "${proofFile}"`).toString();
    assert.ok(proofOut.includes('Merkle Multi-Store Proof saved'));
    assert.ok(fs.existsSync(proofFile));

    // 3. Verify Proof
    const verifyOut = execSync(`node "${cliPath}" ibc-verify-proof --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  await t.test('54. docutrust fhe-keypair, fhe-encrypt, fhe-decrypt, fhe-add', () => {
    const kpFile = path.join(tempDir, 'fhe-kp.json');
    const c1File = path.join(tempDir, 'fhe-c1.json');
    const c2File = path.join(tempDir, 'fhe-c2.json');
    const sumFile = path.join(tempDir, 'fhe-sum.json');

    // 1. Keypair
    const kpOut = execSync(`node "${cliPath}" fhe-keypair --dim 8 --out "${kpFile}"`).toString();
    assert.ok(kpOut.includes('FHE KeyPair saved'));
    assert.ok(fs.existsSync(kpFile));

    // 2. Encrypt 40 and 60
    const enc1Out = execSync(`node "${cliPath}" fhe-encrypt --value 40 --pubkey "${kpFile}" --out "${c1File}"`).toString();
    assert.ok(enc1Out.includes('FHE Ciphertext saved'));
    const enc2Out = execSync(`node "${cliPath}" fhe-encrypt --value 60 --pubkey "${kpFile}" --out "${c2File}"`).toString();
    assert.ok(enc2Out.includes('FHE Ciphertext saved'));

    // 3. Add
    const addOut = execSync(`node "${cliPath}" fhe-add --c1 "${c1File}" --c2 "${c2File}" --out "${sumFile}"`).toString();
    assert.ok(addOut.includes('Homomorphic Sum saved'));

    // 4. Decrypt sum
    const decOut = execSync(`node "${cliPath}" fhe-decrypt --ciphertext "${sumFile}" --privkey "${kpFile}"`).toString();
    assert.ok(decOut.includes('100'));
  });

  await t.test('55. docutrust frost-dkg, frost-round1, frost-verify', () => {
    const dkgFile = path.join(tempDir, 'frost-dkg.json');
    const r1File = path.join(tempDir, 'frost-r1.json');

    // 1. DKG
    const dkgOut = execSync(`node "${cliPath}" frost-dkg --threshold 2 --total 3 --out "${dkgFile}"`).toString();
    assert.ok(dkgOut.includes('DKG Packages saved'));
    assert.ok(fs.existsSync(dkgFile));

    // 2. Round 1
    const r1Out = execSync(`node "${cliPath}" frost-round1 --signer-id 1 --out "${r1File}"`).toString();
    assert.ok(r1Out.includes('Round 1 Nonces saved'));
    assert.ok(fs.existsSync(r1File));
  });

  await t.test('56. docutrust plonk-compile & plonk-verify', () => {
    const circuitFile = path.join(tempDir, 'plonk-circ.json');
    const compiledFile = path.join(tempDir, 'plonk-compiled.json');
    const proofFile = path.join(tempDir, 'plonk-proof.json');
    const vkFile = path.join(tempDir, 'plonk-vk.json');

    const circuitDef = {
      circuitId: 'cli_plonk_test',
      gates: [
        {
          gateIndex: 0,
          qL: 0,
          qR: 0,
          qO: -1,
          qM: 1,
          qC: 0,
          aVar: 'x',
          bVar: 'y',
          cVar: 'out'
        }
      ],
      publicInputKeys: ['out']
    };
    fs.writeFileSync(circuitFile, JSON.stringify(circuitDef, null, 2), 'utf-8');

    // 1. Compile
    const compileOut = execSync(`node "${cliPath}" plonk-compile --circuit "${circuitFile}" --out "${compiledFile}"`).toString();
    assert.ok(compileOut.includes('Compiled PlonK Circuit saved'));
    assert.ok(fs.existsSync(compiledFile));

    const compiled = JSON.parse(fs.readFileSync(compiledFile, 'utf-8'));
    fs.writeFileSync(vkFile, JSON.stringify(compiled.verificationKey, null, 2), 'utf-8');

    // 2. Generate proof via core directly to verify via CLI
    const { ZKPlonKEngine } = require('@docutrust/core');
    const proof = ZKPlonKEngine.createPlonKProof(compiled.circuit, { x: 7, y: 8 }, { out: 56 });
    fs.writeFileSync(proofFile, JSON.stringify(proof, null, 2), 'utf-8');

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" plonk-verify --proof "${proofFile}" --vk "${vkFile}"`).toString();
    assert.ok(verifyOut.includes('VALID & VERIFIED'));
  });

  await t.test('57. docutrust capability-issue & capability-verify', () => {
    const rootKeyFile = path.join(tempDir, 'cap-root-kp.json');
    const tokenFile = path.join(tempDir, 'cap-token.json');
    const chainFile = path.join(tempDir, 'cap-chain.json');

    const { generateKeyPair } = require('@docutrust/core');
    const rootKp = generateKeyPair();
    const workerKp = generateKeyPair();
    fs.writeFileSync(rootKeyFile, JSON.stringify(rootKp, null, 2), 'utf-8');

    // 1. Issue Root UCAN
    const issueOut = execSync(`node "${cliPath}" capability-issue --issuer-key "${rootKeyFile}" --audience "${workerKp.did}" --resource "urn:docutrust:vault:docs" --action "READ" --out "${tokenFile}"`).toString();
    assert.ok(issueOut.includes('Root UCAN Capability Token saved'));
    assert.ok(fs.existsSync(tokenFile));

    const token = JSON.parse(fs.readFileSync(tokenFile, 'utf-8'));
    fs.writeFileSync(chainFile, JSON.stringify([token], null, 2), 'utf-8');

    // 2. Verify
    const verifyOut = execSync(`node "${cliPath}" capability-verify --chain "${chainFile}" --resource "urn:docutrust:vault:docs" --action "READ"`).toString();
    assert.ok(verifyOut.includes('VALID & AUTHORIZED'));
  });

  await t.test('58. docutrust stark-trace, stark-prove, stark-verify', () => {
    const traceFile = path.join(tempDir, 'stark-trace.json');
    const proofFile = path.join(tempDir, 'stark-proof.json');

    // 1. Trace
    const traceOut = execSync(`node "${cliPath}" stark-trace --steps 8 --transition fibonacci --out "${traceFile}"`).toString();
    assert.ok(traceOut.includes('STARK AIR Execution Trace saved'));
    assert.ok(fs.existsSync(traceFile));

    // 2. Prove
    const proveOut = execSync(`node "${cliPath}" stark-prove --trace "${traceFile}" --queries 4 --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('Transparent STARK FRI Proof saved'));
    assert.ok(fs.existsSync(proofFile));

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" stark-verify --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID & VERIFIED'));
  });

  await t.test('59. docutrust frost-consensus-init & frost-consensus-verify', () => {
    const commFile = path.join(tempDir, 'frost-comm.json');
    const commitFile = path.join(tempDir, 'frost-commit.json');

    // 1. Init
    const initOut = execSync(`node "${cliPath}" frost-consensus-init --participants "node1:2,node2:2,node3:1" --threshold 3 --out "${commFile}"`).toString();
    assert.ok(initOut.includes('FROST Consensus Committee initialized'));
    assert.ok(fs.existsSync(commFile));

    // 2. Create and aggregate commitment via core for verification via CLI
    const { FROSTConsensusEngine } = require('@docutrust/core');
    const committee = JSON.parse(fs.readFileSync(commFile, 'utf-8'));
    const payload = { height: 500, hash: '0xabc' };
    const s1 = FROSTConsensusEngine.generateRoundShare(committee, 'node1', 'secret1', 'r1', payload);
    const s2 = FROSTConsensusEngine.generateRoundShare(committee, 'node2', 'secret2', 'r1', payload);
    const commitment = FROSTConsensusEngine.aggregateRound(committee, 'r1', payload, [s1, s2]);
    fs.writeFileSync(commitFile, JSON.stringify(commitment, null, 2), 'utf-8');

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" frost-consensus-verify --committee "${commFile}" --commitment "${commitFile}"`).toString();
    assert.ok(verifyOut.includes('VALID & VERIFIED'));
  });

  await t.test('60. docutrust agent-memory-commit & agent-memory-verify', () => {
    const nodesFile = path.join(tempDir, 'mem-nodes.json');
    const graphFile = path.join(tempDir, 'mem-graph.json');
    const proofFile = path.join(tempDir, 'mem-proof.json');

    const nodes = [
      {
        id: 'node_1',
        content: 'Agent learned zero-knowledge proof verification on-chain.',
        embedding: [0.1, 0.5, 0.8, 0.2],
        tags: ['learning'],
        timestamp: new Date().toISOString()
      }
    ];
    fs.writeFileSync(nodesFile, JSON.stringify(nodes, null, 2), 'utf-8');

    // 1. Commit
    const commitOut = execSync(`node "${cliPath}" agent-memory-commit --agent-did "did:docutrust:agent:test" --nodes "${nodesFile}" --out "${graphFile}"`).toString();
    assert.ok(commitOut.includes('Agent Memory Graph Commitment saved'));
    assert.ok(fs.existsSync(graphFile));

    // 2. Generate proof via core
    const { AgentMemoryEngine } = require('@docutrust/core');
    const graph = JSON.parse(fs.readFileSync(graphFile, 'utf-8'));
    const proof = AgentMemoryEngine.generateSimilarityProof([0.1, 0.49, 0.81, 0.2], nodes[0], 0, graph, 0.8);
    fs.writeFileSync(proofFile, JSON.stringify(proof, null, 2), 'utf-8');

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" agent-memory-verify --graph "${graphFile}" --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID & AUTHENTIC'));
  });

  await t.test('61. docutrust psi-blind & psi-verify', () => {
    const blindOutFile = path.join(tempDir, 'psi-blind.json');
    const receiptFile = path.join(tempDir, 'psi-receipt.json');

    // 1. Blind
    const blindOut = execSync(`node "${cliPath}" psi-blind --party-id "alpha" --items "apple,banana,cherry" --out "${blindOutFile}"`).toString();
    assert.ok(blindOut.includes('Blinded Dataset saved'));
    assert.ok(fs.existsSync(blindOutFile));

    // 2. Generate receipt via core
    const { PSIExecutionEngine } = require('@docutrust/core');
    const blindA = JSON.parse(fs.readFileSync(blindOutFile, 'utf-8'));
    const blindB = PSIExecutionEngine.blindDataset('beta', ['banana', 'date']);
    const doubleA = PSIExecutionEngine.doubleBlindElements(blindA.dataset.blindedElements, blindB.secretKeyHex);
    const doubleB = PSIExecutionEngine.doubleBlindElements(blindB.dataset.blindedElements, blindA.secretKeyHex);
    const intersect = PSIExecutionEngine.computeIntersection('alpha', 'beta', doubleA, doubleB);
    const receipt = PSIExecutionEngine.generateReceipt(blindA.dataset, blindB.dataset, intersect);
    fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2), 'utf-8');

    // 3. Verify
    const verifyOut = execSync(`node "${cliPath}" psi-verify --receipt "${receiptFile}"`).toString();
    assert.ok(verifyOut.includes('VALID & VERIFIED'));
  });

  await t.test('62. docutrust zkml-prove & zkml-verify', () => {
    const layersFile = path.join(tempDir, 'zkml-layers.json');
    const inputFile = path.join(tempDir, 'zkml-input.json');
    const proofFile = path.join(tempDir, 'zkml-proof.json');

    const layers = [
      {
        layerIndex: 0,
        type: 'dense',
        weights: { shape: [2, 2], data: [128, -64, 256, 128], scale: 256, zeroPoint: 0 },
        biases: { shape: [2], data: [0, 0], scale: 256, zeroPoint: 0 }
      },
      {
        layerIndex: 1,
        type: 'softmax'
      }
    ];
    fs.writeFileSync(layersFile, JSON.stringify(layers, null, 2), 'utf-8');
    fs.writeFileSync(inputFile, JSON.stringify([0.5, -0.5], null, 2), 'utf-8');

    // 1. Prove
    const proveOut = execSync(`node "${cliPath}" zkml-prove --model-id "cli_test_model" --layers "${layersFile}" --input "${inputFile}" --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('ZKML Inference Proof saved'));
    assert.ok(fs.existsSync(proofFile));

    // 2. Verify
    const verifyOut = execSync(`node "${cliPath}" zkml-verify --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID & VERIFIED'));
  });

  await t.test('63. docutrust mpc-garble & mpc-evaluate', () => {
    const circuitFile = path.join(tempDir, 'mpc-circuit.json');
    const garbledFile = path.join(tempDir, 'mpc-garbled.json');
    const inputsFile = path.join(tempDir, 'mpc-inputs.json');
    const receiptFile = path.join(tempDir, 'mpc-receipt.json');

    const circuitDef = {
      circuitId: 'cli_circ_01',
      inputWiresGarbler: ['w_g0'],
      inputWiresEvaluator: ['w_e0'],
      outputWires: ['w_out'],
      gates: [
        { id: 'g0', type: 'XOR', inputWires: ['w_g0', 'w_e0'], outputWire: 'w_out' }
      ]
    };
    fs.writeFileSync(circuitFile, JSON.stringify(circuitDef, null, 2), 'utf-8');

    // 1. Garble
    const garbleOut = execSync(`node "${cliPath}" mpc-garble --circuit "${circuitFile}" --out "${garbledFile}"`).toString();
    assert.ok(garbleOut.includes('Garbled Circuit package saved'));
    assert.ok(fs.existsSync(garbledFile));

    const garbledPkg = JSON.parse(fs.readFileSync(garbledFile, 'utf-8'));
    const inputLabels = {
      w_g0: garbledPkg.wireLabels['w_g0'].oneLabel,
      w_e0: garbledPkg.wireLabels['w_e0'].zeroLabel
    };
    fs.writeFileSync(inputsFile, JSON.stringify(inputLabels, null, 2), 'utf-8');

    // 2. Evaluate
    const evalOut = execSync(`node "${cliPath}" mpc-evaluate --circuit "${garbledFile}" --inputs "${inputsFile}" --out "${receiptFile}"`).toString();
    assert.ok(evalOut.includes('MPC Evaluation Receipt saved'));
    assert.ok(fs.existsSync(receiptFile));
  });

  await t.test('64. docutrust swarm-propose & swarm-vote-quorum', () => {
    const proposalFile = path.join(tempDir, 'swarm-prop.json');
    const membersFile = path.join(tempDir, 'swarm-members.json');
    const votesFile = path.join(tempDir, 'swarm-votes.json');
    const proofFile = path.join(tempDir, 'swarm-proof.json');

    const { SwarmConsensusEngine, generateKeyPair } = require('@docutrust/core');
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();

    const members = [
      { agentDid: kp1.did, publicKeyHex: kp1.publicKeyHex, role: 'coordinator', reputationWeight: 60, registeredEpoch: 1 },
      { agentDid: kp2.did, publicKeyHex: kp2.publicKeyHex, role: 'auditor', reputationWeight: 40, registeredEpoch: 1 }
    ];
    fs.writeFileSync(membersFile, JSON.stringify(members, null, 2), 'utf-8');

    // 1. Propose
    const propOut = execSync(`node "${cliPath}" swarm-propose --swarm-id "swarm_cli" --proposer-did "${kp1.did}" --action "TRANSFER_ASSET" --quorum 50 --out "${proposalFile}"`).toString();
    assert.ok(propOut.includes('Swarm Proposal saved'));

    const proposal = JSON.parse(fs.readFileSync(proposalFile, 'utf-8'));
    const vote1 = SwarmConsensusEngine.signVote(proposal, members[0], kp1.privateKeyHex, 'APPROVE');
    fs.writeFileSync(votesFile, JSON.stringify([vote1], null, 2), 'utf-8');

    // 2. Aggregate Quorum
    const quorumOut = execSync(`node "${cliPath}" swarm-vote-quorum --proposal "${proposalFile}" --members "${membersFile}" --votes "${votesFile}" --out "${proofFile}"`).toString();
    assert.ok(quorumOut.includes('Swarm Quorum Proof saved'));
    assert.ok(fs.existsSync(proofFile));
  });

  await t.test('65. docutrust timelock-seal & timelock-open', () => {
    const payloadFile = path.join(tempDir, 'tlock-payload.json');
    const sealedFile = path.join(tempDir, 'tlock-sealed.json');
    const proofFile = path.join(tempDir, 'tlock-proof.json');
    const decryptedFile = path.join(tempDir, 'tlock-decrypted.json');

    const secretData = { secretKey: 'TOP_SECRET_TIMELOCK_KEY_2026' };
    fs.writeFileSync(payloadFile, JSON.stringify(secretData, null, 2), 'utf-8');

    // 1. Seal
    const sealOut = execSync(`node "${cliPath}" timelock-seal --payload "${payloadFile}" --delay 2 --difficulty 200 --out "${sealedFile}"`).toString();
    assert.ok(sealOut.includes('Timelock Sealed Package saved'));

    const sealedPkg = JSON.parse(fs.readFileSync(sealedFile, 'utf-8'));
    fs.writeFileSync(proofFile, JSON.stringify(sealedPkg.vdfProof, null, 2), 'utf-8');

    // 2. Open
    const openOut = execSync(`node "${cliPath}" timelock-open --sealed "${sealedFile}" --proof "${proofFile}" --out "${decryptedFile}"`).toString();
    assert.ok(openOut.includes('Timelock Decrypted Payload saved'));
    assert.ok(fs.existsSync(decryptedFile));

    const decrypted = JSON.parse(fs.readFileSync(decryptedFile, 'utf-8'));
    assert.deepEqual(decrypted, secretData);
  });

  await t.test('66. docutrust pss-init, pss-reshare, pss-reconstruct', () => {
    const pssSetupFile = path.join(tempDir, 'pss-setup.json');
    const pssRenewalFile = path.join(tempDir, 'pss-renewal.json');
    const pssReconFile = path.join(tempDir, 'pss-recon.json');

    // 1. Init
    const initOut = execSync(`node "${cliPath}" pss-init --secret "0x1234567890abcdef" --threshold 2 --total 3 --out "${pssSetupFile}"`).toString();
    assert.ok(initOut.includes('PSS Committee setup saved'));
    assert.ok(fs.existsSync(pssSetupFile));

    // 2. Reshare
    const reshareOut = execSync(`node "${cliPath}" pss-reshare --participant 1 --threshold 2 --total 3 --epoch 0 --out "${pssRenewalFile}"`).toString();
    assert.ok(reshareOut.includes('PSS Renewal Sub-shares saved'));

    // 3. Reconstruct
    const setupData = JSON.parse(fs.readFileSync(pssSetupFile, 'utf-8'));
    const sharesFile = path.join(tempDir, 'pss-shares.json');
    fs.writeFileSync(sharesFile, JSON.stringify(setupData.shares.slice(0, 2), null, 2), 'utf-8');

    const reconOut = execSync(`node "${cliPath}" pss-reconstruct --shares "${sharesFile}" --threshold 2 --out "${pssReconFile}"`).toString();
    assert.ok(reconOut.includes('PSS Reconstructed Secret saved'));
  });

  await t.test('67. docutrust vector-commit, vector-prove, vector-verify', () => {
    const vecFile = path.join(tempDir, 'vec-data.json');
    const commFile = path.join(tempDir, 'vec-comm.json');
    const proofFile = path.join(tempDir, 'vec-proof.json');

    const vectorData = [{ role: 'ADMIN' }, { clearance: 'HIGH' }];
    fs.writeFileSync(vecFile, JSON.stringify(vectorData, null, 2), 'utf-8');

    // 1. Commit
    const commOut = execSync(`node "${cliPath}" vector-commit --vector "${vecFile}" --out "${commFile}"`).toString();
    assert.ok(commOut.includes('Vector Commitment saved'));

    // 2. Prove subvector
    const proveOut = execSync(`node "${cliPath}" vector-prove --vector "${vecFile}" --indices "0,1" --out "${proofFile}"`).toString();
    assert.ok(proveOut.includes('Subvector Proof saved'));

    // 3. Verify
    const commitData = JSON.parse(fs.readFileSync(commFile, 'utf-8'));
    const verifyOut = execSync(`node "${cliPath}" vector-verify --commitment "${commitData.commitmentHex}" --proof "${proofFile}"`).toString();
    assert.ok(verifyOut.includes('VALID'));
  });

  await t.test('68. docutrust pq-blind-keygen, pq-blind-request, pq-blind-sign', () => {
    const kpFile = path.join(tempDir, 'pqblind-kp.json');
    const msgFile = path.join(tempDir, 'pqblind-msg.json');
    const reqFile = path.join(tempDir, 'pqblind-req.json');
    const sigFile = path.join(tempDir, 'pqblind-sig.json');

    // 1. Keygen
    const kpOut = execSync(`node "${cliPath}" pq-blind-keygen --out "${kpFile}"`).toString();
    assert.ok(kpOut.includes('PQ Blind KeyPair generated and saved'));

    // 2. Request / Blind
    fs.writeFileSync(msgFile, JSON.stringify({ vote: 'YES' }), 'utf-8');
    const reqOut = execSync(`node "${cliPath}" pq-blind-request --msg "${msgFile}" --signer-key "${kpFile}" --out "${reqFile}"`).toString();
    assert.ok(reqOut.includes('Blinded Message Request saved'));

    // 3. Sign
    const signOut = execSync(`node "${cliPath}" pq-blind-sign --request "${reqFile}" --signer-key "${kpFile}" --out "${sigFile}"`).toString();
    assert.ok(signOut.includes('Blind Signature saved'));
  });

  await t.test('69. docutrust agent-contract-create', () => {
    const contractFile = path.join(tempDir, 'agent-contract.json');

    const createOut = execSync(`node "${cliPath}" agent-contract-create --principal "did:key:p" --agent "did:key:a" --bounty 500 --stake 250 --out "${contractFile}"`).toString();
    assert.ok(createOut.includes('Agent Escrow Contract created'));
    assert.ok(fs.existsSync(contractFile));
  });
});







