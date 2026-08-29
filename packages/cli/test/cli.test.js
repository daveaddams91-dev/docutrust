const test = require('node:test');
const assert = require('node:assert/strict');
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

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
});
