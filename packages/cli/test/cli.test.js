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
});
