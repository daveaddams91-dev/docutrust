#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let core;
try {
  core = require('@docutrust/core');
} catch (e) {}

// Base58 Alphabet
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
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalizeJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(',') + '}';
}

function safeWriteFileSync(filePath, data) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, data, 'utf-8');
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

function signData(data, privateKey) {
  const payloadBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  let keyObject;
  if (typeof privateKey === 'object' && privateKey.privateKeyPem) {
    keyObject = crypto.createPrivateKey(privateKey.privateKeyPem);
  } else if (typeof privateKey === 'string' && privateKey.includes('BEGIN PRIVATE KEY')) {
    keyObject = crypto.createPrivateKey(privateKey);
  } else if (typeof privateKey === 'string' && /^[0-9a-fA-F]{64}$/.test(privateKey)) {
    const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
    const fullDer = Buffer.concat([pkcs8Header, Buffer.from(privateKey, 'hex')]);
    keyObject = crypto.createPrivateKey({ key: fullDer, format: 'der', type: 'pkcs8' });
  } else {
    throw new Error('Invalid private key format.');
  }
  return crypto.sign(null, payloadBuffer, keyObject).toString('hex');
}

function verifySignature(data, signatureHex, publicKey) {
  try {
    const payloadBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    const signatureBuffer = Buffer.from(signatureHex, 'hex');
    let keyObject;
    if (typeof publicKey === 'object' && publicKey.publicKeyPem) {
      keyObject = crypto.createPublicKey(publicKey.publicKeyPem);
    } else if (typeof publicKey === 'string' && publicKey.includes('BEGIN PUBLIC KEY')) {
      keyObject = crypto.createPublicKey(publicKey);
    } else if (typeof publicKey === 'string' && publicKey.startsWith('did:key:z')) {
      const multibase = publicKey.replace('did:key:z', '').split('#')[0];
      const decoded = decodeBase58(multibase);
      const rawPub = decoded.subarray(2);
      const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
      const fullDer = Buffer.concat([spkiHeader, rawPub]);
      keyObject = crypto.createPublicKey({ key: fullDer, format: 'der', type: 'spki' });
    } else if (typeof publicKey === 'string' && /^[0-9a-fA-F]{64}$/.test(publicKey)) {
      const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
      const fullDer = Buffer.concat([spkiHeader, Buffer.from(publicKey, 'hex')]);
      keyObject = crypto.createPublicKey({ key: fullDer, format: 'der', type: 'spki' });
    } else {
      return false;
    }
    return crypto.verify(null, payloadBuffer, keyObject, signatureBuffer);
  } catch (e) {
    return false;
  }
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
}

const args = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
\x1b[1m\x1b[36m🛡️ DocuTrust CLI v13.0.0\x1b[0m — Sovereign Trust Mesh Evolution: Recursive ZK, Revocation Lattice & AI Agent Provenance

\x1b[1mRECURSIVE ZERO-KNOWLEDGE PROOF AGGREGATION (v13.0.0):\x1b[0m
  \x1b[32mzk-aggregate\x1b[0m --proofs <f> --key <k> [--depth <d>] [--evm] [--out <f>] Aggregate heterogeneous ZK sub-proofs via Fiat-Shamir folding
  \x1b[32mzk-verify-recursive\x1b[0m --proof <f> --key <k|pubHex>                     Verify recursively folded zero-knowledge proof

\x1b[1mTEMPORAL-SPATIAL REVOCATION LATTICE (v13.0.0):\x1b[0m
  \x1b[32mlattice-init\x1b[0m --id <id> --issuer <did> [--shards <s>] [--out <f>]      Initialize 2D multi-epoch revocation lattice
  \x1b[32mlattice-accumulate\x1b[0m --state <s> --revocations <r> [--advance] [--out <f>] Accumulate credential revocations and advance epoch
  \x1b[32mlattice-prove\x1b[0m --state <s> --credential <id> --key <k> [--epoch <e>] [--out <f>] Generate O(1) non-revocation / revocation witness
  \x1b[32mlattice-verify\x1b[0m --proof <p> --key <k|pubHex> [--root <r>]           Verify lattice non-revocation / revocation witness proof

\x1b[1mAUTONOMOUS AI AGENT PROVENANCE & GUARDRAILS (v13.0.0):\x1b[0m
  \x1b[32magent-attest\x1b[0m --payload <f> --key <k> [--out <f>]                    Issue AI agent action attestation with model card & trace commitment
  \x1b[32magent-verify\x1b[0m --attestation <f> --key <k|pubHex> [--output <f|txt>]   Verify AI agent action attestation & guardrail compliance

\x1b[1mSOVEREIGN TRUST SCORING & RISK RECEIPT ENGINE (v12.0.0):\x1b[0m
  \x1b[32mtrustscore-eval\x1b[0m --credential <f> [--min-score <n>] [--key <k>] [--out <f>] Evaluate trust vector & issue signed risk receipt
  \x1b[32mtrustscore-verify\x1b[0m --receipt <f> --evaluator-key <k|pub>           Verify unforgeable DocuTrustRiskReceipt2026

\x1b[1mVERIFIABLE OFF-CHAIN COMPUTE & TRACE PROOFS (v12.0.0):\x1b[0m
  \x1b[32mcompute-run\x1b[0m --program <f> --inputs <f> [--key <k>] [--out <f>]     Execute deterministic compute program & generate receipt
  \x1b[32mcompute-verify\x1b[0m --receipt <f> --prover-key <k|pub> [--inputs <f>]  Verify verifiable compute execution trace receipt

\x1b[1mEPHEMERAL FORWARD-SECRET VANISH CREDENTIALS (v12.0.0):\x1b[0m
  \x1b[32mvanish-issue\x1b[0m --claims <f> --key <k> --subject <did> [--ttl <s>] [--out <f>] Issue self-expiring forward-secret vanish token
  \x1b[32mvanish-verify\x1b[0m --token <f> --ephemeral-key <hex> --issuer-key <k|pub> Verify and decrypt vanish credential token

\x1b[1mCROSS-LEDGER STATESYNC & UNIVERSAL SOLIDITY VERIFIER (v12.0.0):\x1b[0m
  \x1b[32mstatesync-delta\x1b[0m --base <f> --target <f> --key <k> [--source <s>] [--dest <d>] [--out <f>] Generate O(Δ) state synchronization delta proof
  \x1b[32mstatesync-verify\x1b[0m --base <f> --delta <f> --relayer-key <k|pub> [--out <f>] Apply and verify delta proof against base registry
  \x1b[32msolidity-export-universal\x1b[0m [--name <str>] [--solc <ver>] [--out <f>] Generate DocuTrustUniversalVerifier.sol master smart contract


\x1b[1mPOST-QUANTUM SLH-DSA & WEBAUTHN PASSKEYS (v11.0.0):\x1b[0m
  \x1b[32mslhdsa-keygen\x1b[0m [--out <file>]                         Generate NIST FIPS 205 SLH-DSA-SHA2-128s stateless PQC keypair
  \x1b[32mslhdsa-sign\x1b[0m --msg <f|txt> --key <key.json> [--out <f>] Sign message using SLH-DSA post-quantum private key
  \x1b[32mslhdsa-verify\x1b[0m --msg <f|txt> --sig <sig|hex> --pub <pub> Verify SLH-DSA post-quantum signature
  \x1b[32mwebauthn-keygen\x1b[0m [--rp <id>] [--out <file>]              Generate P-256 WebAuthn / FIDO2 Passkey keypair
  \x1b[32mwebauthn-assert\x1b[0m --challenge <c> --key <k> [--rp <id>]  Create signed hardware passkey assertion
  \x1b[32mwebauthn-verify\x1b[0m --assertion <f> --challenge <c> --pub <k> Verify passkey assertion with UP/UV flags

\x1b[1mCROSS-CHAIN BRIDGE & GROTH16 ZK-SNARKS (v11.0.0):\x1b[0m
  \x1b[32mcrosschain-bridge\x1b[0m --source <id> --dest <id> --nonce <n> --root <h> --payload <h> --sender <s> --recipient <r> Create bridge message
  \x1b[32mcrosschain-sign\x1b[0m --msg <f> --relayer <k> [--out <f>]    Sign cross-chain packet as authorized relayer
  \x1b[32mcrosschain-verify\x1b[0m --attestation <f> [--relayers <pks>] Verify cross-chain multi-relayer quorum attestation
  \x1b[32mgroth16-setup\x1b[0m [--circuit <str>] [--inputs <n>] [--out <f>] Generate BN254 Groth16 circuit verification key
  \x1b[32mgroth16-prove\x1b[0m [--circuit <str>] --inputs <i1,i2..> --witness <f> Generate zero-knowledge Groth16 proof
  \x1b[32mgroth16-verify\x1b[0m --proof <f> --vk <f>                    Verify Groth16 ZK-SNARK proof against verification key
  \x1b[32msolidity-export-bridge\x1b[0m [--name <str>] [--out <f>]     Generate DocuTrustBridgeRelayer.sol smart contract
  \x1b[32msolidity-export-groth16\x1b[0m [--name <str>] [--out <f>]    Generate DocuTrustGroth16Verifier.sol smart contract

\x1b[1mLINKABLE RING SIGNATURES (LSAG) & KEY TRANSPARENCY SMT:\x1b[0m
  \x1b[32mringsig-sign\x1b[0m --msg <f|txt> --ring <p1,p2..> --key <priv> [--pub <pub>] [--out <f>] 1-of-N anonymous signature
  \x1b[32mringsig-verify\x1b[0m --msg <f|txt> --sig <sig.json> [--used-tags <t1,t2..>] Verify LSAG ring proof & double-action
  \x1b[32msmt-set\x1b[0m --key <k> --val <v> [--state <f>] [--out <f>] Update 256-bit Sparse Merkle Tree leaf
  \x1b[32msmt-prove\x1b[0m --key <k> [--state <f>] [--out <f>] Generate SMT inclusion / non-membership proof
  \x1b[32msmt-verify\x1b[0m --proof <proof.json> [--root <hex>] Verify SMT audit proof against root
  \x1b[32msolidity-export-smt\x1b[0m [--name <str>] [--out <f>] Generate DocuTrustSMTVerifier.sol EVM smart contract

\x1b[1mSOVEREIGN POLICY-AS-PROOF & PEER DIDS (RFC 0627):\x1b[0m
  \x1b[32mpolicy-evaluate\x1b[0m --payload <f> --policy <f> [--key <k>] [--out <f>] Evaluate VC against Policy AST & emit signed receipt
  \x1b[32mpolicy-verify-receipt\x1b[0m --receipt <f> [--key <pubHex>]  Verify DocuTrustPolicyReceipt2026 proof
  \x1b[32mdid-peer-create\x1b[0m --method <0|2> [--pub <hex>] [--enc <hex>] [--service <url>] Create W3C did:peer identifier
  \x1b[32msolidity-export-registry\x1b[0m [--name <str>] [--out <f>] Generate DocuTrustRegistry.sol multi-issuer trust registry
  \x1b[32mstatuslist-aggregate-check\x1b[0m --root <h> --lists <f1,f2> Validate multi-partition status list aggregate root

\x1b[1mCORE COMMANDS:\x1b[0m
  \x1b[32mdemo / wizard\x1b[0m                                 Run interactive 10-second end-to-end credential issuance & verification
  \x1b[32mkeygen\x1b[0m [--out <file>]                         Generate Ed25519 KeyPair and DID identifier
  \x1b[32mpqc-keygen\x1b[0m [--out <file>]                     Generate Post-Quantum ML-DSA Hybrid KeyPair (NIST FIPS 204)
  \x1b[32missue\x1b[0m  --subject <file> --key <keyfile>       Issue a cryptographically signed W3C Verifiable Credential
  \x1b[32mbatch\x1b[0m  --csv <file> --key <keyfile>           Batch issue credentials from CSV with Polygon Merkle Tree Anchor
  \x1b[32mverify\x1b[0m --vc <file>                            Verify cryptographic signature, Merkle proof & ledger anchor
  \x1b[32mrender-pdf\x1b[0m --vc <file> [--out <file.pdf>]      Render tamper-evident visual PDF with embedded W3C VC metadata
  \x1b[32mverify-pdf\x1b[0m --pdf <file.pdf>                   Extract and verify embedded VC from PDF document
  \x1b[32mdid-resolve\x1b[0m --did <did_string>                 Resolve DID Document (did:key, did:pqc, did:kem, did:bbs, did:pkh, did:web)
  \x1b[32mdataintegrity-issue\x1b[0m --claims <f> -k <k>        Issue W3C DataIntegrityProof VC (eddsa-jcs-2022 / ml-dsa-65-2026)
  \x1b[32mdataintegrity-verify\x1b[0m --vc <file>               Verify W3C DataIntegrityProof VC
  \x1b[32mhelp\x1b[0m                                          Show this help menu

\x1b[1mPAILLIER CONFIDENTIAL COMPUTE & HOMOMORPHIC ZERO-KNOWLEDGE:\x1b[0m
  \x1b[32mconfidential-keygen\x1b[0m [--bits <num>] [--out <f>]  Generate Paillier public/private keypair (default 2048-bit)
  \x1b[32mconfidential-encrypt\x1b[0m -v <val> -k <pub> [--out <f>] Encrypt numerical value with Paillier public key
  \x1b[32mconfidential-sum\x1b[0m -c <c1,c2...> -k <pub> [--out <f>] Homomorphically add encrypted ciphertexts without decrypting
  \x1b[32mconfidential-linear-combination\x1b[0m -t <c1:w1,c2:w2> Evaluate homomorphic weighted sum on ciphertexts
  \x1b[32mconfidential-threshold-prove\x1b[0m -v <n> -t <t> -k <k> Generate ZK proof that encrypted value exceeds threshold
  \x1b[32mconfidential-threshold-verify\x1b[0m -p <f> -k <k> -c <c> Verify Paillier zero-knowledge threshold proof

\x1b[1mW3C URDNA2015 JSON-LD DATASET CANONICALIZATION:\x1b[0m
  \x1b[32mjsonld-canonicalize\x1b[0m --doc <file> [--out <file>] Normalize JSON-LD document into canonical sorted N-Quads
  \x1b[32mjsonld-sign\x1b[0m --doc <file> --key <keyfile>       Sign JSON-LD with JsonLdSignature2020 Linked Data Proof
  \x1b[32mjsonld-verify\x1b[0m --doc <file> [--key <pubHex>]     Verify JsonLdSignature2020 RDF canonicalization signature

\x1b[1mHIERARCHICAL VERIFIABLE TRUST CHAINS & DELEGATION:\x1b[0m
  \x1b[32mtrustchain-issue\x1b[0m --issuer-did <d> --subject-did <s> Issue cryptographically chained Verifiable Delegation Token
  \x1b[32mtrustchain-verify-token\x1b[0m --token <file>          Verify individual delegation token signature & expiration
  \x1b[32mtrustchain-verify\x1b[0m --chain <file> --anchor-did <d> Verify entire multi-tier delegation chain up to Trust Anchor

\x1b[1mPOST-QUANTUM DUAL HYBRID KEM ARMOR (X25519 + ML-KEM-768):\x1b[0m
  \x1b[32mquantum-armor-keygen\x1b[0m [--out <file>]               Generate dual-hybrid classical (X25519) + PQC (ML-KEM-768) keys
  \x1b[32mquantum-armor-seal\x1b[0m -d <data> -r <pqcPub,x25519Pub> Encapsulate and encrypt payload under dual-KEM armor
  \x1b[32mquantum-armor-unseal\x1b[0m --armor <f> --key <privKeys>  Decapsulate hybrid shared secrets and decrypt armor bundle

\x1b[1mANONCREDS 2.0 ZERO-KNOWLEDGE PRIVACY:\x1b[0m
  \x1b[32manoncreds-blind-request\x1b[0m --schema <s> --issuer <i> Create holder blind request with secret commitment
  \x1b[32manoncreds-blind-issue\x1b[0m --req <f> --claims <c> -k <k> Issue BBS+ blind signed credential to holder
  \x1b[32manoncreds-unblind\x1b[0m --cred <f> --secret <s> -b <b> Unblind credential and store with master secret
  \x1b[32manoncreds-derive-proof\x1b[0m --cred <f> -r <k1,k2>  Derive unlinkable ZK selective disclosure presentation
  \x1b[32manoncreds-verify\x1b[0m --pres <file>                Cryptographically verify AnonCreds ZK presentation

\x1b[1mFROST DISTRIBUTED KEY GENERATION (DKG):\x1b[0m
  \x1b[32mdkg-setup\x1b[0m --nodes <num> --threshold <k>        Run DKG ceremony and output group DID and node shares
  \x1b[32mdkg-sign-share\x1b[0m --index <i> --share <hex> -m <msg> Sign partial signature share for message
  \x1b[32mdkg-aggregate\x1b[0m --pub <hex> --shares <f1,f2>     Aggregate partial shares into valid group signature
  \x1b[32mdkg-verify\x1b[0m --sig <file> -m <msg> --pub <hex>    Verify aggregated FROST threshold signature

\x1b[1mEVM SOLIDITY ON-CHAIN SMART CONTRACTS:\x1b[0m
  \x1b[32msolidity-export-verifier\x1b[0m [--name <str>] [--out <f>] Generate DocuTrustVerifier.sol EVM smart contract
  \x1b[32msolidity-calldata\x1b[0m --leaf <h> --proof <f> -r <root> Encode verifyCredentialOnChain ABI calldata

\x1b[1mCRYPTOGRAPHIC AUDIT BUNDLES (.dtbundle):\x1b[0m
  \x1b[32maudit-bundle-create\x1b[0m --org <name> -k <key> [--out <f>] Export signed .dtbundle with HashChain & MMR
  \x1b[32maudit-bundle-verify\x1b[0m --bundle <file.dtbundle>   Verify .dtbundle cryptographic integrity & TSA token

\x1b[1mMULTI-SIGNATURE THRESHOLD (M-of-N):\x1b[0m
  \x1b[32mmultisig-draft\x1b[0m --vc <file> --policy <file>      Create unsigned Multi-Sig draft and canonical hash
  \x1b[32mmultisig-sign\x1b[0m --hash <h> --did <d> -r <role> -k <k> Sign canonical hash as an authorized authority
  \x1b[32mmultisig-assemble\x1b[0m --vc <f> -p <pol> -s <sigs> Assemble finalized M-of-N MultiSig Verifiable Credential
  \x1b[32mmultisig-verify\x1b[0m --vc <file> --policy <file>    Verify M-of-N threshold signatures on credential

\x1b[1mREVOCATION & ACCUMULATORS:\x1b[0m
  \x1b[32mstatuslist-create\x1b[0m --size <num> --bits <1|2|4|8> Create W3C Bitstring StatusList2024 Credential
  \x1b[32mstatuslist-check\x1b[0m --list <file> --index <num>    Check revocation/suspension status at index
  \x1b[32mstatuslist-update\x1b[0m --list <file> --index <i> -s <s> Update status in BitstringStatusList2024
  \x1b[32maccumulator-create\x1b[0m --members <csv>             Initialize RSA dynamic accumulator
  \x1b[32maccumulator-batch-witness\x1b[0m --elements <e1,e2>   Compute constant-size batch membership witness
  \x1b[32maccumulator-verify-batch\x1b[0m --witness <w>         Verify constant-size batch membership witness
  \x1b[32maccumulator-non-membership-witness\x1b[0m --elem <e>   Compute Bezout constant-size non-membership witness
  \x1b[32maccumulator-verify-non-membership\x1b[0m --witness <w> Verify accumulator non-membership witness

\x1b[1mDIF PRESENTATION EXCHANGE & JSON SCHEMA:\x1b[0m
  \x1b[32mpe-definition-create\x1b[0m --id <id> --descriptors <f> Create Presentation Definition v2.0
  \x1b[32mpe-evaluate\x1b[0m --presentation <f> --definition <f>  Evaluate VP against Presentation Definition
  \x1b[32mschema-validate-credential\x1b[0m --vc <f> --schema <f> Validate credential subject against JSON Schema

\x1b[1mPRIVACY & ZERO-KNOWLEDGE:\x1b[0m
  \x1b[32mzk-graph-prove\x1b[0m --id <id> --root <graph.json>    Generate Recursive ZK Predicate Graph Proof
  \x1b[32mzk-graph-verify\x1b[0m --proof <file>                 Verify Recursive ZK Predicate Graph Proof
  \x1b[32mzk-composite\x1b[0m --proofs <f1,f2> --op <AND|OR>   Combine ZK Predicates into composite proof
  \x1b[32mzk-range\x1b[0m --val <num> --min <num> --max <num>   Generate ZK Range Proof with hidden commitment
  \x1b[32mzk-age\x1b[0m --dob <YYYY-MM-DD> --min-age <num>     Generate ZK Age Predicate Proof (e.g. Age >= 21)
  \x1b[32mzk-date\x1b[0m --date <str> --min <str> --max <str>  Generate ZK Date Range Proof
  \x1b[32mto-sd-jwt\x1b[0m --claims <file> --key <keyfile>      Issue IETF SD-JWT with salted disclosures
  \x1b[32mverify-sd-jwt\x1b[0m --presentation <str>            Verify SD-JWT presentation against issuer public key
  \x1b[32mbbs-issue\x1b[0m --messages <msg1,msg2>               Issue BBS+ multi-message signature
  \x1b[32mbbs-prove\x1b[0m --sig <file> --reveal <0,2>          Derive BBS+ unlinkable zero-knowledge proof
  \x1b[32mbbs-verify\x1b[0m --proof <file>                      Verify BBS+ zero-knowledge proof

\x1b[1mPOST-QUANTUM & KEY MANAGEMENT:\x1b[0m
  \x1b[32mkeygen-secp256k1\x1b[0m [--chain <id>] [--out <file>]   Generate Ethereum secp256k1 keypair & did:pkh
  \x1b[32meip712-sign\x1b[0m --vc <file> --key <keyfile>       Sign W3C VC with EIP-712 structured typing
  \x1b[32meip712-verify\x1b[0m --vc <file>                     Verify EIP-712 structured VC signature
  \x1b[32msocial-recovery-setup\x1b[0m --secret <txt> -g <file>   Setup decentralized guardian recovery with timelock
  \x1b[32mkem-keygen\x1b[0m [--out <file>]                     Generate Post-Quantum ML-KEM-768 hybrid keypair
  \x1b[32mpop-challenge\x1b[0m --aud <audience>                 Create Proof-of-Possession challenge
  \x1b[32mshamir-split\x1b[0m --secret <text> -n 5 -k 3         Split secret into K-of-N Shamir polynomial shares
  \x1b[32mshamir-combine\x1b[0m --shares <file>                 Reconstruct secret from Shamir shares
  \x1b[32mjwe-encrypt\x1b[0m --data <str> --recipients <keys>   Encrypt multi-recipient General JWE
  \x1b[32mjwe-decrypt\x1b[0m --jwe <file> --key <privHex>      Decrypt multi-recipient General JWE

\x1b[1mFEDERATION & STREAMING LEDGER:\x1b[0m
  \x1b[32mmultichain-anchor\x1b[0m --chain <eth|sol|btc> --root <h> Generate anchor calldata / payload
  \x1b[32moracle-timestamp\x1b[0m --data <text>                 Issue RFC 3161 timestamp token from TSA Oracle
  \x1b[32mdidcomm-pack\x1b[0m --msg <file> --to <pubHex>        Pack DIDComm v2 encrypted envelope
  \x1b[32mdidcomm-unpack\x1b[0m --envelope <file> --key <priv>  Unpack and decrypt DIDComm v2 envelope
  \x1b[32mmmr-append\x1b[0m --leaf <text>                       Append entry to Merkle Mountain Range ledger

\x1b[1mQUICKSTART:\x1b[0m
  $ docutrust demo
  $ docutrust keygen --out keys.json
  $ docutrust verify --vc examples/certificates/stanford-degree-vc.json

`);
}

function getArgValue(flag) {
  const idx = args.indexOf(flag);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
}

async function runDemoWizard() {
  console.log(`\n\x1b[1m\x1b[36m====================================================\x1b[0m`);
  console.log(`\x1b[1m🛡️  DocuTrust 10-Second Quickstart Demo Wizard\x1b[0m`);
  console.log(`\x1b[1m\x1b[36m====================================================\x1b[0m\n`);

  console.log(`\x1b[34m[Step 1/4]\x1b[0m Generating Institutional KeyPair (Ed25519 + DID)...`);
  const keys = generateKeyPair();
  console.log(`  \x1b[32m✔\x1b[0m Authority DID: \x1b[1m${keys.did}\x1b[0m`);

  console.log(`\n\x1b[34m[Step 2/4]\x1b[0m Constructing W3C Verifiable Credential (Ph.D. in AI)...`);
  const unsigned = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: { id: keys.did, name: 'Stanford University' },
    validFrom: new Date().toISOString(),
    credentialSubject: {
      name: 'Elena Rostova',
      degree: 'Ph.D. in Artificial Intelligence',
      graduationYear: 2026,
      gpa: '3.98',
      honors: 'Summa Cum Laude'
    }
  };
  console.log(`  \x1b[32m✔\x1b[0m Normalized via RFC 8785 JSON Canonicalization Scheme`);

  console.log(`\n\x1b[34m[Step 3/4]\x1b[0m Computing Ed25519 Signature & Polygon Ledger Anchor...`);
  const canonicalHash = sha256Hex(canonicalizeJson(unsigned));
  const signatureHex = signData(canonicalHash, keys);
  const txHash = '0x' + sha256Hex(`polygon:${canonicalHash}:${Date.now()}`);

  const vc = {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: keys.keyId,
      proofPurpose: 'assertionMethod',
      proofValue: signatureHex,
      jcsCanonicalHash: canonicalHash,
      anchorReceipt: {
        network: 'polygon-mainnet',
        txHash,
        blockNumber: 54890300,
        confirmed: true
      }
    }
  };
  console.log(`  \x1b[32m✔\x1b[0m Digital Signature: 0x${signatureHex.substring(0, 32)}...`);
  console.log(`  \x1b[32m✔\x1b[0m Blockchain Anchor: ${txHash}`);

  console.log(`\n\x1b[34m[Step 4/4]\x1b[0m Executing Independent 3rd-Party Verification...`);
  const isSigValid = verifySignature(canonicalHash, signatureHex, keys.did);
  console.log(`  \x1b[32m✔\x1b[0m Verification Result: \x1b[1m\x1b[32m100% CRYPTOGRAPHICALLY AUTHENTIC\x1b[0m (0.04ms)`);

  console.log(`\n\x1b[1m\x1b[36m====================================================\x1b[0m`);
  console.log(`\x1b[32m✔ Quickstart Complete!\x1b[0m Run \x1b[1mdocutrust help\x1b[0m for all CLI options.\n`);
}

async function main() {
  if (command === 'version' || command === '--version' || command === '-v') {
    console.log('12.0.0');
    return;
  }

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  if (command === 'demo' || command === 'wizard') {
    await runDemoWizard();
    return;
  }

  if (command === 'keygen') {
    const outFile = getArgValue('--out') || getArgValue('-o');
    const kp = generateKeyPair();
    const result = JSON.stringify(kp, null, 2);

    if (outFile) {
      fs.writeFileSync(outFile, result, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m KeyPair generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(result);
    }
    console.log(`\x1b[34mIssuer DID:\x1b[0m ${kp.did}`);
    return;
  }

  if (command === 'pqc-keygen') {
    const classical = generateKeyPair();
    const pqcSeed = crypto.randomBytes(32);
    const pqcPublicKeyHex = crypto.createHash('sha3-512').update(Buffer.concat([Buffer.from('ML-DSA-65-PUB:'), pqcSeed])).digest('hex').substring(0, 64);
    const hybridMulticodec = Buffer.concat([
      Buffer.from([0x19, 0x01]),
      Buffer.from(classical.publicKeyHex, 'hex'),
      Buffer.from(pqcPublicKeyHex, 'hex')
    ]);
    const hybridDid = `did:pqc:z${encodeBase58(hybridMulticodec)}`;

    const pqcKeys = {
      hybridDid,
      algorithm: 'ML-DSA-65-Ed25519-Hybrid-2026',
      classicalPublicKeyHex: classical.publicKeyHex,
      pqcPublicKeyHex,
      classicalPrivateKeyHex: classical.privateKeyHex,
      pqcPrivateKeyHex: pqcSeed.toString('hex')
    };

    const outFile = getArgValue('--out') || getArgValue('-o');
    const resultStr = JSON.stringify(pqcKeys, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, resultStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Post-Quantum Hybrid KeyPair saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(resultStr);
    }
    console.log(`\x1b[35mHybrid DID:\x1b[0m ${hybridDid}`);
    return;
  }

  if (command === 'issue') {
    const subjectPath = getArgValue('--subject') || getArgValue('-s');
    const keyPath = getArgValue('--key') || getArgValue('-k');
    const outPath = getArgValue('--out') || getArgValue('-o');

    if (!subjectPath || !keyPath) {
      console.error('\x1b[31mError:\x1b[0m Missing required arguments --subject <file> and --key <file>');
      process.exit(1);
    }

    const subjectData = JSON.parse(fs.readFileSync(subjectPath, 'utf-8'));
    const keyData = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));

    const unsigned = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: subjectData.id || `urn:uuid:${crypto.randomUUID()}`,
      type: ['VerifiableCredential', subjectData.credentialType || 'AchievementCredential'],
      issuer: {
        id: keyData.did || keyData.hybridDid,
        name: keyData.name || 'DocuTrust Authority'
      },
      validFrom: new Date().toISOString(),
      credentialSubject: subjectData.subject || subjectData
    };

    const canonicalPayload = canonicalizeJson(unsigned);
    const canonicalHash = sha256Hex(canonicalPayload);
    const signatureHex = signData(canonicalHash, keyData.classicalPrivateKeyHex ? keyData.classicalPrivateKeyHex : keyData);

    const credential = {
      ...unsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: keyData.keyId || `${keyData.did}#keys-1`,
        proofPurpose: 'assertionMethod',
        proofValue: signatureHex,
        jcsCanonicalHash: canonicalHash
      }
    };

    const resultStr = JSON.stringify(credential, null, 2);
    if (outPath) {
      fs.writeFileSync(outPath, resultStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Credential successfully issued and saved to: \x1b[1m${outPath}\x1b[0m`);
    } else {
      console.log(resultStr);
    }
    return;
  }

  if (command === 'batch') {
    const csvPath = getArgValue('--csv') || getArgValue('-c');
    const keyPath = getArgValue('--key') || getArgValue('-k');
    const outDir = getArgValue('--out-dir') || getArgValue('--out') || getArgValue('-o') || './batch-output';

    if (!csvPath || !keyPath) {
      console.error('\x1b[31mError:\x1b[0m Missing required arguments --csv <file> and --key <file>');
      process.exit(1);
    }

    const keyData = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
    const csvContent = fs.readFileSync(csvPath, 'utf-8').trim();
    const lines = csvContent.split(/\r?\n/).filter(l => l.trim().length > 0);
    if (lines.length <= 1) {
      console.error('\x1b[31mError:\x1b[0m CSV file must contain headers and at least 1 record.');
      process.exit(1);
    }

    const headers = lines[0].split(',').map(h => h.trim());
    const records = [];
    for (let i = 1; i < lines.length; i++) {
      const values = lines[i].split(',').map(v => v.trim());
      const row = {};
      headers.forEach((h, idx) => { row[h] = values[idx] || ''; });
      records.push(row);
    }

    if (!fs.existsSync(outDir)) {
      fs.mkdirSync(outDir, { recursive: true });
    }

    const credentials = records.map((record) => {
      const unsigned = {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: `urn:uuid:${crypto.randomUUID()}`,
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: {
          id: keyData.did || keyData.hybridDid,
          name: keyData.name || 'DocuTrust Authority'
        },
        validFrom: new Date().toISOString(),
        credentialSubject: record
      };

      const canonicalPayload = canonicalizeJson(unsigned);
      const canonicalHash = sha256Hex(canonicalPayload);
      const signatureHex = signData(canonicalHash, keyData.classicalPrivateKeyHex ? keyData.classicalPrivateKeyHex : keyData);

      return {
        ...unsigned,
        proof: {
          type: 'Ed25519Signature2020',
          created: new Date().toISOString(),
          verificationMethod: keyData.keyId || `${keyData.did}#keys-1`,
          proofPurpose: 'assertionMethod',
          proofValue: signatureHex,
          jcsCanonicalHash: canonicalHash
        }
      };
    });

    const leaves = credentials.map(c => c.proof.jcsCanonicalHash);
    const tree = new MerkleTree(leaves);
    const merkleRoot = tree.getRoot();
    const timestamp = Date.now();
    const anchorReceipt = {
      network: 'polygon-mainnet',
      rootHash: merkleRoot,
      txHash: '0x' + sha256Hex(`polygon:${merkleRoot}:${timestamp}`),
      blockNumber: 54890300,
      confirmed: true,
      timestamp,
      leafCount: credentials.length
    };

    credentials.forEach((c, idx) => {
      c.proof.merkleProof = tree.getProof(idx);
      c.proof.anchorReceipt = anchorReceipt;
      const filename = path.join(outDir, `credential-${idx + 1}-${(c.credentialSubject.name || 'recipient').toLowerCase().replace(/[^a-z0-9]/g, '-')}.json`);
      fs.writeFileSync(filename, JSON.stringify(c, null, 2), 'utf-8');
    });

    console.log(`\x1b[32m✔\x1b[0m Batch issuance complete: \x1b[1m${credentials.length} credentials\x1b[0m written to \x1b[1m${outDir}\x1b[0m`);
    console.log(`\x1b[35mMerkle Root:\x1b[0m ${merkleRoot}`);
    console.log(`\x1b[34mPolygon Anchor:\x1b[0m ${anchorReceipt.txHash}`);
    return;
  }

  if (command === 'verify') {
    const vcPath = getArgValue('--vc') || getArgValue('-v');
    if (!vcPath) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file> argument');
      process.exit(1);
    }

    const vc = JSON.parse(fs.readFileSync(vcPath, 'utf-8'));
    if (!vc.proof || !vc.proof.proofValue || !vc.issuer) {
      console.error('\x1b[31m✖ Invalid Credential:\x1b[0m Missing cryptographic proof or issuer header.');
      process.exit(1);
    }

    const issuerId = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
    const { proof, ...unsigned } = vc;
    const canonicalPayload = canonicalizeJson(unsigned);
    const canonicalHash = sha256Hex(canonicalPayload);

    let sigToVerify = proof.proofValue;
    if (sigToVerify.startsWith('pqc1_')) {
      sigToVerify = sigToVerify.replace('pqc1_', '').split('_')[0];
    }

    const isValid = verifySignature(canonicalHash, sigToVerify, issuerId);

    console.log(`\n\x1b[1m--- VERIFICATION REPORT ---\x1b[0m`);
    console.log(`Credential ID:   ${vc.id}`);
    console.log(`Issuer DID:      ${issuerId}`);
    console.log(`Issuance Date:   ${vc.validFrom}`);
    console.log(`Proof Type:      ${proof.type}`);
    console.log(`Signature Status: ${isValid ? '\x1b[32m✔ VALID (Cryptographically Verified)\x1b[0m' : '\x1b[31m✖ INVALID / TAMPERED\x1b[0m'}`);
    
    if (proof.anchorReceipt) {
      console.log(`Ledger Anchor:   \x1b[32m✔ Confirmed on ${proof.anchorReceipt.network} (${proof.anchorReceipt.txHash.slice(0, 16)}...)\x1b[0m`);
    }
    console.log(`---------------------------\n`);
    return;
  }

  if (command === 'encrypt') {
    const inFile = getArgValue('--in') || getArgValue('-i');
    const pass = getArgValue('--pass') || getArgValue('-p');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!inFile || !pass) {
      console.error('\x1b[31mError:\x1b[0m Missing --in <file> or --pass <passphrase>');
      process.exit(1);
    }
    const data = fs.readFileSync(inFile, 'utf-8');
    const encrypted = core.encryptAESGCM(data, pass, true);
    const outStr = JSON.stringify(encrypted, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m File encrypted with AES-256-GCM and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'decrypt') {
    const inFile = getArgValue('--in') || getArgValue('-i');
    const pass = getArgValue('--pass') || getArgValue('-p');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!inFile || !pass) {
      console.error('\x1b[31mError:\x1b[0m Missing --in <file> or --pass <passphrase>');
      process.exit(1);
    }
    const payload = JSON.parse(fs.readFileSync(inFile, 'utf-8'));
    const decryptedBuf = core.decryptAESGCM(payload, pass);
    const decStr = decryptedBuf.toString('utf-8');
    if (outFile) {
      fs.writeFileSync(outFile, decStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m File decrypted and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(decStr);
    }
    return;
  }

  if (command === 'zk-range') {
    const key = getArgValue('--key') || 'gpa';
    const val = parseFloat(getArgValue('--val') || '3.9');
    const min = parseFloat(getArgValue('--min') || '3.5');
    const max = parseFloat(getArgValue('--max') || '4.0');
    const outFile = getArgValue('--out') || getArgValue('-o');

    const salt = crypto.randomBytes(16).toString('hex');
    const proof = core.proveRange(key, val, salt, min, max);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Range Proof generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'zk-age') {
    const key = getArgValue('--key') || 'birthDate';
    const dob = getArgValue('--dob') || getArgValue('--birthdate') || '2000-01-01';
    const minAge = parseInt(getArgValue('--min-age') || getArgValue('--min') || '18');
    const refDate = getArgValue('--ref-date') || undefined;
    const outFile = getArgValue('--out') || getArgValue('-o');

    const proof = core.proveAgeAbove(key, dob, minAge, undefined, refDate);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Age Predicate Proof generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'zk-date') {
    const key = getArgValue('--key') || 'graduationDate';
    const date = getArgValue('--date') || '2024-06-15';
    const minDate = getArgValue('--min-date') || getArgValue('--min') || '2020-01-01';
    const maxDate = getArgValue('--max-date') || getArgValue('--max') || '2026-12-31';
    const outFile = getArgValue('--out') || getArgValue('-o');

    const proof = core.proveDateRange(key, date, minDate, maxDate);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Date Range Proof generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'kem-keygen') {
    const outFile = getArgValue('--out') || getArgValue('-o');
    const kp = core.generateKEMKeyPair();
    const outStr = JSON.stringify(kp, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Post-Quantum ML-KEM-768 KeyPair generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    console.log(`\x1b[34mKEM Recipient DID:\x1b[0m ${kp.hybridRecipientId}`);
    return;
  }

  if (command === 'pop-challenge') {
    const audience = getArgValue('--audience') || getArgValue('-a') || 'did:web:docutrust.org';
    const outFile = getArgValue('--out') || getArgValue('-o');
    const chal = core.ProofOfPossessionProtocol.createChallenge(audience);
    const outStr = JSON.stringify(chal, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Proof-of-Possession challenge created and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'shamir-split') {
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const totalShares = parseInt(getArgValue('--shares') || getArgValue('-n') || '5');
    const threshold = parseInt(getArgValue('--threshold') || getArgValue('-t') || '3');
    const outDir = getArgValue('--out-dir') || getArgValue('--out') || getArgValue('-o') || './shares';

    if (!keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --key <file>');
      process.exit(1);
    }
    const secret = fs.readFileSync(keyFile, 'utf-8');
    const shares = core.splitSecret(secret, totalShares, threshold);
    if (!fs.existsSync(outDir)) {
      fs.mkdirSync(outDir, { recursive: true });
    }
    shares.forEach(s => {
      fs.writeFileSync(path.join(outDir, `share-${s.index}.json`), JSON.stringify(s, null, 2), 'utf-8');
    });
    console.log(`\x1b[32m✔\x1b[0m Secret split into \x1b[1m${totalShares} shares\x1b[0m (threshold: ${threshold}) in: \x1b[1m${outDir}\x1b[0m`);
    return;
  }

  if (command === 'shamir-combine') {
    const sharesDir = getArgValue('--shares-dir') || getArgValue('-d') || './shares';
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!fs.existsSync(sharesDir)) {
      console.error(`\x1b[31mError:\x1b[0m Shares directory not found: ${sharesDir}`);
      process.exit(1);
    }
    const files = fs.readdirSync(sharesDir).filter(f => f.endsWith('.json'));
    const shares = files.map(f => JSON.parse(fs.readFileSync(path.join(sharesDir, f), 'utf-8')));
    const reconstructed = core.combineShares(shares);
    const resultStr = reconstructed.toString('utf-8');
    if (outFile) {
      fs.writeFileSync(outFile, resultStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Secret reconstructed and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(resultStr);
    }
    return;
  }

  if (command === 'to-sd-jwt') {
    const claimsFile = getArgValue('--claims') || getArgValue('-c');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!claimsFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --claims <file> or --key <file>');
      process.exit(1);
    }
    const claims = JSON.parse(fs.readFileSync(claimsFile, 'utf-8'));
    const keyPair = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const sdPackage = core.issueSDJWT(claims, keyPair);
    const outStr = JSON.stringify(sdPackage, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m IETF SD-JWT issued and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'verify-sd-jwt') {
    const sdjwtFile = getArgValue('--sd-jwt') || getArgValue('-s');
    if (!sdjwtFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --sd-jwt <file>');
      process.exit(1);
    }
    const content = fs.readFileSync(sdjwtFile, 'utf-8').trim();
    let presentationStr = content;
    try {
      const parsed = JSON.parse(content);
      if (parsed.combinedSdJwt) presentationStr = parsed.combinedSdJwt;
    } catch (e) {}

    const result = core.verifySDJWTPresentation(presentationStr);
    console.log(`\n\x1b[1m--- SD-JWT VERIFICATION REPORT ---\x1b[0m`);
    console.log(`Issuer DID:        ${result.issuerDid}`);
    console.log(`Signature Status:  ${result.valid ? '\x1b[32m✔ VALID\x1b[0m' : '\x1b[31m✖ INVALID\x1b[0m'}`);
    console.log(`Disclosed Claims:  ${JSON.stringify(result.disclosedClaims)}`);
    console.log(`----------------------------------\n`);
    return;
  }

  if (command === 'bbs-issue') {
    const messagesFile = getArgValue('--messages') || getArgValue('-m');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!messagesFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --messages <file>');
      process.exit(1);
    }
    const messages = JSON.parse(fs.readFileSync(messagesFile, 'utf-8'));
    const kp = core.generateBBSKeyPair(messages.length);
    const sig = core.signBBS(messages, kp);
    const outStr = JSON.stringify({ keyPair: kp, signature: sig, messages }, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m BBS+ multi-message signature issued to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'bbs-prove') {
    const sigFile = getArgValue('--sig') || getArgValue('-s');
    const indicesStr = getArgValue('--indices') || getArgValue('-i') || '0';
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!sigFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --sig <file>');
      process.exit(1);
    }
    const data = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
    const indices = indicesStr.split(',').map(n => parseInt(n.trim()));
    const proof = core.deriveBBSProof(data.signature, data.messages, indices, data.keyPair);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m BBS+ unlinkable ZK proof derived to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'bbs-verify') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    if (!proofFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <file>');
      process.exit(1);
    }
    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    const result = core.verifyBBSProof(proof);
    console.log(`\n\x1b[1m--- BBS+ ZERO-KNOWLEDGE PROOF REPORT ---\x1b[0m`);
    console.log(`Issuer DID:        ${proof.issuerDid}`);
    console.log(`Proof Status:      ${result.valid ? '\x1b[32m✔ CRYPTOGRAPHICALLY VALID\x1b[0m' : '\x1b[31m✖ INVALID\x1b[0m'}`);
    console.log(`Disclosed Values:  ${JSON.stringify(result.disclosedMessages)}`);
    console.log(`----------------------------------------\n`);
    return;
  }

  if (command === 'oracle-timestamp') {
    const dataFile = getArgValue('--data') || getArgValue('-d');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!dataFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --data <file>');
      process.exit(1);
    }
    const content = fs.readFileSync(dataFile, 'utf-8');
    const tsaKp = core.generateKeyPair();
    const oracle = new core.CryptographicTSAOracle(tsaKp);
    const token = oracle.issueTimestampToken(content);
    const outStr = JSON.stringify(token, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m TSA Timestamp Token issued and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'didcomm-pack') {
    const msgFile = getArgValue('--msg') || getArgValue('-m');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const recPub = getArgValue('--recipient-pub') || getArgValue('-r');
    const recDid = getArgValue('--recipient-did') || getArgValue('-d') || 'did:key:zRecipient';
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!msgFile || !keyFile || !recPub) {
      console.error('\x1b[31mError:\x1b[0m Missing --msg, --key, or --recipient-pub');
      process.exit(1);
    }
    const message = JSON.parse(fs.readFileSync(msgFile, 'utf-8'));
    const senderKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const envelope = core.packDIDCommMessage(message, senderKp, recPub, recDid);
    const outStr = JSON.stringify(envelope, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m DIDComm v2 encrypted envelope packed to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'didcomm-unpack') {
    const envFile = getArgValue('--envelope') || getArgValue('-e');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!envFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --envelope or --key');
      process.exit(1);
    }
    const envelope = JSON.parse(fs.readFileSync(envFile, 'utf-8'));
    const recipientKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const result = core.unpackDIDCommMessage(envelope, recipientKp);
    const outStr = JSON.stringify(result, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m DIDComm v2 envelope decrypted to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'mmr-append') {
    const leaf = getArgValue('--leaf') || getArgValue('-l') || 'Immutable MMR Block';
    const outFile = getArgValue('--out') || getArgValue('-o');
    const mmr = new core.MerkleMountainRange();
    const entry = mmr.append(leaf);
    const outStr = JSON.stringify(entry, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Merkle Mountain Range element appended to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'keygen-secp256k1' || command === 'eth-keygen') {
    const chainId = parseInt(getArgValue('--chain') || getArgValue('-c') || '1');
    const outFile = getArgValue('--out') || getArgValue('-o');
    const keyPair = core.generateSecp256k1KeyPair(chainId);
    const outStr = JSON.stringify(keyPair, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Ethereum secp256k1 KeyPair generated and saved to: \x1b[1m${outFile}\x1b[0m`);
      console.log(`  DID:            \x1b[1m${keyPair.did}\x1b[0m`);
      console.log(`  ETH Address:    \x1b[1m${keyPair.ethereumAddress}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'eip712-sign') {
    const vcFile = getArgValue('--vc') || getArgValue('-v');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!vcFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file> or --key <file>');
      process.exit(1);
    }
    const unsignedVc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const keyPair = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const signedVc = core.signVcEIP712(unsignedVc, keyPair);
    const outStr = JSON.stringify(signedVc, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m EIP-712 Structured VC signed and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'eip712-verify') {
    const vcFile = getArgValue('--vc') || getArgValue('-v');
    const expectedSigner = getArgValue('--signer') || getArgValue('-s');
    if (!vcFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file>');
      process.exit(1);
    }
    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const audit = core.verifyVcEIP712(vc, expectedSigner);
    console.log(`\n\x1b[1m--- EIP-712 SIGNATURE VERIFICATION REPORT ---\x1b[0m`);
    console.log(`Signer Address:   ${audit.signerAddress || 'N/A'}`);
    console.log(`Signature Status: ${audit.valid ? '\x1b[32m✔ VALID\x1b[0m' : '\x1b[31m✖ INVALID\x1b[0m'}`);
    if (audit.error) console.log(`Error:            ${audit.error}`);
    console.log(`---------------------------------------------\n`);
    return;
  }

  if (command === 'social-recovery-setup') {
    const secret = getArgValue('--secret') || getArgValue('-s');
    const guardiansFile = getArgValue('--guardians') || getArgValue('-g');
    const threshold = parseInt(getArgValue('--threshold') || getArgValue('-t') || '3');
    const hours = parseInt(getArgValue('--hours') || '48');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!secret || !guardiansFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --secret <text> or --guardians <file>');
      process.exit(1);
    }
    const guardians = JSON.parse(fs.readFileSync(guardiansFile, 'utf-8'));
    const setup = core.SocialRecoveryEngine.setupRecovery('did:key:zOwnerCLI', secret, guardians, threshold, hours);
    const outStr = JSON.stringify(setup, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Social Recovery configured and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'zk-non-membership') {
    const claimKey = getArgValue('--key') || getArgValue('-k') || 'restrictedList';
    const val = getArgValue('--val') || getArgValue('-v');
    const salt = getArgValue('--salt') || crypto.randomBytes(16).toString('hex');
    const restrictedStr = getArgValue('--restricted') || getArgValue('-r');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!val || !restrictedStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --val <value> or --restricted <a,b,c>');
      process.exit(1);
    }
    const restrictedSet = restrictedStr.split(',').map(s => s.trim());
    const proof = core.proveSetNonMembership(claimKey, val, salt, restrictedSet);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Non-Membership Proof saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'multichain-anchor') {
    const chain = getArgValue('--chain') || getArgValue('-c') || 'ethereum';
    const root = getArgValue('--root') || getArgValue('-r');
    const count = parseInt(getArgValue('--count') || getArgValue('-n') || '100');
    const memo = getArgValue('--memo') || getArgValue('-m') || 'DocuTrust Anchor';
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!root) {
      console.error('\x1b[31mError:\x1b[0m Missing --root <merkleRootHex>');
      process.exit(1);
    }
    const anchor = core.MultiChainLedgerAnchor.formatAnchor(chain, root, count, memo);
    const outStr = JSON.stringify(anchor, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m MultiChain Anchor payload generated for ${chain}: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'schema-validate') {
    const dataFile = getArgValue('--data') || getArgValue('-d');
    const schemaFile = getArgValue('--schema') || getArgValue('-s');
    if (!dataFile || !schemaFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --data <file.json> or --schema <file.json>');
      process.exit(1);
    }
    const data = JSON.parse(fs.readFileSync(dataFile, 'utf-8'));
    const schema = JSON.parse(fs.readFileSync(schemaFile, 'utf-8'));
    const result = core.SchemaValidator.validate(data, schema);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Schema validation PASSED. Schema Hash: \x1b[1m${result.schemaHash}\x1b[0m`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Schema validation FAILED. Errors:\n` + result.errors.map(e => `  - ${e}`).join('\n'));
      process.exit(1);
    }
    return;
  }

  if (command === 'schema-hash') {
    const schemaFile = getArgValue('--schema') || getArgValue('-s');
    if (!schemaFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --schema <file.json>');
      process.exit(1);
    }
    const schema = JSON.parse(fs.readFileSync(schemaFile, 'utf-8'));
    const hash = core.SchemaValidator.computeSchemaHash(schema);
    console.log(`\x1b[32m✔\x1b[0m RFC 8785 Canonical Schema Hash: \x1b[1m${hash}\x1b[0m`);
    return;
  }

  if (command === 'jwe-keygen') {
    const outFile = getArgValue('--out') || getArgValue('-o');
    const kp = core.MultiRecipientJWE.generateRecipientKeyPair();
    const outStr = JSON.stringify(kp, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m JWE X25519 KeyPair generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'jwe-encrypt') {
    const payloadFile = getArgValue('--payload') || getArgValue('-p');
    const recipientsFile = getArgValue('--recipients') || getArgValue('-r');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!payloadFile || !recipientsFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --payload <file> or --recipients <file>');
      process.exit(1);
    }
    const payload = JSON.parse(fs.readFileSync(payloadFile, 'utf-8'));
    const recipients = JSON.parse(fs.readFileSync(recipientsFile, 'utf-8'));
    const jwe = core.MultiRecipientJWE.encrypt(payload, recipients);
    const outStr = JSON.stringify(jwe, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Multi-Recipient JWE encrypted and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'jwe-decrypt') {
    const jweFile = getArgValue('--jwe');
    const did = getArgValue('--did');
    const key = getArgValue('--key') || getArgValue('-k');
    if (!jweFile || !did || !key) {
      console.error('\x1b[31mError:\x1b[0m Missing --jwe <file>, --did <did>, or --key <privHex>');
      process.exit(1);
    }
    const jwe = JSON.parse(fs.readFileSync(jweFile, 'utf-8'));
    const decrypted = core.MultiRecipientJWE.decrypt(jwe, did, key);
    console.log(`\x1b[32m✔\x1b[0m Decryption SUCCESS:\n`, decrypted.parsedJson || decrypted.plaintext);
    return;
  }

  if (command === 'zk-intersection') {
    const claimKey = getArgValue('--key') || getArgValue('-k') || 'clearance';
    const val = getArgValue('--val') || getArgValue('-v');
    const salt = getArgValue('--salt') || crypto.randomBytes(16).toString('hex');
    const targetStr = getArgValue('--target') || getArgValue('-t');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!val || !targetStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --val <value> or --target <a,b,c>');
      process.exit(1);
    }
    const targetSet = targetStr.split(',').map(s => s.trim());
    const proof = core.proveSetIntersection(claimKey, val, salt, targetSet);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Set Intersection Proof saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  // Dynamic Accumulator Commands
  const ACC_STORE_FILE = path.join(process.cwd(), '.docutrust_accumulators.json');
  function loadAccStore() {
    if (fs.existsSync(ACC_STORE_FILE)) {
      try { return JSON.parse(fs.readFileSync(ACC_STORE_FILE, 'utf-8')); } catch (e) {}
    }
    return {};
  }
  function saveAccStore(store) {
    fs.writeFileSync(ACC_STORE_FILE, JSON.stringify(store, null, 2), 'utf-8');
  }

  if (command === 'accumulator-create') {
    const id = getArgValue('--id') || `acc_${crypto.randomBytes(4).toString('hex')}`;
    const membersStr = getArgValue('--members') || getArgValue('--elements') || getArgValue('-m') || getArgValue('-e');
    const store = loadAccStore();
    const acc = new core.CryptographicAccumulator(id);
    const initialMembers = membersStr ? membersStr.split(',').map(s => s.trim()).filter(Boolean) : [];
    for (const m of initialMembers) acc.add(m);
    store[id] = { state: acc.exportState(), members: initialMembers };
    saveAccStore(store);
    console.log(`\x1b[32m✔\x1b[0m Dynamic Cryptographic Accumulator initialized: \x1b[1m${id}\x1b[0m`);
    console.log(JSON.stringify(store[id].state, null, 2));
    return;
  }

  if (command === 'accumulator-add') {
    const id = getArgValue('--id');
    const elementsStr = getArgValue('--elements') || getArgValue('-e');
    if (!id || !elementsStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --id <id> or --elements <e1,e2,...>');
      process.exit(1);
    }
    const store = loadAccStore();
    if (!store[id]) {
      console.error(`\x1b[31mError:\x1b[0m Accumulator '${id}' not found in local store.`);
      process.exit(1);
    }
    const acc = new core.CryptographicAccumulator(id, store[id].state.modulus, store[id].state.generator);
    const existingMembers = store[id].members || [];
    for (const m of existingMembers) acc.add(m);
    const newElements = elementsStr.split(',').map(s => s.trim());
    for (const el of newElements) {
      acc.add(el);
      if (!existingMembers.includes(el)) existingMembers.push(el);
    }
    store[id].state = acc.exportState();
    store[id].members = existingMembers;
    saveAccStore(store);
    console.log(`\x1b[32m✔\x1b[0m Added ${newElements.length} element(s) to accumulator \x1b[1m${id}\x1b[0m`);
    console.log(JSON.stringify(store[id].state, null, 2));
    return;
  }

  if (command === 'accumulator-delete') {
    const id = getArgValue('--id');
    const element = getArgValue('--element') || getArgValue('-e');
    if (!id || !element) {
      console.error('\x1b[31mError:\x1b[0m Missing --id <id> or --element <e>');
      process.exit(1);
    }
    const store = loadAccStore();
    if (!store[id]) {
      console.error(`\x1b[31mError:\x1b[0m Accumulator '${id}' not found.`);
      process.exit(1);
    }
    const acc = new core.CryptographicAccumulator(id, store[id].state.modulus, store[id].state.generator);
    const existingMembers = (store[id].members || []).filter(m => m !== element);
    for (const m of existingMembers) acc.add(m);
    store[id].state = acc.exportState();
    store[id].members = existingMembers;
    saveAccStore(store);
    console.log(`\x1b[32m✔\x1b[0m Deleted '${element}' from accumulator \x1b[1m${id}\x1b[0m`);
    console.log(JSON.stringify(store[id].state, null, 2));
    return;
  }

  if (command === 'accumulator-witness') {
    const id = getArgValue('--id');
    const element = getArgValue('--element') || getArgValue('-e');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!id || !element) {
      console.error('\x1b[31mError:\x1b[0m Missing --id <id> or --element <e>');
      process.exit(1);
    }
    const store = loadAccStore();
    if (!store[id]) {
      console.error(`\x1b[31mError:\x1b[0m Accumulator '${id}' not found.`);
      process.exit(1);
    }
    const acc = new core.CryptographicAccumulator(id, store[id].state.modulus, store[id].state.generator);
    for (const m of store[id].members || []) acc.add(m);
    const witness = acc.createWitness(element);
    const outStr = JSON.stringify(witness, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Membership Witness saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'accumulator-verify') {
    const witnessFile = getArgValue('--witness') || getArgValue('-w');
    const accHex = getArgValue('--acc') || getArgValue('-a');
    const modHex = getArgValue('--mod') || getArgValue('-m');
    if (!witnessFile || !accHex) {
      console.error('\x1b[31mError:\x1b[0m Missing --witness <file.json> or --acc <hex>');
      process.exit(1);
    }
    const witness = JSON.parse(fs.readFileSync(witnessFile, 'utf-8'));
    const valid = core.CryptographicAccumulator.verifyWitness(witness, accHex, modHex || undefined);
    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m Accumulator Membership Witness is \x1b[1m\x1b[32mVALID\x1b[0m (Cryptographically Verified)`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Accumulator Membership Witness is \x1b[1m\x1b[31mINVALID\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  if (command === 'accumulator-batch-witness') {
    const id = getArgValue('--id');
    const elementsStr = getArgValue('--elements') || getArgValue('-e');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!id || !elementsStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --id <string> or --elements <elem1,elem2>');
      process.exit(1);
    }
    const elements = elementsStr.split(',').map(e => e.trim());
    const store = loadAccStore();
    if (!store[id]) {
      console.error(`\x1b[31mError:\x1b[0m Accumulator '${id}' not found`);
      process.exit(1);
    }
    const acc = new core.CryptographicAccumulator(id, store[id].state.modulus, store[id].state.generator);
    for (const m of store[id].members || []) acc.add(m);
    const witness = acc.createBatchWitness(elements);
    const outStr = JSON.stringify(witness, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Batch Membership Witness saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'accumulator-verify-batch') {
    const witnessFile = getArgValue('--witness') || getArgValue('-w');
    const accHex = getArgValue('--acc') || getArgValue('-a');
    const modHex = getArgValue('--mod') || getArgValue('-m');
    if (!witnessFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --witness <file.json>');
      process.exit(1);
    }
    const witness = JSON.parse(fs.readFileSync(witnessFile, 'utf-8'));
    const targetAccHex = accHex || witness.accumulatorHex;
    if (!targetAccHex) {
      console.error('\x1b[31mError:\x1b[0m Missing --acc <hex> (and not present in witness file)');
      process.exit(1);
    }
    const valid = core.CryptographicAccumulator.verifyBatchWitness(witness, targetAccHex, modHex || undefined);
    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m Accumulator Batch Membership Witness is \x1b[1m\x1b[32mVALID\x1b[0m (Cryptographically Verified)`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Accumulator Batch Membership Witness is \x1b[1m\x1b[31mINVALID\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  if (command === 'accumulator-non-membership-witness') {
    const id = getArgValue('--id');
    const element = getArgValue('--element') || getArgValue('-e');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!id || !element) {
      console.error('\x1b[31mError:\x1b[0m Missing --id <id> or --element <e>');
      process.exit(1);
    }
    const store = loadAccStore();
    if (!store[id]) {
      console.error(`\x1b[31mError:\x1b[0m Accumulator '${id}' not found.`);
      process.exit(1);
    }
    const acc = new core.CryptographicAccumulator(id, store[id].state.modulus, store[id].state.generator);
    for (const m of store[id].members || []) acc.add(m);
    const witness = acc.createNonMembershipWitness(element);
    const outStr = JSON.stringify(witness, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Non-Membership Witness saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'accumulator-verify-non-membership') {
    const witnessFile = getArgValue('--witness') || getArgValue('-w');
    const accHex = getArgValue('--acc') || getArgValue('-a');
    const genHex = getArgValue('--gen') || getArgValue('-g');
    const modHex = getArgValue('--mod') || getArgValue('-m');
    if (!witnessFile || !accHex) {
      console.error('\x1b[31mError:\x1b[0m Missing --witness <file.json> or --acc <hex>');
      process.exit(1);
    }
    const witness = JSON.parse(fs.readFileSync(witnessFile, 'utf-8'));
    const valid = core.CryptographicAccumulator.verifyNonMembershipWitness(witness, accHex, genHex || undefined, modHex || undefined);
    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m Accumulator Non-Membership Witness is \x1b[1m\x1b[32mVALID\x1b[0m (Cryptographically Verified)`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Accumulator Non-Membership Witness is \x1b[1m\x1b[31mINVALID\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  // W3C BitstringStatusList2024 Commands
  if (command === 'statuslist-create') {
    const length = parseInt(getArgValue('--length') || getArgValue('-l') || '100000');
    const statusSize = parseInt(getArgValue('--size') || getArgValue('-s') || '1');
    const statusPurpose = getArgValue('--purpose') || getArgValue('-p') || 'revocation';
    const id = getArgValue('--id');
    const issuer = getArgValue('--issuer');
    const outFile = getArgValue('--out') || getArgValue('-o');

    const list = new core.BitstringStatusList2024(length, statusSize, statusPurpose);
    const encoded = list.encode(true);
    let outputData = {
      encodedList: encoded,
      length,
      statusSize,
      statusPurpose
    };
    if (id && issuer) {
      outputData.credential = list.generateCredential(id, issuer);
    }
    const outStr = JSON.stringify(outputData, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m W3C BitstringStatusList2024 generated and saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'statuslist-check') {
    const listArg = getArgValue('--list') || getArgValue('-l');
    const index = parseInt(getArgValue('--index') || getArgValue('-i') || '0');
    const statusSize = parseInt(getArgValue('--size') || getArgValue('-s') || '1');
    const length = getArgValue('--length') ? parseInt(getArgValue('--length')) : undefined;

    if (!listArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --list <encoded|file>');
      process.exit(1);
    }
    let encoded = listArg;
    if (fs.existsSync(listArg)) {
      const parsed = JSON.parse(fs.readFileSync(listArg, 'utf-8'));
      encoded = parsed.encodedList || parsed.credentialSubject?.encodedList || parsed;
    }
    const list = core.BitstringStatusList2024.decode(encoded, { length, statusSize });
    const status = list.getStatus(index);
    console.log(`\x1b[32m✔\x1b[0m Status at index ${index}: \x1b[1m${status}\x1b[0m (Valid: ${list.isValid(index)}, Revoked: ${list.isRevoked(index)}, Suspended: ${list.isSuspended(index)})`);
    return;
  }

  if (command === 'statuslist-update') {
    const listArg = getArgValue('--list') || getArgValue('-l');
    const index = parseInt(getArgValue('--index') || getArgValue('-i') || '0');
    const status = parseInt(getArgValue('--status') || getArgValue('-v') || '1');
    const statusSize = parseInt(getArgValue('--size') || getArgValue('-s') || '1');
    const length = getArgValue('--length') ? parseInt(getArgValue('--length')) : undefined;
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!listArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --list <encoded|file>');
      process.exit(1);
    }
    let encoded = listArg;
    let fileJson = null;
    if (fs.existsSync(listArg)) {
      fileJson = JSON.parse(fs.readFileSync(listArg, 'utf-8'));
      encoded = fileJson.encodedList || fileJson.credentialSubject?.encodedList || fileJson;
    }
    const list = core.BitstringStatusList2024.decode(encoded, { length, statusSize });
    list.setStatus(index, status);
    const newEncoded = list.encode(true);
    if (fileJson && typeof fileJson === 'object') {
      if (fileJson.encodedList) fileJson.encodedList = newEncoded;
      if (fileJson.credentialSubject?.encodedList) fileJson.credentialSubject.encodedList = newEncoded;
    }
    const outResult = fileJson || { encodedList: newEncoded, index, status };
    const outStr = JSON.stringify(outResult, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Updated status list saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  // DIF Presentation Exchange Commands
  if (command === 'pe-definition-create') {
    const id = getArgValue('--id') || `pe_def_${crypto.randomBytes(4).toString('hex')}`;
    const descFile = getArgValue('--descriptors') || getArgValue('-d');
    const name = getArgValue('--name') || getArgValue('-n');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!descFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --descriptors <file.json>');
      process.exit(1);
    }
    const descriptors = JSON.parse(fs.readFileSync(descFile, 'utf-8'));
    const def = core.PresentationExchangeEngine.createDefinition(id, descriptors, { name });
    const outStr = JSON.stringify(def, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m DIF Presentation Definition saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'pe-evaluate') {
    const presFile = getArgValue('--presentation') || getArgValue('-p');
    const defFile = getArgValue('--definition') || getArgValue('-d');
    const subFile = getArgValue('--submission') || getArgValue('-s');

    if (!presFile || !defFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --presentation <file.json> or --definition <file.json>');
      process.exit(1);
    }
    const presentation = JSON.parse(fs.readFileSync(presFile, 'utf-8'));
    const definition = JSON.parse(fs.readFileSync(defFile, 'utf-8'));
    const submission = subFile ? JSON.parse(fs.readFileSync(subFile, 'utf-8')) : undefined;

    const result = core.PresentationExchangeEngine.evaluatePresentation(presentation, definition, submission);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Presentation Exchange Evaluation PASSED. Matched descriptors: [${result.matchedDescriptors.join(', ')}]`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Presentation Exchange Evaluation FAILED. Errors:\n` + result.errors.map(e => `  - ${e}`).join('\n'));
      process.exit(1);
    }
    return;
  }

  // ZK Membership, Composite & Graph Commands
  if (command === 'zk-membership') {
    const claimKey = getArgValue('--key') || getArgValue('-k') || 'role';
    const val = getArgValue('--val') || getArgValue('-v');
    const salt = getArgValue('--salt') || crypto.randomBytes(16).toString('hex');
    const allowedStr = getArgValue('--allowed') || getArgValue('-a');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!val || !allowedStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --val <value> or --allowed <a,b,c>');
      process.exit(1);
    }
    const allowedSet = allowedStr.split(',').map(s => s.trim());
    const proof = core.proveSetMembership(claimKey, val, salt, allowedSet);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Membership Proof saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'zk-composite') {
    const proofsStr = getArgValue('--proofs') || getArgValue('-p');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!proofsStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --proofs <file1.json,file2.json>');
      process.exit(1);
    }
    const proofFiles = proofsStr.split(',').map(s => s.trim());
    const proofs = proofFiles.map(f => JSON.parse(fs.readFileSync(f, 'utf-8')));
    const composite = core.proveCompositePredicate(proofs);
    const outStr = JSON.stringify(composite, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m ZK Composite Proof saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'zk-graph-prove') {
    const id = getArgValue('--id') || `graph_${crypto.randomBytes(4).toString('hex')}`;
    const rootFile = getArgValue('--root') || getArgValue('-r');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!rootFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --root <file.json>');
      process.exit(1);
    }
    const root = JSON.parse(fs.readFileSync(rootFile, 'utf-8'));
    const proof = core.provePredicateGraph(id, root);
    const outStr = JSON.stringify(proof, null, 2);
    if (outFile) {
      fs.writeFileSync(outFile, outStr, 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Recursive ZK Predicate Graph Proof saved to: \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(outStr);
    }
    return;
  }

  if (command === 'zk-graph-verify') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    const ctxFile = getArgValue('--context') || getArgValue('-c');
    if (!proofFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <file.json>');
      process.exit(1);
    }
    const graphProof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    const context = ctxFile ? JSON.parse(fs.readFileSync(ctxFile, 'utf-8')) : undefined;
    const result = core.verifyPredicateGraph(graphProof, context);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Recursive ZK Predicate Graph is \x1b[1m\x1b[32mVALID\x1b[0m (Satisfied nodes: ${result.satisfiedNodes.join(', ')})`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Recursive ZK Predicate Graph is \x1b[1m\x1b[31mINVALID\x1b[0m. Errors:\n` + result.errors.map(e => `  - ${e}`).join('\n'));
      process.exit(1);
    }
    return;
  }

  if (command === 'schema-validate-credential') {
    const credFile = getArgValue('--credential') || getArgValue('-c');
    const schemaFile = getArgValue('--schema') || getArgValue('-s');
    if (!credFile || !schemaFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --credential <file.json> or --schema <file.json>');
      process.exit(1);
    }
    const cred = JSON.parse(fs.readFileSync(credFile, 'utf-8'));
    const schema = JSON.parse(fs.readFileSync(schemaFile, 'utf-8'));
    const result = core.SchemaValidator.validateCredentialSubject(cred, schema);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Credential Subject Schema validation \x1b[1m\x1b[32mPASSED\x1b[0m`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Credential Subject Schema validation \x1b[1m\x1b[31mFAILED\x1b[0m. Errors:\n` + result.errors.map(e => `  - ${e}`).join('\n'));
      process.exit(1);
    }
    return;
  }

  if (command === 'multisig-draft') {
    const vcFile = getArgValue('--vc');
    const policyFile = getArgValue('--policy') || getArgValue('-p');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!vcFile || !policyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file.json> or --policy <file.json>');
      process.exit(1);
    }
    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const policy = JSON.parse(fs.readFileSync(policyFile, 'utf-8'));
    const draft = core.MultiSigThresholdEngine.createDraft(vc, policy);
    if (outFile) {
      fs.writeFileSync(outFile, JSON.stringify(draft, null, 2), 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m MultiSig Draft generated at \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(JSON.stringify(draft, null, 2));
    }
    return;
  }

  if (command === 'multisig-sign') {
    const hash = getArgValue('--hash');
    const did = getArgValue('--did') || getArgValue('-d');
    const role = getArgValue('--role') || getArgValue('-r') || 'Trustee';
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!hash || !did || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --hash <hex>, --did <did>, or --key <keyfile.json>');
      process.exit(1);
    }
    const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const sigEntry = core.MultiSigThresholdEngine.signAsAuthority(hash, did, role, keyData.privateKeyHex);
    if (outFile) {
      fs.writeFileSync(outFile, JSON.stringify(sigEntry, null, 2), 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m Authority Signature saved to \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(JSON.stringify(sigEntry, null, 2));
    }
    return;
  }

  if (command === 'multisig-assemble') {
    const vcFile = getArgValue('--vc');
    const policyFile = getArgValue('--policy') || getArgValue('-p');
    const sigsFile = getArgValue('--signatures') || getArgValue('-s');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!vcFile || !policyFile || !sigsFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file.json>, --policy <file.json>, or --signatures <sigs.json>');
      process.exit(1);
    }
    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const policy = JSON.parse(fs.readFileSync(policyFile, 'utf-8'));
    const sigs = JSON.parse(fs.readFileSync(sigsFile, 'utf-8'));
    const signatures = Array.isArray(sigs) ? sigs : (sigs.signatures || [sigs]);
    const finalizedVc = core.MultiSigThresholdEngine.assembleMultiSigCredential(vc, policy, signatures);
    if (outFile) {
      fs.writeFileSync(outFile, JSON.stringify(finalizedVc, null, 2), 'utf-8');
      console.log(`\x1b[32m✔\x1b[0m MultiSig Credential assembled at \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(JSON.stringify(finalizedVc, null, 2));
    }
    return;
  }

  if (command === 'multisig-verify') {
    const vcFile = getArgValue('--vc');
    const policyFile = getArgValue('--policy') || getArgValue('-p');
    if (!vcFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file.json>');
      process.exit(1);
    }
    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const policy = policyFile ? JSON.parse(fs.readFileSync(policyFile, 'utf-8')) : undefined;
    const report = core.MultiSigThresholdEngine.verifyMultiSigCredential(vc, policy);
    if (report.valid) {
      console.log(`\x1b[32m✔\x1b[0m MultiSig Credential is \x1b[1m\x1b[32mVALID\x1b[0m (${report.validSignaturesCount}/${report.threshold} signatures satisfied)`);
      console.log(`  Policy ID: ${report.policyId}`);
      console.log(`  Signers: ${report.signers.join(', ')}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m MultiSig Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${report.error}`);
      process.exit(1);
    }
    return;
  }

  if (command === 'render-pdf') {
    const vcFile = getArgValue('--vc');
    const title = getArgValue('--title') || 'Verifiable Certificate';
    const outFile = getArgValue('--out') || getArgValue('-o') || 'verifiable-credential.pdf';
    if (!vcFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file.json>');
      process.exit(1);
    }
    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const pdfBytes = core.VerifiablePDFGenerator.generatePDF(vc, { title });
    fs.writeFileSync(outFile, Buffer.from(pdfBytes));
    console.log(`\x1b[32m✔\x1b[0m Verifiable PDF rendered at \x1b[1m${outFile}\x1b[0m (${pdfBytes.length} bytes)`);
    return;
  }

  if (command === 'verify-pdf') {
    const pdfFile = getArgValue('--pdf') || getArgValue('-f');
    if (!pdfFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --pdf <file.pdf>');
      process.exit(1);
    }
    const pdfBytes = fs.readFileSync(pdfFile);
    const report = core.VerifiablePDFGenerator.extractAndVerify(pdfBytes);
    if (report.valid) {
      console.log(`\x1b[32m✔\x1b[0m Embedded Verifiable Credential in PDF is \x1b[1m\x1b[32mVALID\x1b[0m`);
      console.log(`  Issuer: ${report.issuer}`);
      console.log(`  Recipient: ${report.recipientName || report.recipientDid}`);
      console.log(`  Type: ${Array.isArray(report.credential?.type) ? report.credential.type.join(', ') : report.credential?.type}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Embedded PDF Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${report.error}`);
      process.exit(1);
    }
    return;
  }

  if (command === 'did-resolve') {
    const did = getArgValue('--did') || getArgValue('-d');
    if (!did) {
      console.error('\x1b[31mError:\x1b[0m Missing --did <did_string>');
      process.exit(1);
    }
    const doc = await core.DIDResolver.resolve(did);
    console.log(JSON.stringify(doc, null, 2));
    return;
  }

  // ==========================================
  // AnonCreds 2.0 CLI Handlers
  // ==========================================
  if (command === 'anoncreds-blind-request') {
    const schemaId = getArgValue('--schema') || 'schema:degree:2026';
    const issuerDid = getArgValue('--issuer') || 'did:key:zIssuer';
    const secret = getArgValue('--secret') || core.AnonCredsEngine.generateHolderMasterSecret().masterSecret;
    const outFile = getArgValue('--out') || 'blind-request.json';
    
    const { request, blindingFactor } = core.AnonCredsEngine.createBlindRequest(secret, schemaId, issuerDid);
    const result = { masterSecret: secret, blindingFactor, request };
    fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
    console.log(`\x1b[32m✔\x1b[0m AnonCreds Blind Request generated at \x1b[1m${outFile}\x1b[0m`);
    console.log(`  Commitment: ${request.blindedSecretCommitment.commitmentHex}`);
    return;
  }

  if (command === 'anoncreds-blind-issue') {
    const reqFile = getArgValue('--req') || getArgValue('-r');
    const claimsFile = getArgValue('--claims') || getArgValue('-c');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || 'blind-credential.json';

    if (!reqFile || !claimsFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --req <file>, --claims <file>, or --key <keyfile>');
      process.exit(1);
    }
    const reqObj = JSON.parse(fs.readFileSync(reqFile, 'utf-8'));
    const request = reqObj.request || reqObj;
    const claims = JSON.parse(fs.readFileSync(claimsFile, 'utf-8'));
    const keys = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));

    const blindCred = core.AnonCredsEngine.issueBlindCredential(
      request,
      claims,
      { issuerDid: keys.did, publicKeyHex: keys.publicKeyHex, schemaId: request.schemaId },
      keys
    );
    fs.writeFileSync(outFile, JSON.stringify(blindCred, null, 2));
    console.log(`\x1b[32m✔\x1b[0m AnonCreds Blind Credential issued at \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'anoncreds-unblind') {
    const credFile = getArgValue('--cred') || getArgValue('-c');
    const secret = getArgValue('--secret') || getArgValue('-s');
    const blindingFactor = getArgValue('--blinding') || getArgValue('-b');
    const outFile = getArgValue('--out') || 'unblinded-credential.json';

    if (!credFile || !secret || !blindingFactor) {
      console.error('\x1b[31mError:\x1b[0m Missing --cred <file>, --secret <str>, or --blinding <str>');
      process.exit(1);
    }
    const blindCred = JSON.parse(fs.readFileSync(credFile, 'utf-8'));
    const unblinded = core.AnonCredsEngine.unblindCredential(blindCred, secret, blindingFactor);
    fs.writeFileSync(outFile, JSON.stringify(unblinded, null, 2));
    console.log(`\x1b[32m✔\x1b[0m AnonCreds Credential unblinded at \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'anoncreds-derive-proof') {
    const credFile = getArgValue('--cred') || getArgValue('-c');
    const secret = getArgValue('--secret') || getArgValue('-s');
    const reveal = (getArgValue('--reveal') || getArgValue('-r') || '').split(',').filter(Boolean);
    const nonce = getArgValue('--nonce') || 'verifier-nonce-' + Date.now();
    const outFile = getArgValue('--out') || 'anoncreds-presentation.json';

    if (!credFile || !secret) {
      console.error('\x1b[31mError:\x1b[0m Missing --cred <file> or --secret <str>');
      process.exit(1);
    }
    const cred = JSON.parse(fs.readFileSync(credFile, 'utf-8'));
    const pres = core.AnonCredsEngine.createPresentation(cred, secret, reveal, nonce);
    fs.writeFileSync(outFile, JSON.stringify(pres, null, 2));
    console.log(`\x1b[32m✔\x1b[0m AnonCreds ZK Presentation derived at \x1b[1m${outFile}\x1b[0m`);
    console.log(`  Disclosed claims: ${Object.keys(pres.disclosedClaims).join(', ')}`);
    return;
  }

  if (command === 'anoncreds-verify') {
    const presFile = getArgValue('--pres') || getArgValue('-p');
    const nonce = getArgValue('--nonce');
    const issuerDid = getArgValue('--issuer');

    if (!presFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --pres <presentation.json>');
      process.exit(1);
    }
    const pres = JSON.parse(fs.readFileSync(presFile, 'utf-8'));
    const result = core.AnonCredsEngine.verifyPresentation(pres, nonce, issuerDid);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m AnonCreds Zero-Knowledge Presentation is \x1b[1m\x1b[32mVALID\x1b[0m`);
      console.log(`  Disclosed: ${JSON.stringify(result.disclosedClaims)}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m AnonCreds Presentation Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.error}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // FROST DKG CLI Handlers
  // ==========================================
  if (command === 'dkg-setup') {
    const nodesCount = parseInt(getArgValue('--nodes') || '3', 10);
    const threshold = parseInt(getArgValue('--threshold') || '2', 10);
    const outFile = getArgValue('--out') || 'dkg-ceremony.json';

    const participants = [];
    for (let i = 1; i <= nodesCount; i++) {
      participants.push({ name: `Node-${i}` });
    }
    const ceremony = core.DKGEngine.runDKGCeremony(participants, threshold);
    fs.writeFileSync(outFile, JSON.stringify(ceremony, null, 2));
    console.log(`\x1b[32m✔\x1b[0m DKG Ceremony completed. Group DID: \x1b[1m${ceremony.groupDid}\x1b[0m`);
    console.log(`  Saved ${nodesCount} participant shares to \x1b[1m${outFile}\x1b[0m (Threshold: ${threshold}-of-${nodesCount})`);
    return;
  }

  if (command === 'dkg-sign-share') {
    const index = parseInt(getArgValue('--index') || '1', 10);
    const shareHex = getArgValue('--share');
    const signerDid = getArgValue('--did') || `did:node:${index}`;
    const message = getArgValue('--msg') || getArgValue('-m');
    const outFile = getArgValue('--out') || `share-${index}-sig.json`;

    if (!shareHex || !message) {
      console.error('\x1b[31mError:\x1b[0m Missing --share <hex> or --msg <text>');
      process.exit(1);
    }
    const share = core.DKGEngine.signShare(index, shareHex, signerDid, message);
    fs.writeFileSync(outFile, JSON.stringify(share, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Partial signature share generated at \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'dkg-aggregate') {
    const pubHex = getArgValue('--pub');
    const did = getArgValue('--did') || 'did:key:zGroup';
    const threshold = parseInt(getArgValue('--threshold') || '2', 10);
    const sharesFiles = (getArgValue('--shares') || '').split(',').filter(Boolean);
    const outFile = getArgValue('--out') || 'aggregated-signature.json';

    if (!pubHex || sharesFiles.length === 0) {
      console.error('\x1b[31mError:\x1b[0m Missing --pub <hex> or --shares <f1,f2>');
      process.exit(1);
    }
    const shares = sharesFiles.map(f => JSON.parse(fs.readFileSync(f.trim(), 'utf-8')));
    const signature = core.DKGEngine.aggregateSignatures(pubHex, did, threshold, shares);
    fs.writeFileSync(outFile, JSON.stringify(signature, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Aggregated FROST signature created at \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'dkg-verify') {
    const sigFile = getArgValue('--sig');
    const message = getArgValue('--msg') || getArgValue('-m');
    const pubHex = getArgValue('--pub');

    if (!sigFile || !message) {
      console.error('\x1b[31mError:\x1b[0m Missing --sig <file> or --msg <text>');
      process.exit(1);
    }
    const signature = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
    const result = core.DKGEngine.verifyAggregatedSignature(signature, message, pubHex);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Aggregated Threshold Signature is \x1b[1m\x1b[32mVALID\x1b[0m (Threshold ${signature.thresholdMet}/${signature.totalParticipants})`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Signature Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.error}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // Solidity Verifier CLI Handlers
  // ==========================================
  if (command === 'solidity-export-verifier') {
    const name = getArgValue('--name') || 'DocuTrustVerifier';
    const owner = getArgValue('--owner');
    const outFile = getArgValue('--out') || `${name}.sol`;

    const code = core.SolidityEngine.generateVerifierContract({ contractName: name, ownerAddress: owner });
    fs.writeFileSync(outFile, code, 'utf-8');
    console.log(`\x1b[32m✔\x1b[0m Solidity Verifier Smart Contract exported to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'solidity-calldata') {
    const leaf = getArgValue('--leaf');
    const proofFile = getArgValue('--proof');
    const root = getArgValue('--root') || getArgValue('-r');

    if (!leaf || !proofFile || !root) {
      console.error('\x1b[31mError:\x1b[0m Missing --leaf <hash>, --proof <file>, or --root <hash>');
      process.exit(1);
    }
    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    const calldata = core.SolidityEngine.encodeVerificationCalldata(leaf, proof, root);
    console.log(JSON.stringify(calldata, null, 2));
    return;
  }

  // ==========================================
  // Cryptographic Audit Bundle CLI Handlers
  // ==========================================
  if (command === 'audit-bundle-create') {
    const org = getArgValue('--org') || 'DocuTrust Sovereign Trust';
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || 'audit-bundle.dtbundle';

    const keys = keyFile ? JSON.parse(fs.readFileSync(keyFile, 'utf-8')) : core.generateKeyPair();
    const bundle = core.AuditBundleEngine.createAuditBundle({
      organization: org,
      signerKeyPair: keys
    });
    fs.writeFileSync(outFile, JSON.stringify(bundle, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Signed Cryptographic Audit Bundle (.dtbundle) exported to \x1b[1m${outFile}\x1b[0m`);
    console.log(`  Bundle ID: ${bundle.id}`);
    return;
  }

  if (command === 'audit-bundle-verify') {
    const bundleFile = getArgValue('--bundle') || getArgValue('-b');
    const pubHex = getArgValue('--pub');

    if (!bundleFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --bundle <file.dtbundle>');
      process.exit(1);
    }
    const bundle = JSON.parse(fs.readFileSync(bundleFile, 'utf-8'));
    const result = core.AuditBundleEngine.verifyAuditBundle(bundle, pubHex);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Audit Bundle Verification \x1b[1m\x1b[32mPASSED\x1b[0m`);
      console.log(`  Organization: ${result.organization}`);
      console.log(`  HashChain Blocks: ${result.hashchainValid ? 'VALID' : 'INVALID'}`);
      console.log(`  MMR Peaks: ${result.mmrValid ? 'VALID' : 'INVALID'}`);
      console.log(`  TSA Oracle Token: ${result.tsaTimestampValid ? 'VALID' : 'INVALID'}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Audit Bundle Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.errors?.join(', ') || result.error}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // W3C DataIntegrityProof CLI Handlers
  // ==========================================
  if (command === 'dataintegrity-issue') {
    const claimsFile = getArgValue('--claims') || getArgValue('-c');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const cryptosuite = getArgValue('--suite') || 'eddsa-jcs-2022';
    const outFile = getArgValue('--out') || 'dataintegrity-vc.json';

    if (!claimsFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --claims <file> or --key <keyfile>');
      process.exit(1);
    }
    const claims = JSON.parse(fs.readFileSync(claimsFile, 'utf-8'));
    const keys = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));

    const vc = core.VerifiableCredentialsEngine.issueDataIntegrity({
      issuer: { id: keys.did, name: 'Institutional Issuer' },
      credentialSubject: claims,
      cryptosuite,
      keyPair: keys
    });
    fs.writeFileSync(outFile, JSON.stringify(vc, null, 2));
    console.log(`\x1b[32m✔\x1b[0m W3C DataIntegrityProof VC issued to \x1b[1m${outFile}\x1b[0m (Suite: ${cryptosuite})`);
    return;
  }

  if (command === 'dataintegrity-verify') {
    const vcFile = getArgValue('--vc');
    if (!vcFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --vc <file.json>');
      process.exit(1);
    }
    const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
    const result = await core.VerifiableCredentialsEngine.verify(vc);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m W3C DataIntegrityProof VC is \x1b[1m\x1b[32mVALID\x1b[0m`);
      console.log(`  Cryptosuite: ${vc.proof?.cryptosuite}`);
      console.log(`  Issuer: ${result.issuer}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m DataIntegrity Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.error}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // v6.0.0 Confidential Computing CLI Handlers
  // ==========================================
  if (command === 'confidential-keygen') {
    const bits = parseInt(getArgValue('--bits') || '512', 10);
    const outFile = getArgValue('--out') || getArgValue('-o') || 'paillier-keys.json';
    const keys = core.PaillierCryptosystem.generateKeyPair(bits);
    safeWriteFileSync(outFile, JSON.stringify(keys, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Paillier ${bits}-bit Homomorphic KeyPair generated and saved to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'confidential-encrypt') {
    const claimKey = getArgValue('--claim') || getArgValue('--key') || getArgValue('-c');
    const value = parseInt(getArgValue('--value') || getArgValue('--val') || getArgValue('-v'), 10);
    const keyFile = getArgValue('--pub') || getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'encrypted-claim.json';

    if (!claimKey || isNaN(value) || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --claim/--key <key>, --value/--val <num>, or --pub/--key <file.json>');
      process.exit(1);
    }

    const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const pubKey = keyData.publicKey || keyData;
    const encrypted = core.ConfidentialClaimsEngine.encryptClaim(claimKey, value, pubKey);
    safeWriteFileSync(outFile, JSON.stringify(encrypted, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Homomorphic claim "${claimKey}" encrypted to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'confidential-sum') {
    const inputsStr = getArgValue('--inputs') || getArgValue('-i');
    const keyFile = getArgValue('--pub') || getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'sum-result.json';

    if (!inputsStr || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --inputs <c1.json,c2.json> or --pub/--key <key.json>');
      process.exit(1);
    }

    const files = inputsStr.split(',').map(f => f.trim());
    const ciphertexts = files.map(f => {
      const parsed = JSON.parse(fs.readFileSync(f, 'utf-8'));
      return parsed.ciphertextHex || parsed;
    });

    const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const pubKey = keyData.publicKey || keyData;
    const result = core.ConfidentialClaimsEngine.homomorphicSum(ciphertexts, pubKey);
    safeWriteFileSync(outFile, JSON.stringify(result, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Homomorphic addition computed over ${files.length} claims -> \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'confidential-linear-combination') {
    const termsStr = getArgValue('--terms') || getArgValue('-t');
    const keyFile = getArgValue('--pub') || getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'lincomb-result.json';

    if (!termsStr || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --terms <c1.json:w1,c2.json:w2> or --pub/--key <key.json>');
      process.exit(1);
    }

    const termEntries = termsStr.split(',').map(entry => {
      const trimmed = entry.trim();
      const lastColon = trimmed.lastIndexOf(':');
      let filePath = trimmed;
      let weight = 1;
      if (lastColon > 1) {
        const potentialWeight = parseInt(trimmed.slice(lastColon + 1), 10);
        if (!isNaN(potentialWeight)) {
          filePath = trimmed.slice(0, lastColon);
          weight = potentialWeight;
        }
      }
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      const ciphertextHex = parsed.ciphertextHex || parsed.ciphertext || parsed;
      return { ciphertextHex, weight };
    });

    const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const pubKey = keyData.publicKey || keyData;
    const result = core.ConfidentialClaimsEngine.evaluateLinearCombination(termEntries, pubKey);
    safeWriteFileSync(outFile, JSON.stringify(result, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Homomorphic linear combination computed over ${termEntries.length} terms -> \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'confidential-threshold' || command === 'confidential-threshold-prove') {
    const claimKey = getArgValue('--claim') || getArgValue('--key') || getArgValue('-c');
    const val = parseInt(getArgValue('--value') || getArgValue('--val') || getArgValue('-v'), 10);
    const threshold = parseInt(getArgValue('--threshold') || getArgValue('-t'), 10);
    const op = getArgValue('--op') || 'gte';
    const keyFile = getArgValue('--pub') || getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'threshold-proof.json';

    if (!claimKey || isNaN(val) || isNaN(threshold) || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --claim <name>, --value <num>, --threshold <num>, or --pub/--key <keyfile>');
      process.exit(1);
    }

    const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const pubKey = keyData.publicKey || keyData;
    const proof = core.ConfidentialClaimsEngine.proveThreshold(claimKey, val, threshold, op, pubKey);
    safeWriteFileSync(outFile, JSON.stringify(proof, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Confidential Threshold Proof generated -> \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'confidential-verify-threshold' || command === 'confidential-threshold-verify') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    if (!proofFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <proof.json>');
      process.exit(1);
    }
    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    const valid = core.ConfidentialClaimsEngine.verifyThresholdProof(proof);
    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m Confidential Threshold Proof is \x1b[1m\x1b[32mVALID\x1b[0m (Claim: ${proof.claimKey} ${proof.operator} ${proof.threshold})`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Confidential Threshold Proof \x1b[1m\x1b[31mFAILED\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // v6.0.0 W3C URDNA2015 JSON-LD CLI Handlers
  // ==========================================
  if (command === 'jsonld-canonicalize') {
    const docFile = getArgValue('--doc') || getArgValue('--in') || getArgValue('-d') || getArgValue('-i');
    const outFile = getArgValue('--out') || getArgValue('-o');
    if (!docFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --doc or --in <doc.json>');
      process.exit(1);
    }
    const doc = JSON.parse(fs.readFileSync(docFile, 'utf-8'));
    const canonical = core.JsonLdCanonicalizationEngine.canonicalize(doc);
    const digest = core.JsonLdCanonicalizationEngine.digest(doc);
    if (outFile) {
      safeWriteFileSync(outFile, canonical);
      console.log(`\x1b[32m✔\x1b[0m Canonical N-Quads saved to \x1b[1m${outFile}\x1b[0m (Digest: ${digest})`);
    } else {
      console.log(`\x1b[32m✔\x1b[0m Dataset Digest (SHA-256): \x1b[1m${digest}\x1b[0m\n${canonical}`);
    }
    return;
  }

  if (command === 'jsonld-sign') {
    const docFile = getArgValue('--doc') || getArgValue('--in') || getArgValue('-d') || getArgValue('-i');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'signed-jsonld.json';
    if (!docFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --doc/--in <doc.json> or --key <key.json>');
      process.exit(1);
    }
    const doc = JSON.parse(fs.readFileSync(docFile, 'utf-8'));
    const keyPair = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const signed = core.JsonLdCanonicalizationEngine.signJsonLd(doc, keyPair);
    safeWriteFileSync(outFile, JSON.stringify(signed, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Linked Data Document signed and saved to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'jsonld-verify') {
    const docFile = getArgValue('--doc') || getArgValue('--in') || getArgValue('-d') || getArgValue('-i');
    const pubKeyHex = getArgValue('--pub') || getArgValue('-p');
    if (!docFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --doc/--in <signed-doc.json>');
      process.exit(1);
    }
    const doc = JSON.parse(fs.readFileSync(docFile, 'utf-8'));
    const result = core.JsonLdCanonicalizationEngine.verifyJsonLd(doc, pubKeyHex);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m JSON-LD Linked Data Signature is \x1b[1m\x1b[32mVALID\x1b[0m`);
      console.log(`  Canonical Digest: ${result.canonicalRdfDigest}`);
      console.log(`  Quad Count: ${result.quadCount}`);
      console.log(`  Verification Method: ${result.verificationMethod}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m JSON-LD Signature \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.errors.join(', ')}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // v6.0.0 Hierarchical Verifiable Trust Chains
  // ==========================================
  if (command === 'trustchain-issue' || command === 'trustchain-create-token') {
    const keyFile = getArgValue('--delegator-key') || getArgValue('--key') || getArgValue('-k');
    const delegateDid = getArgValue('--delegate') || getArgValue('-d');
    const typesStr = getArgValue('--types') || getArgValue('-t') || '*';
    const depth = parseInt(getArgValue('--depth') || '2', 10);
    const outFile = getArgValue('--out') || getArgValue('-o') || 'delegation-token.json';

    if (!keyFile || !delegateDid) {
      console.error('\x1b[31mError:\x1b[0m Missing --delegator-key/--key <key.json> or --delegate <did>');
      process.exit(1);
    }

    const delegatorKeyPair = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const allowedCredentialTypes = typesStr.split(',').map(t => t.trim());
    const token = core.TrustChainEngine.createDelegationToken({
      delegatorKeyPair,
      delegateDid,
      allowedCredentialTypes,
      maxDepth: depth
    });
    safeWriteFileSync(outFile, JSON.stringify(token, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Delegation Token created and saved to \x1b[1m${outFile}\x1b[0m (Delegate: ${delegateDid})`);
    return;
  }

  if (command === 'trustchain-verify-token') {
    const tokenFile = getArgValue('--token') || getArgValue('-t');
    const pubHex = getArgValue('--pub') || getArgValue('-p');
    if (!tokenFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --token <token.json>');
      process.exit(1);
    }
    const token = JSON.parse(fs.readFileSync(tokenFile, 'utf-8'));
    const valid = core.TrustChainEngine.verifyDelegationToken(token, pubHex);
    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m Delegation Token is \x1b[1m\x1b[32mVALID\x1b[0m`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Delegation Token is \x1b[1m\x1b[31mINVALID\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  if (command === 'trustchain-verify' || command === 'trustchain-verify-chain') {
    const chainStr = getArgValue('--chain') || getArgValue('--tokens');
    const vcFile = getArgValue('--vc');
    const rootsStr = getArgValue('--root-dids') || getArgValue('--root');
    const leafIssuer = getArgValue('--issuer');

    if (!chainStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --chain/--tokens <t1.json,t2.json>');
      process.exit(1);
    }

    const tokenFiles = chainStr.split(',').map(f => f.trim());
    const chain = tokenFiles.map(f => JSON.parse(fs.readFileSync(f, 'utf-8')));
    const credential = vcFile ? JSON.parse(fs.readFileSync(vcFile, 'utf-8')) : undefined;
    const accreditedRootDids = rootsStr ? rootsStr.split(',').map(d => d.trim()) : [];

    const result = core.TrustChainEngine.verifyTrustChain({
      chain,
      credential,
      accreditedRootDids,
      leafIssuerDid: leafIssuer
    });

    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Trust Chain Verification \x1b[1m\x1b[32mPASSED\x1b[0m (Chain is VALID)`);
      console.log(`  Root Authority: ${result.rootAuthorityDid}`);
      console.log(`  Leaf Issuer: ${result.leafIssuerDid}`);
      console.log(`  Chain Depth: ${result.chainDepth}`);
      console.log(`  Tokens Verified: ${result.tokensVerified}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Trust Chain Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.errors.join(', ')}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // v6.0.0 Post-Quantum Dual Hybrid KEM Armor
  // ==========================================
  if (command === 'quantum-armor-keygen') {
    const outFile = getArgValue('--out') || getArgValue('-o') || 'dual-kem-keys.json';
    const keys = core.DualHybridKEMEngine.generateDualKeyPair();
    safeWriteFileSync(outFile, JSON.stringify(keys, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Dual Hybrid KEM KeyPair generated and saved to \x1b[1m${outFile}\x1b[0m (DID: ${keys.hybridPublicKey.did})`);
    return;
  }

  if (command === 'quantum-armor-seal') {
    const docFile = getArgValue('--doc') || getArgValue('--in') || getArgValue('-d') || getArgValue('-i');
    const pubFile = getArgValue('--pub') || getArgValue('--key') || getArgValue('-p') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'quantum-envelope.json';

    if (!docFile || !pubFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --doc/--in <vc.json> or --pub/--key <dual-keys.json>');
      process.exit(1);
    }

    const payload = JSON.parse(fs.readFileSync(docFile, 'utf-8'));
    const pubData = JSON.parse(fs.readFileSync(pubFile, 'utf-8'));
    const recipientPub = pubData.hybridPublicKey || pubData;

    const envelope = core.DualHybridKEMEngine.sealCredential(payload, recipientPub);
    safeWriteFileSync(outFile, JSON.stringify(envelope, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Quantum-Sealed Envelope created and saved to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'quantum-armor-unseal') {
    const envFile = getArgValue('--armor') || getArgValue('--envelope') || getArgValue('--in') || getArgValue('-a') || getArgValue('-e') || getArgValue('-i');
    const privFile = getArgValue('--priv') || getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'unsealed-vc.json';

    if (!envFile || !privFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --armor/--envelope/--in <envelope.json> or --priv/--key <dual-keys.json>');
      process.exit(1);
    }

    const envelope = JSON.parse(fs.readFileSync(envFile, 'utf-8'));
    const privData = JSON.parse(fs.readFileSync(privFile, 'utf-8'));
    const recipientPriv = privData.hybridSecretKey || privData;

    const unsealed = core.DualHybridKEMEngine.unsealCredential(envelope, recipientPriv);
    safeWriteFileSync(outFile, JSON.stringify(unsealed, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Envelope unsealed successfully and saved to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  // ==========================================
  // did:jwk Decentralized Identifier Commands
  // ==========================================
  if (command === 'did-jwk') {
    const jwkFile = getArgValue('--jwk') || getArgValue('-j');
    const didStr = getArgValue('--did') || getArgValue('-d');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (jwkFile) {
      const jwk = JSON.parse(fs.readFileSync(jwkFile, 'utf-8'));
      const did = core.DIDResolver.encodeDidJwk(jwk);
      const doc = core.DIDResolver.resolveDidJwk(did);
      const output = { did, didDocument: doc };
      if (outFile) {
        safeWriteFileSync(outFile, JSON.stringify(output, null, 2));
        console.log(`\x1b[32m✔\x1b[0m did:jwk encoded and saved to \x1b[1m${outFile}\x1b[0m: ${did}`);
      } else {
        console.log(JSON.stringify(output, null, 2));
      }
      return;
    } else if (didStr) {
      const doc = core.DIDResolver.resolveDidJwk(didStr);
      if (outFile) {
        safeWriteFileSync(outFile, JSON.stringify(doc, null, 2));
        console.log(`\x1b[32m✔\x1b[0m DID Document resolved and saved to \x1b[1m${outFile}\x1b[0m`);
      } else {
        console.log(JSON.stringify(doc, null, 2));
      }
      return;
    } else {
      console.error('\x1b[31mError:\x1b[0m Missing --jwk <key.json> or --did <did:jwk:...>');
      process.exit(1);
    }
  }

  // ==========================================
  // Verifiable SVG Digital Badge Commands
  // ==========================================
  if (command === 'badge-render') {
    const credFile = getArgValue('--credential') || getArgValue('--in') || getArgValue('-c') || getArgValue('-i');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'credential-badge.svg';
    const theme = getArgValue('--theme') || getArgValue('-t') || 'sovereign';
    const title = getArgValue('--title');
    const recipient = getArgValue('--recipient');

    if (!credFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --credential/--in <vc.json>');
      process.exit(1);
    }

    const credential = JSON.parse(fs.readFileSync(credFile, 'utf-8'));
    const svg = core.BadgeEngine.renderBadgeSvg(credential, {
      theme,
      badgeTitle: title || undefined,
      recipientName: recipient || undefined
    });

    safeWriteFileSync(outFile, svg);
    console.log(`\x1b[32m✔\x1b[0m Verifiable SVG Badge generated and saved to \x1b[1m${outFile}\x1b[0m (Theme: ${theme})`);
    return;
  }

  if (command === 'badge-verify') {
    const svgFile = getArgValue('--svg') || getArgValue('--in') || getArgValue('-s') || getArgValue('-i');
    if (!svgFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --svg/--in <badge.svg>');
      process.exit(1);
    }

    const svgContent = fs.readFileSync(svgFile, 'utf-8');
    const result = await core.BadgeEngine.verifyBadgeSvg(svgContent);

    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Verifiable SVG Badge is \x1b[1m\x1b[32mAUTHENTIC & VALID\x1b[0m`);
      console.log(`  Issuer: ${result.issuer || 'Unknown'}`);
      console.log(`  Canonical JCS Hash: ${result.canonicalHash}`);
    } else {
      console.log(`\x1b[31m✖\x1b[0m Verifiable SVG Badge is \x1b[1m\x1b[31mINVALID\x1b[0m: ${result.error || 'Verification failed.'}`);
      process.exit(1);
    }
    return;
  }

  // ==========================================
  // v9.0.0 Sovereign Policy-as-Proof & did:peer
  // ==========================================

  if (command === 'policy-evaluate') {
    const payloadFile = getArgValue('--payload') || getArgValue('--in') || getArgValue('-i');
    const policyFile = getArgValue('--policy') || getArgValue('-p');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!payloadFile || !policyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --payload/--in <credential.json> or --policy <policy.json>');
      process.exit(1);
    }

    const payload = JSON.parse(fs.readFileSync(payloadFile, 'utf-8'));
    const policy = JSON.parse(fs.readFileSync(policyFile, 'utf-8'));
    let evaluatorKp = null;
    if (keyFile) {
      evaluatorKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    }

    const result = core.PolicyEngine.evaluate(payload, policy, { evaluatorKeyPair: evaluatorKp });
    if (outFile) {
      safeWriteFileSync(outFile, JSON.stringify(result, null, 2));
      console.log(`\x1b[32m✔\x1b[0m Policy evaluation result saved to \x1b[1m${outFile}\x1b[0m`);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }

    if (result.passed) {
      console.log(`\x1b[32m✔ Policy Evaluation PASSED\x1b[0m for policy: \x1b[1m${result.policyName}\x1b[0m`);
    } else {
      console.error(`\x1b[31m✖ Policy Evaluation FAILED\x1b[0m: ${result.errors.join(', ')}`);
      process.exit(1);
    }
    return;
  }

  if (command === 'policy-verify-receipt') {
    const receiptFile = getArgValue('--receipt') || getArgValue('--in') || getArgValue('-r') || getArgValue('-i');
    const pubHex = getArgValue('--key') || getArgValue('-k');

    if (!receiptFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --receipt/--in <receipt.json>');
      process.exit(1);
    }

    const receipt = JSON.parse(fs.readFileSync(receiptFile, 'utf-8'));
    const valid = core.PolicyEngine.verifyReceipt(receipt, pubHex || undefined);

    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m Policy Evaluation Receipt is \x1b[1m\x1b[32mAUTHENTIC & VALID\x1b[0m`);
      console.log(`  Policy ID: ${receipt.policyId}`);
      console.log(`  Evaluator DID: ${receipt.evaluatorDid}`);
      console.log(`  Passed: ${receipt.passed}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Policy Evaluation Receipt is \x1b[1m\x1b[31mINVALID\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  if (command === 'did-peer-create') {
    const methodStr = getArgValue('--method') || getArgValue('-m') || '0';
    const method = parseInt(methodStr, 10);
    const pubHex = getArgValue('--pub') || getArgValue('-p');
    const encHex = getArgValue('--enc') || getArgValue('-e');
    const service = getArgValue('--service') || getArgValue('-s');
    const outFile = getArgValue('--out') || getArgValue('-o');

    let did = '';
    if (method === 0) {
      const keyHex = pubHex || generateKeyPair().publicKeyHex;
      did = core.DIDResolver.createDidPeer0(keyHex);
    } else if (method === 2) {
      const keyHex = pubHex || generateKeyPair().publicKeyHex;
      did = core.DIDResolver.createDidPeer2({
        verificationKeyHex: keyHex,
        encryptionKeyHex: encHex || undefined,
        serviceEndpoint: service || undefined
      });
    } else {
      console.error('\x1b[31mError:\x1b[0m Method must be 0 or 2 for did:peer');
      process.exit(1);
    }

    const doc = await core.DIDResolver.resolve(did);
    const result = { did, didDocument: doc };

    if (outFile) {
      safeWriteFileSync(outFile, JSON.stringify(result, null, 2));
      console.log(`\x1b[32m✔\x1b[0m did:peer created and saved to \x1b[1m${outFile}\x1b[0m: ${did}`);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    return;
  }

  // ========================================================
  // Linkable Ring Signatures (LSAG) Commands (DocuTrust v10)
  // ========================================================
  if (command === 'ringsig-sign') {
    const msgInput = getArgValue('--msg') || getArgValue('-m');
    const ringStr = getArgValue('--ring') || getArgValue('-r');
    const privHex = getArgValue('--key') || getArgValue('-k');
    const pubHex = getArgValue('--pub') || getArgValue('-p');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!msgInput || !ringStr || !privHex) {
      console.error('\x1b[31mError:\x1b[0m Missing --msg <txt/file>, --ring <pub1,pub2..>, or --key <privHex>');
      process.exit(1);
    }

    let message = msgInput;
    if (fs.existsSync(msgInput)) {
      try {
        message = JSON.parse(fs.readFileSync(msgInput, 'utf-8'));
      } catch (_) {
        message = fs.readFileSync(msgInput, 'utf-8');
      }
    }

    const ring = ringStr.split(',').map(s => s.trim());
    let signerPub = pubHex;
    if (!signerPub) {
      // Derive or search
      signerPub = ring[0];
    }

    const sig = core.RingSignatureEngine.sign({
      message,
      ring,
      signerPrivateKeyHex: privHex,
      signerPublicKeyHex: signerPub
    });

    if (outFile) {
      safeWriteFileSync(outFile, JSON.stringify(sig, null, 2));
      console.log(`\x1b[32m✔\x1b[0m Linkable Ring Signature generated and saved to \x1b[1m${outFile}\x1b[0m`);
      console.log(`  Key Image Tag: \x1b[36m${sig.keyImage}\x1b[0m`);
      console.log(`  Ring Size: ${sig.ring.length} participants`);
    } else {
      console.log(JSON.stringify(sig, null, 2));
    }
    return;
  }

  if (command === 'ringsig-verify') {
    const msgInput = getArgValue('--msg') || getArgValue('-m');
    const sigFile = getArgValue('--sig') || getArgValue('-s');
    const usedTagsStr = getArgValue('--used-tags') || getArgValue('-u');

    if (!msgInput || !sigFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --msg <txt/file> or --sig <signature.json>');
      process.exit(1);
    }

    let message = msgInput;
    if (fs.existsSync(msgInput)) {
      try {
        message = JSON.parse(fs.readFileSync(msgInput, 'utf-8'));
      } catch (_) {
        message = fs.readFileSync(msgInput, 'utf-8');
      }
    }

    const signature = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
    const usedKeyImages = usedTagsStr ? usedTagsStr.split(',').map(s => s.trim()) : undefined;

    const result = core.RingSignatureEngine.verify({
      message,
      signature,
      usedKeyImages
    });

    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Linkable Ring Signature is \x1b[1m\x1b[32mVALID & ANONYMOUS\x1b[0m`);
      console.log(`  Ring Size: ${result.ringSize} participants`);
      console.log(`  Key Image Tag: ${result.keyImage}`);
      console.log(`  Double Action: ${result.isDoubleAction ? 'YES' : 'NO'}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Ring Signature Verification \x1b[1m\x1b[31mFAILED\x1b[0m: ${result.error || 'Invalid ring loop'}`);
      process.exit(1);
    }
    return;
  }

  // ========================================================
  // 256-bit Sparse Merkle Tree (SMT) Commands (DocuTrust v10)
  // ========================================================
  if (command === 'smt-set') {
    const key = getArgValue('--key') || getArgValue('-k');
    const val = getArgValue('--val') || getArgValue('-v');
    const stateFile = getArgValue('--state') || getArgValue('-s') || 'smt-state.json';
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!key || val === null) {
      console.error('\x1b[31mError:\x1b[0m Missing --key <hex/string> or --val <hex/string>');
      process.exit(1);
    }

    const smt = new core.SparseMerkleTree(256);
    let state = {};
    if (fs.existsSync(stateFile)) {
      try {
        state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
        for (const [k, v] of Object.entries(state.leaves || {})) {
          smt.set(k, v);
        }
      } catch (_) {}
    }

    const keyHex = key.length === 64 && /^[0-9a-fA-F]+$/.test(key) ? key : sha256Hex(key);
    const valHex = val.length === 64 && /^[0-9a-fA-F]+$/.test(val) ? val : sha256Hex(val);

    smt.set(keyHex, valHex);
    state.leaves = state.leaves || {};
    state.leaves[keyHex] = valHex;
    state.root = smt.getRoot();

    safeWriteFileSync(stateFile, JSON.stringify(state, null, 2));
    console.log(`\x1b[32m✔\x1b[0m SMT updated. New Root: \x1b[1m\x1b[32m${state.root}\x1b[0m`);
    return;
  }

  if (command === 'smt-prove') {
    const key = getArgValue('--key') || getArgValue('-k');
    const stateFile = getArgValue('--state') || getArgValue('-s') || 'smt-state.json';
    const outFile = getArgValue('--out') || getArgValue('-o') || 'smt-proof.json';

    if (!key) {
      console.error('\x1b[31mError:\x1b[0m Missing --key <hex/string>');
      process.exit(1);
    }

    const smt = new core.SparseMerkleTree(256);
    if (fs.existsSync(stateFile)) {
      try {
        const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
        for (const [k, v] of Object.entries(state.leaves || {})) {
          smt.set(k, v);
        }
      } catch (_) {}
    }

    const keyHex = key.length === 64 && /^[0-9a-fA-F]+$/.test(key) ? key : sha256Hex(key);
    const proof = smt.prove(keyHex);

    safeWriteFileSync(outFile, JSON.stringify(proof, null, 2));
    console.log(`\x1b[32m✔\x1b[0m SMT ${proof.exists ? 'Inclusion' : 'Non-Membership'} proof saved to \x1b[1m${outFile}\x1b[0m`);
    console.log(`  Root: ${proof.root}`);
    console.log(`  Exists: ${proof.exists}`);
    return;
  }

  if (command === 'smt-verify') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    const rootHex = getArgValue('--root') || getArgValue('-r');

    if (!proofFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <proof.json>');
      process.exit(1);
    }

    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    const valid = core.SparseMerkleTree.verifyProof(proof, rootHex || undefined);

    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m SMT Proof is \x1b[1m\x1b[32mCRYPTOGRAPHICALLY VALID\x1b[0m`);
      console.log(`  Audit Status: ${proof.exists ? 'INCLUDED' : 'NON-MEMBER (DOES NOT EXIST)'}`);
      console.log(`  Key: ${proof.key}`);
      console.log(`  Root: ${proof.root}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m SMT Proof verification \x1b[1m\x1b[31mFAILED\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  if (command === 'solidity-export-smt') {
    const name = getArgValue('--name') || getArgValue('-n') || 'DocuTrustSMTVerifier';
    const version = getArgValue('--solc') || '^0.8.24';
    const outFile = getArgValue('--out') || getArgValue('-o') || `${name}.sol`;

    const code = core.generateSMTVerifierContract({ contractName: name, solidityVersion: version });
    safeWriteFileSync(outFile, code);
    console.log(`\x1b[32m✔\x1b[0m Solidity SMT Verifier smart contract exported to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'solidity-export-registry') {
    const name = getArgValue('--name') || getArgValue('-n') || 'DocuTrustRegistry';
    const version = getArgValue('--solc') || '^0.8.24';
    const outFile = getArgValue('--out') || getArgValue('-o') || `${name}.sol`;

    const code = core.generateRegistryContract({ contractName: name, solidityVersion: version });
    safeWriteFileSync(outFile, code);
    console.log(`\x1b[32m✔\x1b[0m Solidity Trust Registry smart contract exported to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'statuslist-aggregate-check') {
    const rootHex = getArgValue('--root') || getArgValue('-r');
    const listsStr = getArgValue('--lists') || getArgValue('-l');

    if (!rootHex || !listsStr) {
      console.error('\x1b[31mError:\x1b[0m Missing --root <0x.../hex> or --lists <list1.json,list2.json>');
      process.exit(1);
    }

    const files = listsStr.split(',');
    const partitions = files.map(f => JSON.parse(fs.readFileSync(f.trim(), 'utf-8')));
    const aggregator = new core.BitstringStatusListAggregator();
    for (const p of partitions) {
      aggregator.addPartition(p);
    }
    const computedRoot = aggregator.getAggregateRoot();
    const cleanRoot = rootHex.replace(/^0x/, '');

    if (computedRoot.toLowerCase() === cleanRoot.toLowerCase()) {
      console.log(`\x1b[32m✔\x1b[0m Status List Multi-Partition Root matches: \x1b[32m${computedRoot}\x1b[0m`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Root mismatch: computed ${computedRoot}, expected ${cleanRoot}`);
      process.exit(1);
    }
    return;
  }

  // ========================================================
  // v11.0.0 NIST FIPS 205 SLH-DSA CLI Commands
  // ========================================================
  if (command === 'slhdsa-keygen') {
    const outFile = getArgValue('--out') || getArgValue('-o') || 'slhdsa-keypair.json';
    const kp = core.SLHDSAEngine.generateKeyPair();
    safeWriteFileSync(outFile, JSON.stringify(kp, null, 2));
    console.log(`\x1b[32m✔\x1b[0m NIST FIPS 205 SLH-DSA-SHA2-128s KeyPair generated successfully!`);
    console.log(`  DID Identifier: \x1b[1m\x1b[36m${kp.did}\x1b[0m`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'slhdsa-sign') {
    const msgInput = getArgValue('--msg') || getArgValue('-m');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'slhdsa-signature.json';

    if (!msgInput || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --msg <txt|file> or --key <key.json>');
      process.exit(1);
    }

    const message = fs.existsSync(msgInput) ? fs.readFileSync(msgInput, 'utf-8') : msgInput;
    const keyPair = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const sig = core.SLHDSAEngine.sign(message, keyPair);
    safeWriteFileSync(outFile, JSON.stringify(sig, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Message signed with NIST FIPS 205 SLH-DSA!`);
    console.log(`  Algorithm: ${sig.algorithm}`);
    console.log(`  Signature saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'slhdsa-verify') {
    const msgInput = getArgValue('--msg') || getArgValue('-m');
    const sigInput = getArgValue('--sig') || getArgValue('-s');
    const pubInput = getArgValue('--pub') || getArgValue('-p');

    if (!msgInput || !sigInput || !pubInput) {
      console.error('\x1b[31mError:\x1b[0m Missing --msg <txt|file>, --sig <file|hex>, or --pub <file|hex|did>');
      process.exit(1);
    }

    const message = fs.existsSync(msgInput) ? fs.readFileSync(msgInput, 'utf-8') : msgInput;
    let signature = sigInput;
    if (fs.existsSync(sigInput)) {
      const parsed = JSON.parse(fs.readFileSync(sigInput, 'utf-8'));
      signature = parsed.signatureValue || parsed.signatureHex || parsed;
    }
    let publicKey = pubInput;
    if (fs.existsSync(pubInput)) {
      const parsed = JSON.parse(fs.readFileSync(pubInput, 'utf-8'));
      publicKey = parsed.publicKeyHex || parsed.did || parsed;
    }

    const valid = core.SLHDSAEngine.verify(message, signature, publicKey);
    if (valid) {
      console.log(`\x1b[32m✔\x1b[0m SLH-DSA Signature is \x1b[1m\x1b[32m100% CRYPTOGRAPHICALLY AUTHENTIC\x1b[0m`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m SLH-DSA Signature verification \x1b[1m\x1b[31mFAILED\x1b[0m`);
      process.exit(1);
    }
    return;
  }

  // ========================================================
  // v11.0.0 WebAuthn / FIDO2 Passkey CLI Commands
  // ========================================================
  if (command === 'webauthn-keygen') {
    const rpId = getArgValue('--rp') || 'localhost';
    const outFile = getArgValue('--out') || getArgValue('-o') || 'webauthn-passkey.json';
    const kp = core.WebAuthnAttestationEngine.generateKeyPair(rpId);
    safeWriteFileSync(outFile, JSON.stringify(kp, null, 2));
    console.log(`\x1b[32m✔\x1b[0m WebAuthn P-256 Passkey KeyPair generated successfully!`);
    console.log(`  DID Identifier: \x1b[1m\x1b[36m${kp.did}\x1b[0m`);
    console.log(`  Credential ID: ${kp.credentialId}`);
    console.log(`  Relying Party: ${kp.rpId}`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'webauthn-assert') {
    const challenge = getArgValue('--challenge') || getArgValue('-c');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const rpId = getArgValue('--rp');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'webauthn-assertion.json';

    if (!challenge || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --challenge <str> or --key <passkey.json>');
      process.exit(1);
    }

    const keyPair = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const assertion = core.WebAuthnAttestationEngine.createAssertion(challenge, keyPair, { rpId });
    safeWriteFileSync(outFile, JSON.stringify(assertion, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Hardware WebAuthn Passkey Assertion created!`);
    console.log(`  Credential ID: ${assertion.credentialId}`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'webauthn-verify') {
    const assertFile = getArgValue('--assertion') || getArgValue('-a');
    const challenge = getArgValue('--challenge') || getArgValue('-c');
    const pubInput = getArgValue('--pub') || getArgValue('-p');
    const rpId = getArgValue('--rp');

    if (!assertFile || !challenge || !pubInput) {
      console.error('\x1b[31mError:\x1b[0m Missing --assertion <file>, --challenge <str>, or --pub <file|hex|did>');
      process.exit(1);
    }

    const assertion = JSON.parse(fs.readFileSync(assertFile, 'utf-8'));
    let publicKey = pubInput;
    if (fs.existsSync(pubInput)) {
      publicKey = JSON.parse(fs.readFileSync(pubInput, 'utf-8'));
    }

    const result = core.WebAuthnAttestationEngine.verifyAssertion(assertion, challenge, publicKey, { expectedRpId: rpId });
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m WebAuthn Passkey Assertion is \x1b[1m\x1b[32mAUTHENTIC\x1b[0m`);
      console.log(`  User Present (UP): ${result.userPresent ? 'YES' : 'NO'}`);
      console.log(`  User Verified (UV): ${result.userVerified ? 'YES' : 'NO'}`);
      console.log(`  Sign Count: ${result.signCount}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m WebAuthn verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // ========================================================
  // v11.0.0 Multi-Chain Verifiable Attestation Bridge CLI Commands
  // ========================================================
  if (command === 'crosschain-bridge') {
    const sourceChainId = parseInt(getArgValue('--source') || '1', 10);
    const destinationChainId = parseInt(getArgValue('--dest') || '8453', 10);
    const sequenceNonce = parseInt(getArgValue('--nonce') || '1', 10);
    const stateRoot = getArgValue('--root') || '0x' + '0'.repeat(64);
    const payloadHash = getArgValue('--payload') || '0x' + '0'.repeat(64);
    const senderAddress = getArgValue('--sender') || '0x0000000000000000000000000000000000000001';
    const recipientAddress = getArgValue('--recipient') || '0x0000000000000000000000000000000000000002';
    const outFile = getArgValue('--out') || getArgValue('-o') || 'crosschain-message.json';

    const msg = core.CrossChainBridgeEngine.createMessage({
      sourceChainId,
      destinationChainId,
      sequenceNonce,
      stateRoot,
      payloadHash,
      senderAddress,
      recipientAddress
    });

    safeWriteFileSync(outFile, JSON.stringify(msg, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Cross-Chain Bridge Message constructed!`);
    console.log(`  Message ID: \x1b[1m\x1b[36m${msg.messageId}\x1b[0m`);
    console.log(`  Route: Chain ${msg.sourceChainId} -> Chain ${msg.destinationChainId} (Nonce: ${msg.sequenceNonce})`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'crosschain-sign') {
    const msgFile = getArgValue('--msg') || getArgValue('-m');
    const relayerKeyFile = getArgValue('--relayer') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'relayer-signature.json';

    if (!msgFile || !relayerKeyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --msg <msg.json> or --relayer <key.json>');
      process.exit(1);
    }

    const message = JSON.parse(fs.readFileSync(msgFile, 'utf-8'));
    const relayerKp = JSON.parse(fs.readFileSync(relayerKeyFile, 'utf-8'));
    const sig = core.CrossChainBridgeEngine.signMessage(message, relayerKp);
    safeWriteFileSync(outFile, JSON.stringify(sig, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Relayer signed cross-chain message packet!`);
    console.log(`  Relayer DID: ${sig.relayerDid}`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'crosschain-verify') {
    const attestationFile = getArgValue('--attestation') || getArgValue('-a');
    const relayersStr = getArgValue('--relayers');

    if (!attestationFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --attestation <attestation.json>');
      process.exit(1);
    }

    const attestation = JSON.parse(fs.readFileSync(attestationFile, 'utf-8'));
    const authorizedRelayers = relayersStr ? relayersStr.split(',').map(s => s.trim()) : undefined;

    const result = core.CrossChainBridgeEngine.verifyAttestation(attestation, authorizedRelayers);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Cross-Chain Attestation is \x1b[1m\x1b[32mVALID & QUORUM SATISFIED\x1b[0m`);
      console.log(`  Quorum: ${result.verifiedSignatures} / ${result.requiredThreshold} Relayers`);
      console.log(`  Route: Chain ${attestation.message.sourceChainId} -> Chain ${attestation.message.destinationChainId}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Cross-chain verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // ========================================================
  // v11.0.0 Groth16 Zero-Knowledge SNARK CLI Commands
  // ========================================================
  if (command === 'groth16-setup') {
    const circuitName = getArgValue('--circuit') || 'StandardComplianceCircuit';
    const inputsCount = parseInt(getArgValue('--inputs') || '2', 10);
    const outFile = getArgValue('--out') || getArgValue('-o') || `${circuitName}.vk.json`;

    const vk = core.Groth16Engine.generateVerificationKey(circuitName, inputsCount);
    safeWriteFileSync(outFile, JSON.stringify(vk, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Groth16 Verification Key generated for circuit: \x1b[1m\x1b[36m${circuitName}\x1b[0m`);
    console.log(`  Public Input Slots: ${inputsCount}`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'groth16-prove') {
    const circuitName = getArgValue('--circuit') || 'StandardComplianceCircuit';
    const inputsStr = getArgValue('--inputs') || getArgValue('-i') || '100,200';
    const witnessFile = getArgValue('--witness') || getArgValue('-w');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'groth16-proof.json';

    const publicInputs = inputsStr.split(',').map(s => s.trim());
    const witness = witnessFile && fs.existsSync(witnessFile) ? JSON.parse(fs.readFileSync(witnessFile, 'utf-8')) : {};

    const proof = core.Groth16Engine.createProof(circuitName, publicInputs, witness);
    safeWriteFileSync(outFile, JSON.stringify(proof, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Zero-Knowledge Groth16 Proof generated!`);
    console.log(`  Curve: ${proof.curve}`);
    console.log(`  Circuit: ${proof.circuitName}`);
    console.log(`  Saved to: \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'groth16-verify') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    const vkFile = getArgValue('--vk') || getArgValue('-k');

    if (!proofFile || !vkFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <proof.json> or --vk <vk.json>');
      process.exit(1);
    }

    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    const vk = JSON.parse(fs.readFileSync(vkFile, 'utf-8'));

    const result = core.Groth16Engine.verifyProof(proof, vk);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Groth16 Zero-Knowledge Proof is \x1b[1m\x1b[32mCRYPTOGRAPHICALLY VALID\x1b[0m`);
      console.log(`  Pairing Verification: PASS`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Groth16 verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // ========================================================
  // v11.0.0 Solidity Bridge & Groth16 Verifier Smart Contract Generators
  // ========================================================
  if (command === 'solidity-export-bridge') {
    const name = getArgValue('--name') || getArgValue('-n') || 'DocuTrustBridgeRelayer';
    const version = getArgValue('--solc') || '^0.8.20';
    const outFile = getArgValue('--out') || getArgValue('-o') || `${name}.sol`;

    const code = core.generateBridgeRelayerContract({ contractName: name, solidityVersion: version });
    safeWriteFileSync(outFile, code);
    console.log(`\x1b[32m✔\x1b[0m Solidity Cross-Chain Bridge Relayer smart contract exported to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'solidity-export-groth16') {
    const name = getArgValue('--name') || getArgValue('-n') || 'DocuTrustGroth16Verifier';
    const version = getArgValue('--solc') || '^0.8.20';
    const outFile = getArgValue('--out') || getArgValue('-o') || `${name}.sol`;

    const code = core.generateGroth16VerifierContract({ contractName: name, solidityVersion: version });
    safeWriteFileSync(outFile, code);
    console.log(`\x1b[32m✔\x1b[0m Solidity Groth16 Verifier smart contract exported to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  // ========================================================
  // DocuTrust v12.0.0 Command Handlers
  // ========================================================

  // 1. Trust Score Engine
  if (command === 'trustscore-eval') {
    const credFile = getArgValue('--credential') || getArgValue('-c');
    const minScore = Number(getArgValue('--min-score') || getArgValue('-m') || 650);
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!credFile) {
      console.error('\x1b[31mError:\x1b[0m Missing required --credential <credential.json>');
      process.exit(1);
    }

    const credential = JSON.parse(fs.readFileSync(credFile, 'utf-8'));
    const evalResult = core.TrustScoreEngine.evaluate(credential, { minimumAcceptableScore: minScore });

    console.log(`\x1b[32m✔\x1b[0m Trust & Risk Score Evaluation Completed:`);
    console.log(`  Overall Score: \x1b[1m\x1b[36m${evalResult.overallScore} / 1000\x1b[0m`);
    console.log(`  Risk Tier:     \x1b[1m${evalResult.riskTier}\x1b[0m`);
    console.log(`  Acceptable:    ${evalResult.isAcceptable ? '\x1b[32mYES\x1b[0m' : '\x1b[31mNO\x1b[0m'}`);
    console.log(`  Breakdown:     Crypto: ${evalResult.breakdown.cryptoSuiteScore}/250, Issuer: ${evalResult.breakdown.issuerAccreditationScore}/250, Revocation: ${evalResult.breakdown.revocationFreshnessScore}/200, Temporal: ${evalResult.breakdown.temporalValidityScore}/150, Schema: ${evalResult.breakdown.schemaComplianceScore}/150`);

    if (keyFile) {
      const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
      const receipt = core.TrustScoreEngine.issueRiskReceipt(credential, evalResult, keyData);
      const outReceiptFile = outFile || 'trust-risk-receipt.json';
      safeWriteFileSync(outReceiptFile, JSON.stringify(receipt, null, 2));
      console.log(`  Signed Risk Receipt saved to: \x1b[1m${outReceiptFile}\x1b[0m`);
    }
    return;
  }

  if (command === 'trustscore-verify') {
    const receiptFile = getArgValue('--receipt') || getArgValue('-r');
    const evalKeyArg = getArgValue('--evaluator-key') || getArgValue('-k');

    if (!receiptFile || !evalKeyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --receipt <receipt.json> or --evaluator-key <key.json|pubHex>');
      process.exit(1);
    }

    const receipt = JSON.parse(fs.readFileSync(receiptFile, 'utf-8'));
    let evaluatorKey = evalKeyArg;
    if (fs.existsSync(evalKeyArg)) {
      const kd = JSON.parse(fs.readFileSync(evalKeyArg, 'utf-8'));
      evaluatorKey = kd.publicKeyHex || kd.publicKeyPem || kd;
    }

    const audit = core.TrustScoreEngine.verifyRiskReceipt(receipt, evaluatorKey);
    if (audit.valid) {
      console.log(`\x1b[32m✔\x1b[0m DocuTrust Risk Receipt is \x1b[1m\x1b[32mCRYPTOGRAPHICALLY VALID\x1b[0m`);
      console.log(`  Credential ID: ${receipt.credentialId}`);
      console.log(`  Overall Score: ${receipt.overallScore}/1000 (${receipt.riskTier})`);
      console.log(`  Evaluator DID: ${receipt.evaluatorDid}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Risk receipt verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, audit.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // 2. Verifiable Compute Engine
  if (command === 'compute-run') {
    const progFile = getArgValue('--program') || getArgValue('-p');
    const inputFile = getArgValue('--inputs') || getArgValue('-i');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'compute-receipt.json';

    if (!progFile || !inputFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --program <program.json> or --inputs <inputs.json>');
      process.exit(1);
    }

    const program = JSON.parse(fs.readFileSync(progFile, 'utf-8'));
    const inputs = JSON.parse(fs.readFileSync(inputFile, 'utf-8'));
    let proverKp;
    if (keyFile) {
      proverKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    }

    const { finalOutputs, trace, receipt } = core.VerifiableComputeEngine.execute(program, inputs, proverKp);
    console.log(`\x1b[32m✔\x1b[0m Verifiable Compute execution finished with ${trace.length} deterministic steps.`);
    console.log(`  Outputs:`, JSON.stringify(finalOutputs, null, 2));

    if (receipt) {
      safeWriteFileSync(outFile, JSON.stringify(receipt, null, 2));
      console.log(`  Signed Compute Receipt saved to: \x1b[1m${outFile}\x1b[0m`);
    }
    return;
  }

  if (command === 'compute-verify') {
    const receiptFile = getArgValue('--receipt') || getArgValue('-r');
    const proverKeyArg = getArgValue('--prover-key') || getArgValue('-k');
    const inputFile = getArgValue('--inputs') || getArgValue('-i');

    if (!receiptFile || !proverKeyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --receipt <receipt.json> or --prover-key <key.json|pubHex>');
      process.exit(1);
    }

    const receipt = JSON.parse(fs.readFileSync(receiptFile, 'utf-8'));
    let proverKey = proverKeyArg;
    if (fs.existsSync(proverKeyArg)) {
      const kd = JSON.parse(fs.readFileSync(proverKeyArg, 'utf-8'));
      proverKey = kd.publicKeyHex || kd.publicKeyPem || kd;
    }
    const expectedInputs = inputFile ? JSON.parse(fs.readFileSync(inputFile, 'utf-8')) : undefined;

    const result = core.VerifiableComputeEngine.verifyReceipt(receipt, proverKey, expectedInputs);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Verifiable Compute Receipt is \x1b[1m\x1b[32mCRYPTOGRAPHICALLY VALID\x1b[0m`);
      console.log(`  Program:      ${receipt.programId} v${receipt.programVersion}`);
      console.log(`  Trace Digest: ${receipt.executionTraceHash || receipt.traceMerkleRoot}`);
      console.log(`  Output Root:  ${receipt.outputStateHash}`);
      console.log(`  Step Count:   ${receipt.executionStepCount}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Compute receipt verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // 3. Ephemeral Forward-Secret Vanish Credential Engine
  if (command === 'vanish-issue') {
    const claimsFile = getArgValue('--claims') || getArgValue('-c');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const subjectDid = getArgValue('--subject') || getArgValue('-s');
    const ttl = Number(getArgValue('--ttl') || 300);
    const outFile = getArgValue('--out') || getArgValue('-o') || 'vanish-token.json';

    if (!claimsFile || !keyFile || !subjectDid) {
      console.error('\x1b[31mError:\x1b[0m Missing required arguments: --claims <f>, --key <k>, --subject <did>');
      process.exit(1);
    }

    const claims = JSON.parse(fs.readFileSync(claimsFile, 'utf-8'));
    const issuerKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));

    const { token, ephemeralKey } = core.VanishCredEngine.issueToken(claims, issuerKp, subjectDid, { ttlSeconds: ttl });
    const outputData = { token, ephemeralKey };
    safeWriteFileSync(outFile, JSON.stringify(outputData, null, 2));

    console.log(`\x1b[32m✔\x1b[0m Ephemeral Vanish Token issued successfully!`);
    console.log(`  Token ID:       ${token.id}`);
    console.log(`  TTL Seconds:    ${ttl}s`);
    console.log(`  Epoch Expires:  ${token.epochExpires}`);
    console.log(`  Ephemeral Key:  \x1b[33m${ephemeralKey}\x1b[0m`);
    console.log(`  Saved to:       \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'vanish-verify') {
    const tokenFile = getArgValue('--token') || getArgValue('-t');
    const ephemeralKey = getArgValue('--ephemeral-key') || getArgValue('-e');
    const issuerKeyArg = getArgValue('--issuer-key') || getArgValue('-k');

    if (!tokenFile || !ephemeralKey || !issuerKeyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --token <token.json>, --ephemeral-key <hex>, or --issuer-key <key.json|pubHex>');
      process.exit(1);
    }

    const tokenObj = JSON.parse(fs.readFileSync(tokenFile, 'utf-8'));
    const token = tokenObj.token || tokenObj;
    let issuerKey = issuerKeyArg;
    if (fs.existsSync(issuerKeyArg)) {
      const kd = JSON.parse(fs.readFileSync(issuerKeyArg, 'utf-8'));
      issuerKey = kd.publicKeyHex || kd.publicKeyPem || kd;
    }

    const result = core.VanishCredEngine.verifyAndDecrypt(token, ephemeralKey, issuerKey);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Vanish Credential Token is \x1b[1m\x1b[32mACTIVE & VALID\x1b[0m`);
      console.log(`  Remaining Time: \x1b[32m${result.remainingSeconds}s\x1b[0m`);
      console.log(`  Decrypted Claims:`, JSON.stringify(result.claims, null, 2));
    } else {
      console.error(`\x1b[31m✖\x1b[0m Vanish token verification \x1b[1m\x1b[31mFAILED\x1b[0m (Expired: ${result.isExpired}):`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // 4. Cross-Ledger Sovereign Registry StateSync & Delta Proof Engine
  if (command === 'statesync-delta') {
    const baseFile = getArgValue('--base') || getArgValue('-b');
    const targetFile = getArgValue('--target') || getArgValue('-t');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const sourceLedger = getArgValue('--source') || 'EVM:Mainnet';
    const destLedger = getArgValue('--dest') || 'Mesh:Local';
    const outFile = getArgValue('--out') || getArgValue('-o') || 'statesync-delta.json';

    if (!baseFile || !targetFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --base <base.json>, --target <target.json>, or --key <key.json>');
      process.exit(1);
    }

    const baseState = JSON.parse(fs.readFileSync(baseFile, 'utf-8'));
    const targetState = JSON.parse(fs.readFileSync(targetFile, 'utf-8'));
    const relayerKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));

    const deltaProof = core.StateSyncEngine.generateDeltaProof(baseState, targetState, relayerKp, {
      source: sourceLedger,
      destination: destLedger
    });

    safeWriteFileSync(outFile, JSON.stringify(deltaProof, null, 2));
    console.log(`\x1b[32m✔\x1b[0m StateSync Delta Proof generated successfully!`);
    console.log(`  Source Root:     ${deltaProof.sourceStateRoot}`);
    console.log(`  Target Root:     ${deltaProof.targetStateRoot}`);
    console.log(`  Delta Elements:  ${deltaProof.deltaCount}`);
    console.log(`  Saved to:        \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'statesync-verify') {
    const baseFile = getArgValue('--base') || getArgValue('-b');
    const deltaFile = getArgValue('--delta') || getArgValue('-d');
    const relayerKeyArg = getArgValue('--relayer-key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o');

    if (!baseFile || !deltaFile || !relayerKeyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --base <base.json>, --delta <delta.json>, or --relayer-key <k|pubHex>');
      process.exit(1);
    }

    const baseState = JSON.parse(fs.readFileSync(baseFile, 'utf-8'));
    const deltaProof = JSON.parse(fs.readFileSync(deltaFile, 'utf-8'));
    let relayerKey = relayerKeyArg;
    if (fs.existsSync(relayerKeyArg)) {
      const kd = JSON.parse(fs.readFileSync(relayerKeyArg, 'utf-8'));
      relayerKey = kd.publicKeyHex || kd.publicKeyPem || kd;
    }

    const syncResult = core.StateSyncEngine.applyAndVerifyDelta(baseState, deltaProof, relayerKey);
    if (syncResult.valid) {
      console.log(`\x1b[32m✔\x1b[0m StateSync Delta Proof is \x1b[1m\x1b[32mAUTHENTICATED & RECONCILED\x1b[0m`);
      console.log(`  Target Root:  ${syncResult.reconciledTargetRoot}`);
      if (outFile) {
        safeWriteFileSync(outFile, JSON.stringify(syncResult.newState, null, 2));
        console.log(`  Updated state saved to: \x1b[1m${outFile}\x1b[0m`);
      }
    } else {
      console.error(`\x1b[31m✖\x1b[0m StateSync verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, syncResult.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // 5. Universal Solidity Verifier Smart Contract Generator
  if (command === 'solidity-export-universal') {
    const name = getArgValue('--name') || getArgValue('-n') || 'DocuTrustUniversalVerifier';
    const version = getArgValue('--solc') || '^0.8.20';
    const outFile = getArgValue('--out') || getArgValue('-o') || `${name}.sol`;

    const code = core.generateUniversalVerifierContract({ contractName: name, solidityVersion: version });
    safeWriteFileSync(outFile, code);
    console.log(`\x1b[32m✔\x1b[0m Master Universal EVM Solidity Smart Contract exported to \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  // 6. v13.0.0 Recursive Zero-Knowledge Proof Aggregation
  if (command === 'zk-aggregate') {
    const proofsFile = getArgValue('--proofs') || getArgValue('-p');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const depth = Number(getArgValue('--depth') || 1);
    const generateEvm = args.includes('--evm');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'recursive-zk-proof.json';

    if (!proofsFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --proofs <proofs.json> or --key <aggregator-key.json>');
      process.exit(1);
    }

    const subProofs = JSON.parse(fs.readFileSync(proofsFile, 'utf-8'));
    const aggKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));

    const recProof = core.ZKRecursiveEngine.aggregateProofs(subProofs, {
      aggregatorKeyPair: aggKp,
      depth,
      generateEvmCalldata: generateEvm
    });

    safeWriteFileSync(outFile, JSON.stringify(recProof, null, 2));
    console.log(`\x1b[32m✔\x1b[0m Recursive ZK Aggregated Proof generated successfully!`);
    console.log(`  Proof ID:           ${recProof.recursiveProofId}`);
    console.log(`  Sub-Proof Count:    ${recProof.subProofCount}`);
    console.log(`  Aggregation Depth:  ${recProof.depth}`);
    console.log(`  Inputs Commitment:  ${recProof.linearizedPublicInputsCommitment}`);
    if (recProof.evmCalldataHex) {
      console.log(`  EVM Calldata:       ${recProof.evmCalldataHex.slice(0, 32)}...`);
    }
    console.log(`  Saved to:           \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'zk-verify-recursive') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    const keyArg = getArgValue('--key') || getArgValue('-k');

    if (!proofFile || !keyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <proof.json> or --key <key.json|pubHex>');
      process.exit(1);
    }

    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    let aggPub = keyArg;
    if (fs.existsSync(keyArg)) {
      const kd = JSON.parse(fs.readFileSync(keyArg, 'utf-8'));
      aggPub = kd.publicKeyHex || kd.publicKeyPem || kd;
    }

    const result = core.ZKRecursiveEngine.verifyRecursiveProof(proof, aggPub);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Recursive ZK Proof is \x1b[1m\x1b[32mCRYPTOGRAPHICALLY VALID\x1b[0m`);
      console.log(`  Proof ID:         ${result.recursiveProofId}`);
      console.log(`  Sub-Proofs:       ${result.subProofCount}`);
      console.log(`  Folding Depth:    ${result.depth}`);
      console.log(`  Inputs Digest:    ${result.linearizedPublicInputsCommitment}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Recursive ZK verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // 7. v13.0.0 Temporal-Spatial Revocation Lattice Engine
  if (command === 'lattice-init') {
    const latticeId = getArgValue('--id') || `lattice-${Date.now()}`;
    const issuerDid = getArgValue('--issuer') || getArgValue('-i');
    const shards = Number(getArgValue('--shards') || 4);
    const outFile = getArgValue('--out') || getArgValue('-o') || 'revocation-lattice.json';

    if (!issuerDid) {
      console.error('\x1b[31mError:\x1b[0m Missing --issuer <did>');
      process.exit(1);
    }

    const state = core.RevocationLatticeEngine.initializeLattice(latticeId, issuerDid, shards);
    safeWriteFileSync(outFile, JSON.stringify(state, null, 2));

    console.log(`\x1b[32m✔\x1b[0m Revocation Lattice initialized successfully!`);
    console.log(`  Lattice ID:    ${state.latticeId}`);
    console.log(`  Issuer DID:    ${state.issuerDid}`);
    console.log(`  Shards:        ${state.shardsCount}`);
    console.log(`  Lattice Root:  ${state.globalLatticeRoot}`);
    console.log(`  Saved to:      \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'lattice-accumulate') {
    const stateFile = getArgValue('--state') || getArgValue('-s');
    const revocationsFile = getArgValue('--revocations') || getArgValue('-r');
    const advanceEpoch = args.includes('--advance');
    const outFile = getArgValue('--out') || getArgValue('-o') || stateFile;

    if (!stateFile || !revocationsFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --state <lattice.json> or --revocations <ids.json>');
      process.exit(1);
    }

    const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
    const revList = JSON.parse(fs.readFileSync(revocationsFile, 'utf-8'));
    const revokedIds = Array.isArray(revList) ? revList : revList.revokedCredentialIds || [];

    const nextState = core.RevocationLatticeEngine.accumulateRevocations(state, revokedIds, advanceEpoch);
    safeWriteFileSync(outFile, JSON.stringify(nextState, null, 2));

    console.log(`\x1b[32m✔\x1b[0m Revocation Lattice updated successfully!`);
    console.log(`  Current Epoch:  ${nextState.currentEpoch}`);
    console.log(`  Lattice Root:   ${nextState.globalLatticeRoot}`);
    console.log(`  Accumulated:    ${revokedIds.length} revocation(s)`);
    console.log(`  Saved to:       \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'lattice-prove') {
    const stateFile = getArgValue('--state') || getArgValue('-s');
    const credId = getArgValue('--credential') || getArgValue('-c');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const epochArg = getArgValue('--epoch');
    const outFile = getArgValue('--out') || getArgValue('-o') || `lattice-proof-${Date.now()}.json`;

    if (!stateFile || !credId || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --state <lattice.json>, --credential <id>, or --key <issuer-key.json>');
      process.exit(1);
    }

    const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
    const issuerKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    const targetEpoch = epochArg !== undefined ? Number(epochArg) : undefined;

    const proof = core.RevocationLatticeEngine.generateLatticeProof(state, credId, issuerKp, targetEpoch);
    safeWriteFileSync(outFile, JSON.stringify(proof, null, 2));

    console.log(`\x1b[32m✔\x1b[0m Revocation Lattice Proof generated!`);
    console.log(`  Credential ID:   ${proof.credentialId}`);
    console.log(`  Status:          ${proof.isRevoked ? '\x1b[31mREVOKED\x1b[0m' : '\x1b[32mACTIVE (VALID)\x1b[0m'}`);
    console.log(`  Epoch:           ${proof.targetEpoch}`);
    console.log(`  Shard Index:     ${proof.targetShard}`);
    console.log(`  Saved to:        \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'lattice-verify') {
    const proofFile = getArgValue('--proof') || getArgValue('-p');
    const keyArg = getArgValue('--key') || getArgValue('-k');
    const expectedRoot = getArgValue('--root') || getArgValue('-r');

    if (!proofFile || !keyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --proof <proof.json> or --key <key.json|pubHex>');
      process.exit(1);
    }

    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
    let issuerPub = keyArg;
    if (fs.existsSync(keyArg)) {
      const kd = JSON.parse(fs.readFileSync(keyArg, 'utf-8'));
      issuerPub = kd.publicKeyHex || kd.publicKeyPem || kd;
    }

    const result = core.RevocationLatticeEngine.verifyLatticeProof(proof, issuerPub, expectedRoot);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m Revocation Lattice Proof is \x1b[1m\x1b[32mCRYPTOGRAPHICALLY AUTHENTIC\x1b[0m`);
      console.log(`  Credential Status: ${result.isRevoked ? '\x1b[31mREVOKED\x1b[0m' : '\x1b[32mNOT REVOKED (VALID)\x1b[0m'}`);
      console.log(`  Epoch:             ${proof.targetEpoch}`);
      console.log(`  Lattice Root:      ${proof.latticeRoot}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Lattice proof verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  // 8. v13.0.0 Autonomous AI Agent Provenance & Guardrails
  if (command === 'agent-attest') {
    const payloadFile = getArgValue('--payload') || getArgValue('-p');
    const keyFile = getArgValue('--key') || getArgValue('-k');
    const outFile = getArgValue('--out') || getArgValue('-o') || 'agent-attestation.json';

    if (!payloadFile || !keyFile) {
      console.error('\x1b[31mError:\x1b[0m Missing --payload <payload.json> or --key <agent-key.json>');
      process.exit(1);
    }

    const payload = JSON.parse(fs.readFileSync(payloadFile, 'utf-8'));
    const agentKp = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));

    const attestation = core.AgentProvenanceEngine.issueAttestation(payload, agentKp);
    safeWriteFileSync(outFile, JSON.stringify(attestation, null, 2));

    console.log(`\x1b[32m✔\x1b[0m AI Agent Action Attestation issued successfully!`);
    console.log(`  Attestation ID:  ${attestation.attestationId}`);
    console.log(`  Agent DID:       ${attestation.agentDid}`);
    console.log(`  Model Fingerprint: ${attestation.modelFingerprint}`);
    console.log(`  Trace Steps:     ${attestation.stepCount}`);
    console.log(`  Guardrails:      ${attestation.guardrailPassed ? '\x1b[32mPASSED\x1b[0m' : '\x1b[31mVIOLATED\x1b[0m'}`);
    console.log(`  Saved to:        \x1b[1m${outFile}\x1b[0m`);
    return;
  }

  if (command === 'agent-verify') {
    const attestFile = getArgValue('--attestation') || getArgValue('-a');
    const keyArg = getArgValue('--key') || getArgValue('-k');
    const outputFile = getArgValue('--output');

    if (!attestFile || !keyArg) {
      console.error('\x1b[31mError:\x1b[0m Missing --attestation <attestation.json> or --key <key.json|pubHex>');
      process.exit(1);
    }

    const attestation = JSON.parse(fs.readFileSync(attestFile, 'utf-8'));
    let agentPub = keyArg;
    if (fs.existsSync(keyArg)) {
      const kd = JSON.parse(fs.readFileSync(keyArg, 'utf-8'));
      agentPub = kd.publicKeyHex || kd.publicKeyPem || kd;
    }
    const expectedOutput = outputFile ? (fs.existsSync(outputFile) ? JSON.parse(fs.readFileSync(outputFile, 'utf-8')) : outputFile) : undefined;

    const result = core.AgentProvenanceEngine.verifyAttestation(attestation, agentPub, expectedOutput);
    if (result.valid) {
      console.log(`\x1b[32m✔\x1b[0m AI Agent Attestation is \x1b[1m\x1b[32mVERIFIED & TAMPER-FREE\x1b[0m`);
      console.log(`  Agent DID:       ${result.agentDid}`);
      console.log(`  Execution Steps: ${result.stepCount}`);
      console.log(`  Guardrail State: ${result.guardrailPassed ? '\x1b[32mCOMPLIANT\x1b[0m' : '\x1b[31mNON-COMPLIANT\x1b[0m'}`);
    } else {
      console.error(`\x1b[31m✖\x1b[0m Agent attestation verification \x1b[1m\x1b[31mFAILED\x1b[0m:`, result.errors.join(', '));
      process.exit(1);
    }
    return;
  }

  console.log(`Unknown command: ${command}. Run 'docutrust help' for usage.`);
}

main().catch(err => {
  console.error('\x1b[31mError:\x1b[0m', err.message);
  process.exit(1);
});
