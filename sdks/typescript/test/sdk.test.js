const { test, describe } = require('node:test');
const assert = require('node:assert');
const { DocuTrustClient, generateKeyPair, sha256Hex, MerkleTree } = require('../dist/index.js');

describe('DocuTrust TypeScript SDK (@docutrust/sdk)', () => {
  test('SDK exports core cryptographic primitives', () => {
    assert.strictEqual(typeof generateKeyPair, 'function');
    assert.strictEqual(typeof sha256Hex, 'function');
    assert.strictEqual(typeof MerkleTree, 'function');

    const kp = generateKeyPair();
    assert.ok(kp.publicKeyHex);
    assert.ok(kp.did.startsWith('did:key:z'));
  });

  test('DocuTrustClient initializes with default and custom options', () => {
    const client1 = new DocuTrustClient();
    assert.ok(client1);

    const client2 = new DocuTrustClient({
      apiUrl: 'https://custom-node.docutrust.org/api/v1',
      apiKey: 'dt_live_secret123'
    });
    assert.ok(client2);
  });

  test('DocuTrustClient correctly formats and sends requests with mock fetch', async () => {
    const mockCalls = [];
    const mockFetch = async (url, options) => {
      mockCalls.push({ url, options });
      return {
        ok: true,
        json: async () => ({ success: true, mockData: 'valid' })
      };
    };

    const client = new DocuTrustClient({
      apiUrl: 'https://test-api.docutrust.org/api/v1',
      apiKey: 'dt_test_key_abc',
      fetchFn: mockFetch
    });

    // 1. issueCredential
    const issueRes = await client.issueCredential({
      credentialSubject: { id: 'did:key:zAlice', name: 'Alice Smith' },
      type: 'AchievementCredential'
    });
    assert.strictEqual(issueRes.success, true);
    assert.strictEqual(mockCalls[0].url, 'https://test-api.docutrust.org/api/v1/credentials/issue');
    assert.strictEqual(mockCalls[0].options.method, 'POST');
    assert.strictEqual(mockCalls[0].options.headers['Authorization'], 'Bearer dt_test_key_abc');

    // 2. verifyCredential
    const verifyRes = await client.verifyCredential({ id: 'urn:uuid:123' });
    assert.strictEqual(verifyRes.success, true);
    assert.strictEqual(mockCalls[1].url, 'https://test-api.docutrust.org/api/v1/credentials/verify');

    // 3. batchIssue
    await client.batchIssue({
      records: [{ name: 'Alice' }, { name: 'Bob' }]
    });
    assert.strictEqual(mockCalls[2].url, 'https://test-api.docutrust.org/api/v1/credentials/issue-batch');

    // 4. verifyPdf
    await client.verifyPdf(Buffer.from('%PDF-1.7 sample'));
    assert.strictEqual(mockCalls[3].url, 'https://test-api.docutrust.org/api/v1/credentials/verify-pdf');

    // 5. selectiveDisclosure
    await client.generateSelectiveDisclosure({ id: 'vc1' }, ['name']);
    assert.strictEqual(mockCalls[4].url, 'https://test-api.docutrust.org/api/v1/credentials/selective-disclosure');

    // 6. ZK predicates
    await client.proveZKRange({ claimKey: 'gpa', actualValue: 3.9, min: 3.5, max: 4.0 });
    assert.strictEqual(mockCalls[5].url, 'https://test-api.docutrust.org/api/v1/credentials/zk-predicate/prove');

    // 7. KEM
    await client.kemGenerateKeys();
    assert.strictEqual(mockCalls[6].url, 'https://test-api.docutrust.org/api/v1/kem/generate-keys');

    // 8. Shamir
    await client.shamirSplit({ secret: 'masterKey123' });
    assert.strictEqual(mockCalls[7].url, 'https://test-api.docutrust.org/api/v1/keys/shamir/split');

    // 9. SD-JWT
    await client.issueSDJWT({ name: 'Alice' });
    assert.strictEqual(mockCalls[8].url, 'https://test-api.docutrust.org/api/v1/credentials/sd-jwt/issue');

    // 10. BBS+
    await client.bbsIssue(['message1', 'message2']);
    assert.strictEqual(mockCalls[9].url, 'https://test-api.docutrust.org/api/v1/credentials/bbs/issue');

    // 11. TSA Oracle
    await client.issueTimestampToken('doc_hash_123');
    assert.strictEqual(mockCalls[10].url, 'https://test-api.docutrust.org/api/v1/oracle/timestamp');

    // 12. DIDComm
    await client.didcommPack({
      message: { hello: 'world' },
      recipientPublicKeyHex: 'abc',
      recipientDid: 'did:key:zBob'
    });
    assert.strictEqual(mockCalls[11].url, 'https://test-api.docutrust.org/api/v1/didcomm/pack');

    // 13. MMR
    await client.mmrAppend('leaf_data');
    assert.strictEqual(mockCalls[12].url, 'https://test-api.docutrust.org/api/v1/ledger/mmr/append');

    // 14. EIP-712
    await client.generateSecp256k1Keys(1);
    assert.strictEqual(mockCalls[13].url, 'https://test-api.docutrust.org/api/v1/crypto/secp256k1/generate');

    // 15. Social Recovery
    await client.setupSocialRecovery('did:key:zOwner', '0xsecret', [{ did: 'did:key:zG1', name: 'G1' }]);
    assert.strictEqual(mockCalls[14].url, 'https://test-api.docutrust.org/api/v1/recovery/social/setup');

    // 16. ZK Non-membership
    await client.proveSetNonMembership('passport', 'VAL', 'salt', ['SANCTIONED']);
    assert.strictEqual(mockCalls[15].url, 'https://test-api.docutrust.org/api/v1/zk/prove-non-membership');

    // 17. MultiChain Anchor
    await client.formatMultiChainAnchor('ethereum', '0xroot', 100);
    assert.strictEqual(mockCalls[16].url, 'https://test-api.docutrust.org/api/v1/ledger/multichain/anchor');

    // 18. Schema Validation
    await client.validateSchema({ id: '1' }, { type: 'object' });
    assert.strictEqual(mockCalls[17].url, 'https://test-api.docutrust.org/api/v1/schema/validate');

    // 19. JWE Multi-Recipient
    await client.encryptJWE({ data: 123 }, [{ did: 'did:key:z1', publicKey: 'abc' }]);
    assert.strictEqual(mockCalls[18].url, 'https://test-api.docutrust.org/api/v1/jwe/encrypt');

    // 20. ZK Set Intersection
    await client.proveSetIntersection('badge', 'B1', 'salt', ['B1', 'B2']);
    assert.strictEqual(mockCalls[19].url, 'https://test-api.docutrust.org/api/v1/zk/prove-intersection');

    // 21. MultiSig Draft
    await client.createMultiSigDraft({ id: 'vc1' }, { threshold: 2 });
    assert.strictEqual(mockCalls[20].url, 'https://test-api.docutrust.org/api/v1/credentials/multisig/draft');

    // 22. MultiSig Sign
    await client.signMultiSigAsAuthority('0xhash', 'did:key:zDean', 'Dean', '0xpriv');
    assert.strictEqual(mockCalls[21].url, 'https://test-api.docutrust.org/api/v1/credentials/multisig/sign');

    // 23. MultiSig Assemble
    await client.assembleMultiSigCredential({ id: 'vc1' }, { threshold: 2 }, []);
    assert.strictEqual(mockCalls[22].url, 'https://test-api.docutrust.org/api/v1/credentials/multisig/assemble');

    // 24. MultiSig Verify
    await client.verifyMultiSigCredential({ id: 'vc1' }, { threshold: 2 });
    assert.strictEqual(mockCalls[23].url, 'https://test-api.docutrust.org/api/v1/credentials/multisig/verify');

    // 25. DID Resolve
    await client.resolveDID('did:key:z123');
    assert.strictEqual(mockCalls[24].url, 'https://test-api.docutrust.org/api/v1/did/resolve?did=did%3Akey%3Az123');

    // 26. Trust Registry
    await client.getTrustRegistryIssuers();
    assert.strictEqual(mockCalls[25].url, 'https://test-api.docutrust.org/api/v1/trust/registry');

    // 27. Vault Credentials
    await client.getVaultCredentials({ search: 'Stanford', limit: 10 });
    assert.strictEqual(mockCalls[26].url, 'https://test-api.docutrust.org/api/v1/vault/credentials?search=Stanford&limit=10');

    // 28. Confidential Encrypt
    await client.encryptConfidentialClaim('salary', 75000, { n: '123' });
    assert.strictEqual(mockCalls[27].url, 'https://test-api.docutrust.org/api/v1/confidential/encrypt');

    // 29. Homomorphic Sum
    await client.homomorphicSum(['c1', 'c2'], { n: '123' });
    assert.strictEqual(mockCalls[28].url, 'https://test-api.docutrust.org/api/v1/confidential/compute/sum');

    // 30. JSON-LD Canonicalize
    await client.canonicalizeJsonLd({ id: 'doc1' });
    assert.strictEqual(mockCalls[29].url, 'https://test-api.docutrust.org/api/v1/jsonld/canonicalize');

    // 31. JSON-LD Sign
    await client.signJsonLd({ id: 'doc1' }, { privateKeyHex: 'abc' });
    assert.strictEqual(mockCalls[30].url, 'https://test-api.docutrust.org/api/v1/jsonld/sign');

    // 32. TrustChain Token Create
    await client.createDelegationToken({ delegatorKeyPair: {}, delegateDid: 'did:key:z1' });
    assert.strictEqual(mockCalls[31].url, 'https://test-api.docutrust.org/api/v1/trustchain/token/create');

    // 33. TrustChain Verify
    await client.verifyTrustChain({ chain: [], credential: {}, accreditedRootDids: [] });
    assert.strictEqual(mockCalls[32].url, 'https://test-api.docutrust.org/api/v1/trustchain/verify');

    // 34. Quantum Armor KeyGen
    await client.generateDualKEMKeys();
    assert.strictEqual(mockCalls[33].url, 'https://test-api.docutrust.org/api/v1/quantum-armor/keys/generate');

    // 35. Quantum Armor Seal
    await client.sealCredentialWithQuantumArmor({ secret: 1 }, {});
    assert.strictEqual(mockCalls[34].url, 'https://test-api.docutrust.org/api/v1/quantum-armor/seal');

    // 36. Quantum Armor Unseal
    await client.unsealCredentialWithQuantumArmor({}, {});
    assert.strictEqual(mockCalls[35].url, 'https://test-api.docutrust.org/api/v1/quantum-armor/unseal');

    // 37. Accumulator Batch Witness
    await client.createAccumulatorBatchWitness('acc1', ['docA', 'docB']);
    assert.strictEqual(mockCalls[36].url, 'https://test-api.docutrust.org/api/v1/accumulator/batch-witness');

    // 38. Accumulator Verify Batch
    await client.verifyAccumulatorBatchWitness({ witness: '123' }, '456');
    assert.strictEqual(mockCalls[37].url, 'https://test-api.docutrust.org/api/v1/accumulator/verify-batch');

    // 39. Confidential Linear Combination
    await client.evaluateConfidentialLinearCombination([{ ciphertextHex: 'c1', weight: 2 }], { n: '123' });
    assert.strictEqual(mockCalls[38].url, 'https://test-api.docutrust.org/api/v1/confidential/compute/linear-combination');

    // 40. Policy Evaluate
    await client.evaluatePolicy({ id: 'vc-1' }, { id: 'pol-1' });
    assert.strictEqual(mockCalls[39].url, 'https://test-api.docutrust.org/api/v1/policy/evaluate');

    // 41. did:peer create & resolve
    await client.createDidPeer({ method: 0, publicKeyHex: 'abcdef' });
    assert.strictEqual(mockCalls[40].url, 'https://test-api.docutrust.org/api/v1/did/peer/create');

    await client.resolveDidPeer('did:peer:0z6Mku7');
    assert.strictEqual(mockCalls[41].url, 'https://test-api.docutrust.org/api/v1/did/peer/resolve?did=did%3Apeer%3A0z6Mku7');

    // 42. Status List Aggregate Check
    await client.checkAggregatedStatus('0xroot', []);
    assert.strictEqual(mockCalls[42].url, 'https://test-api.docutrust.org/api/v1/statuslist/aggregate-check');

    // 43. Solidity Export Registry
    await client.generateSolidityRegistry({ contractName: 'MyRegistry' });
    assert.strictEqual(mockCalls[43].url, 'https://test-api.docutrust.org/api/v1/solidity/export-registry');

    // 44. Ring Signature Sign & Verify
    await client.signRingSignature({ message: 'msg', ring: ['k1', 'k2'], signerPrivateKeyHex: 'priv' });
    assert.strictEqual(mockCalls[44].url, 'https://test-api.docutrust.org/api/v1/ringsig/sign');

    await client.verifyRingSignature({ message: 'msg', signature: {} });
    assert.strictEqual(mockCalls[45].url, 'https://test-api.docutrust.org/api/v1/ringsig/verify');

    // 45. SMT Set, Prove, Verify
    await client.setSMTLeaf('key1', 'val1');
    assert.strictEqual(mockCalls[46].url, 'https://test-api.docutrust.org/api/v1/smt/set');

    await client.generateSMTProof('key1');
    assert.strictEqual(mockCalls[47].url, 'https://test-api.docutrust.org/api/v1/smt/prove');

    await client.verifySMTProof({ root: 'r' });
    assert.strictEqual(mockCalls[48].url, 'https://test-api.docutrust.org/api/v1/smt/verify');

    // 46. Solidity SMT Verifier
    await client.generateSoliditySMTVerifier({ contractName: 'MySMTVerifier' });
    assert.strictEqual(mockCalls[49].url, 'https://test-api.docutrust.org/api/v1/solidity/export-smt');

    // 47. Policy Verify Receipt
    await client.verifyPolicyReceipt({ id: 'rec-1' });
    assert.strictEqual(mockCalls[50].url, 'https://test-api.docutrust.org/api/v1/policy/verify-receipt');

    // 48. SLH-DSA
    await client.generateSLHDSAKeyPair();
    assert.strictEqual(mockCalls[51].url, 'https://test-api.docutrust.org/api/v1/slhdsa/keygen');
    await client.signSLHDSA('test msg', {});
    assert.strictEqual(mockCalls[52].url, 'https://test-api.docutrust.org/api/v1/slhdsa/sign');
    await client.verifySLHDSA('test msg', 'sig', 'pub');
    assert.strictEqual(mockCalls[53].url, 'https://test-api.docutrust.org/api/v1/slhdsa/verify');

    // 49. WebAuthn
    await client.generateWebAuthnKeyPair('example.com');
    assert.strictEqual(mockCalls[54].url, 'https://test-api.docutrust.org/api/v1/webauthn/keygen');
    await client.createWebAuthnAssertion('challenge-1', {});
    assert.strictEqual(mockCalls[55].url, 'https://test-api.docutrust.org/api/v1/webauthn/assertion');
    await client.verifyWebAuthnAssertion({}, 'challenge-1', {});
    assert.strictEqual(mockCalls[56].url, 'https://test-api.docutrust.org/api/v1/webauthn/verify');

    // 50. Cross-Chain Bridge
    await client.createCrossChainMessage({ sourceChainId: 1, destinationChainId: 8453, sequenceNonce: 1, stateRoot: '0x0', payloadHash: '0x0' });
    assert.strictEqual(mockCalls[57].url, 'https://test-api.docutrust.org/api/v1/crosschain/message');
    await client.signCrossChainMessage({}, {});
    assert.strictEqual(mockCalls[58].url, 'https://test-api.docutrust.org/api/v1/crosschain/sign');
    await client.assembleCrossChainAttestation({}, []);
    assert.strictEqual(mockCalls[59].url, 'https://test-api.docutrust.org/api/v1/crosschain/attest');
    await client.verifyCrossChainAttestation({});
    assert.strictEqual(mockCalls[60].url, 'https://test-api.docutrust.org/api/v1/crosschain/verify');

    // 51. Groth16 ZK-SNARKs
    await client.setupGroth16Circuit('CircuitA', 2);
    assert.strictEqual(mockCalls[61].url, 'https://test-api.docutrust.org/api/v1/groth16/setup');
    await client.proveGroth16('CircuitA', ['1', '2'], {});
    assert.strictEqual(mockCalls[62].url, 'https://test-api.docutrust.org/api/v1/groth16/prove');
    await client.verifyGroth16Proof({}, {});
    assert.strictEqual(mockCalls[63].url, 'https://test-api.docutrust.org/api/v1/groth16/verify');
    await client.aggregateGroth16Proofs([{}, {}]);
    assert.strictEqual(mockCalls[64].url, 'https://test-api.docutrust.org/api/v1/groth16/aggregate');

    // 52. Solidity Exporters
    await client.generateSolidityBridgeRelayer();
    assert.strictEqual(mockCalls[65].url, 'https://test-api.docutrust.org/api/v1/solidity/export-bridge');
    await client.generateSolidityGroth16Verifier();
    assert.strictEqual(mockCalls[66].url, 'https://test-api.docutrust.org/api/v1/solidity/export-groth16');

    // 53. v12.0.0 Trust Score
    await client.evaluateTrustScore({}, {});
    assert.strictEqual(mockCalls[67].url, 'https://test-api.docutrust.org/api/v1/trustscore/evaluate');
    await client.verifyTrustScoreReceipt({}, '0x123');
    assert.strictEqual(mockCalls[68].url, 'https://test-api.docutrust.org/api/v1/trustscore/verify');

    // 54. v12.0.0 Verifiable Compute
    await client.executeVerifiableCompute({}, {}, {});
    assert.strictEqual(mockCalls[69].url, 'https://test-api.docutrust.org/api/v1/compute/execute');
    await client.verifyComputeReceipt({}, '0x123');
    assert.strictEqual(mockCalls[70].url, 'https://test-api.docutrust.org/api/v1/compute/verify');

    // 55. v12.0.0 Vanish Ephemeral Credentials
    await client.issueVanishToken({}, {}, 'did:key:z123');
    assert.strictEqual(mockCalls[71].url, 'https://test-api.docutrust.org/api/v1/vanish/issue');
    await client.verifyVanishToken({}, '0x123', '0x456');
    assert.strictEqual(mockCalls[72].url, 'https://test-api.docutrust.org/api/v1/vanish/verify');

    // 56. v12.0.0 StateSync Delta Proofs
    await client.generateStateDelta({}, {}, {});
    assert.strictEqual(mockCalls[73].url, 'https://test-api.docutrust.org/api/v1/statesync/delta');
    await client.verifyStateDelta({}, {}, '0x123');
    assert.strictEqual(mockCalls[74].url, 'https://test-api.docutrust.org/api/v1/statesync/verify');

    // 57. v12.0.0 Universal Solidity Verifier
    await client.generateUniversalSolidityVerifier();
    assert.strictEqual(mockCalls[75].url, 'https://test-api.docutrust.org/api/v1/solidity/export-universal');

    // 58. v15.0.0 Post-Quantum Ratchet
    await client.generateRatchetKeyPair();
    assert.strictEqual(mockCalls[76].url, 'https://test-api.docutrust.org/api/v1/ratchet/keygen');
    await client.initInitiatorRatchetSession('pk_bob');
    assert.strictEqual(mockCalls[77].url, 'https://test-api.docutrust.org/api/v1/ratchet/init/initiator');
    await client.initResponderRatchetSession({});
    assert.strictEqual(mockCalls[78].url, 'https://test-api.docutrust.org/api/v1/ratchet/init/responder');
    await client.encryptRatchet({}, { hello: 'world' });
    assert.strictEqual(mockCalls[79].url, 'https://test-api.docutrust.org/api/v1/ratchet/encrypt');
    await client.decryptRatchet({}, {});
    assert.strictEqual(mockCalls[80].url, 'https://test-api.docutrust.org/api/v1/ratchet/decrypt');

    // 59. v15.0.0 Polynomial Commitments
    await client.generatePolySRS(16);
    assert.strictEqual(mockCalls[81].url, 'https://test-api.docutrust.org/api/v1/zk/poly/srs');
    await client.commitPolynomial([1, 2, 3], {});
    assert.strictEqual(mockCalls[82].url, 'https://test-api.docutrust.org/api/v1/zk/poly/commit');
    await client.evaluatePolynomial([1, 2, 3], 5);
    assert.strictEqual(mockCalls[83].url, 'https://test-api.docutrust.org/api/v1/zk/poly/evaluate');
    await client.createPolyEvaluationProof([1, 2, 3], 5, {});
    assert.strictEqual(mockCalls[84].url, 'https://test-api.docutrust.org/api/v1/zk/poly/prove');
    await client.verifyPolyEvaluationProof({}, {}, {});
    assert.strictEqual(mockCalls[85].url, 'https://test-api.docutrust.org/api/v1/zk/poly/verify');

    // 60. v15.0.0 TEE Remote Attestation
    await client.generateTEEAttestationQuote('Intel-SGX-DCAP', {}, {});
    assert.strictEqual(mockCalls[86].url, 'https://test-api.docutrust.org/api/v1/tee/quote/generate');
    await client.verifyTEEAttestationQuote({});
    assert.strictEqual(mockCalls[87].url, 'https://test-api.docutrust.org/api/v1/tee/quote/verify');
    await client.issueTEEBoundCredential({}, {}, {}, '0x123');
    assert.strictEqual(mockCalls[88].url, 'https://test-api.docutrust.org/api/v1/tee/vc/issue');
    await client.verifyTEEBoundCredential({});
    assert.strictEqual(mockCalls[89].url, 'https://test-api.docutrust.org/api/v1/tee/vc/verify');

    // 61. v15.0.0 IBC Relayer
    await client.computeIBCPacketCommitment({});
    assert.strictEqual(mockCalls[90].url, 'https://test-api.docutrust.org/api/v1/ibc/packet/commit');
    await client.generateIBCMerkleProof('key', '0x123');
    assert.strictEqual(mockCalls[91].url, 'https://test-api.docutrust.org/api/v1/ibc/proof/generate');
    await client.verifyIBCMerkleProof({});
    assert.strictEqual(mockCalls[92].url, 'https://test-api.docutrust.org/api/v1/ibc/proof/verify');
    await client.createIBCLightClient('chain-1', {});
    assert.strictEqual(mockCalls[93].url, 'https://test-api.docutrust.org/api/v1/ibc/client/create');
    await client.updateIBCLightClient({}, {});
    assert.strictEqual(mockCalls[94].url, 'https://test-api.docutrust.org/api/v1/ibc/client/update');
    await client.relayIBCPacket({}, {}, {});
    assert.strictEqual(mockCalls[95].url, 'https://test-api.docutrust.org/api/v1/ibc/packet/relay');

    // 62. v16.0.0 FHE Queries
    await client.generateFHEKeyPair(8, 2147483647);
    assert.strictEqual(mockCalls[96].url, 'https://test-api.docutrust.org/api/v1/fhe/keypair');
    await client.encryptFHEValue(42, {});
    assert.strictEqual(mockCalls[97].url, 'https://test-api.docutrust.org/api/v1/fhe/encrypt');
    await client.decryptFHEValue({}, {});
    assert.strictEqual(mockCalls[98].url, 'https://test-api.docutrust.org/api/v1/fhe/decrypt');
    await client.addFHECiphertexts({}, {});
    assert.strictEqual(mockCalls[99].url, 'https://test-api.docutrust.org/api/v1/fhe/add');
    await client.multiplyFHECiphertexts({}, {});
    assert.strictEqual(mockCalls[100].url, 'https://test-api.docutrust.org/api/v1/fhe/multiply');
    await client.queryFHEDatabase([], {});
    assert.strictEqual(mockCalls[101].url, 'https://test-api.docutrust.org/api/v1/fhe/query-db');
    await client.createFHEQueryReceipt('q1', {}, 'did:key:z1', '0x123');
    assert.strictEqual(mockCalls[102].url, 'https://test-api.docutrust.org/api/v1/fhe/receipt/create');
    await client.verifyFHEQueryReceipt({});
    assert.strictEqual(mockCalls[103].url, 'https://test-api.docutrust.org/api/v1/fhe/receipt/verify');

    // 63. v16.0.0 FROST Threshold Signatures
    await client.generateFROSTDKG(2, 3);
    assert.strictEqual(mockCalls[104].url, 'https://test-api.docutrust.org/api/v1/frost/dkg');
    await client.generateFROSTRound1Commitment(1);
    assert.strictEqual(mockCalls[105].url, 'https://test-api.docutrust.org/api/v1/frost/round1');
    await client.generateFROSTRound2Share(1, {}, [], 'msg');
    assert.strictEqual(mockCalls[106].url, 'https://test-api.docutrust.org/api/v1/frost/round2');
    await client.aggregateFROSTSignatures('msg', [], [], '0x123');
    assert.strictEqual(mockCalls[107].url, 'https://test-api.docutrust.org/api/v1/frost/aggregate');
    await client.verifyFROSTThresholdSignature('msg', {}, '0x123');
    assert.strictEqual(mockCalls[108].url, 'https://test-api.docutrust.org/api/v1/frost/verify');
    await client.issueFROSTThresholdCredential({}, '0x123', {}, 'did:key:z1');
    assert.strictEqual(mockCalls[109].url, 'https://test-api.docutrust.org/api/v1/frost/credential/issue');
    await client.verifyFROSTThresholdCredential({});
    assert.strictEqual(mockCalls[110].url, 'https://test-api.docutrust.org/api/v1/frost/credential/verify');

    // 64. v16.0.0 ZK-PlonK
    await client.compilePlonKCircuit('circ1', []);
    assert.strictEqual(mockCalls[111].url, 'https://test-api.docutrust.org/api/v1/zk/plonk/compile');
    await client.generatePlonKProof({}, {});
    assert.strictEqual(mockCalls[112].url, 'https://test-api.docutrust.org/api/v1/zk/plonk/prove');
    await client.verifyPlonKProof({}, {});
    assert.strictEqual(mockCalls[113].url, 'https://test-api.docutrust.org/api/v1/zk/plonk/verify');

    // 65. v16.0.0 Agentic Capabilities
    await client.issueRootCapability('did:key:root', 'did:key:aud', [], [], 3600, '0x123');
    assert.strictEqual(mockCalls[114].url, 'https://test-api.docutrust.org/api/v1/capability/root/issue');
    await client.attenuateCapability({}, 'did:key:del', 'did:key:aud', [], [], 1800, '0x123');
    assert.strictEqual(mockCalls[115].url, 'https://test-api.docutrust.org/api/v1/capability/attenuate');
    await client.verifyDelegationChain([], 'READ', 'urn:res');
    assert.strictEqual(mockCalls[116].url, 'https://test-api.docutrust.org/api/v1/capability/chain/verify');
    await client.createAgentExecutionReceipt('did:key:agent', {}, [], {}, '0x123');
    assert.strictEqual(mockCalls[117].url, 'https://test-api.docutrust.org/api/v1/capability/receipt/create');
    await client.verifyAgentExecutionReceipt({});
    assert.strictEqual(mockCalls[118].url, 'https://test-api.docutrust.org/api/v1/capability/receipt/verify');

    // 66. v17.0.0 Transparent STARKs
    await client.generateSTARKTrace(8, [1, 1], 'fibonacci');
    assert.strictEqual(mockCalls[119].url, 'https://test-api.docutrust.org/api/v1/stark/trace');
    await client.generateSTARKProof({}, 4);
    assert.strictEqual(mockCalls[120].url, 'https://test-api.docutrust.org/api/v1/stark/prove');
    await client.verifySTARKProof({});
    assert.strictEqual(mockCalls[121].url, 'https://test-api.docutrust.org/api/v1/stark/verify');

    // 67. v17.0.0 aBFT FROST Consensus Mesh
    await client.initFROSTConsensusCommittee([{ id: 'v1', weight: 1 }], 1);
    assert.strictEqual(mockCalls[122].url, 'https://test-api.docutrust.org/api/v1/frost/consensus/init');
    await client.generateFROSTConsensusRoundShare({}, 'v1', 'sec1', 'r1', {});
    assert.strictEqual(mockCalls[123].url, 'https://test-api.docutrust.org/api/v1/frost/consensus/share');
    await client.aggregateFROSTConsensusCommitment({}, 'r1', {}, []);
    assert.strictEqual(mockCalls[124].url, 'https://test-api.docutrust.org/api/v1/frost/consensus/aggregate');
    await client.verifyFROSTConsensusCommitment({}, {});
    assert.strictEqual(mockCalls[125].url, 'https://test-api.docutrust.org/api/v1/frost/consensus/verify');
    await client.generateFROSTEquivocationSlashingProof({}, {}, {});
    assert.strictEqual(mockCalls[126].url, 'https://test-api.docutrust.org/api/v1/frost/consensus/equivocation');

    // 68. v17.0.0 Verifiable Agent Memory & Poisoning Defense
    await client.commitAgentMemoryGraph('did:agent:1', []);
    assert.strictEqual(mockCalls[127].url, 'https://test-api.docutrust.org/api/v1/agent/memory/commit');
    await client.generateAgentMemorySimilarityProof([0.1], {}, 0, {}, 0.75);
    assert.strictEqual(mockCalls[128].url, 'https://test-api.docutrust.org/api/v1/agent/memory/prove-similarity');
    await client.verifyAgentMemorySimilarityProof({}, {});
    assert.strictEqual(mockCalls[129].url, 'https://test-api.docutrust.org/api/v1/agent/memory/verify-similarity');
    await client.auditAgentMemoryPoisoning({}, 'prompt', [0.1]);
    assert.strictEqual(mockCalls[130].url, 'https://test-api.docutrust.org/api/v1/agent/memory/audit');

    // 69. v17.0.0 Private Set Intersection (PSI)
    await client.blindPSIDataset('org_a', ['a']);
    assert.strictEqual(mockCalls[131].url, 'https://test-api.docutrust.org/api/v1/psi/blind');
    await client.doubleBlindPSIDataset(['a'], 'key2');
    assert.strictEqual(mockCalls[132].url, 'https://test-api.docutrust.org/api/v1/psi/double-blind');
    await client.computePSIIntersection('org_a', 'org_b', [], []);
    assert.strictEqual(mockCalls[133].url, 'https://test-api.docutrust.org/api/v1/psi/intersect');
    await client.createPSIExecutionReceipt({}, {}, {});
    assert.strictEqual(mockCalls[134].url, 'https://test-api.docutrust.org/api/v1/psi/receipt');
    await client.verifyPSIExecutionReceipt({});
    assert.strictEqual(mockCalls[135].url, 'https://test-api.docutrust.org/api/v1/psi/verify');

    // 70. v18.0.0 Zero-Knowledge Machine Learning (zkML)
    await client.commitModelWeights('m1', 'mlp', []);
    assert.strictEqual(mockCalls[136].url, 'https://test-api.docutrust.org/api/v1/zkml/commit');
    await client.proveZKMLInference('m1', {}, [], [1.0]);
    assert.strictEqual(mockCalls[137].url, 'https://test-api.docutrust.org/api/v1/zkml/prove');
    await client.verifyZKMLInference({});
    assert.strictEqual(mockCalls[138].url, 'https://test-api.docutrust.org/api/v1/zkml/verify');
    await client.exportZKMLSolidityCalldata({});
    assert.strictEqual(mockCalls[139].url, 'https://test-api.docutrust.org/api/v1/zkml/solidity-calldata');

    // 71. v18.0.0 MPC Garbled Circuits
    await client.garbleCircuit('c1', [], [], [], []);
    assert.strictEqual(mockCalls[140].url, 'https://test-api.docutrust.org/api/v1/mpc/garble');
    await client.initObliviousTransfer('s1', '00', '11', 0);
    assert.strictEqual(mockCalls[141].url, 'https://test-api.docutrust.org/api/v1/mpc/ot/init');
    await client.evaluateGarbledCircuit({}, {});
    assert.strictEqual(mockCalls[142].url, 'https://test-api.docutrust.org/api/v1/mpc/evaluate');
    await client.verifyGarbledCircuitReceipt({});
    assert.strictEqual(mockCalls[143].url, 'https://test-api.docutrust.org/api/v1/mpc/verify-receipt');

    // 72. v18.0.0 Verifiable Swarm Consensus
    await client.createSwarmCluster('Swarm1', []);
    assert.strictEqual(mockCalls[144].url, 'https://test-api.docutrust.org/api/v1/swarm/cluster/create');
    await client.proposeSwarmIntent('sw1', 'did:1', 'ACT', {});
    assert.strictEqual(mockCalls[145].url, 'https://test-api.docutrust.org/api/v1/swarm/propose');
    await client.signSwarmVote({}, {}, 'sec', 'APPROVE');
    assert.strictEqual(mockCalls[146].url, 'https://test-api.docutrust.org/api/v1/swarm/vote');
    await client.aggregateSwarmQuorum({}, [], []);
    assert.strictEqual(mockCalls[147].url, 'https://test-api.docutrust.org/api/v1/swarm/aggregate');
    await client.verifySwarmConsensusProof({}, []);
    assert.strictEqual(mockCalls[148].url, 'https://test-api.docutrust.org/api/v1/swarm/verify');

    // 73. v18.0.0 Threshold Timelock Encryption
    await client.generateVDFParameters(100);
    assert.strictEqual(mockCalls[149].url, 'https://test-api.docutrust.org/api/v1/timelock/vdf/params');
    await client.evaluateVDF({});
    assert.strictEqual(mockCalls[150].url, 'https://test-api.docutrust.org/api/v1/timelock/vdf/evaluate');
    await client.verifyVDFProof({});
    assert.strictEqual(mockCalls[151].url, 'https://test-api.docutrust.org/api/v1/timelock/vdf/verify');
    await client.sealTimelockCredential({});
    assert.strictEqual(mockCalls[152].url, 'https://test-api.docutrust.org/api/v1/timelock/seal');
    await client.unsealTimelockCredential({}, {});
    assert.strictEqual(mockCalls[153].url, 'https://test-api.docutrust.org/api/v1/timelock/unseal');
  });

  test('DocuTrustClient handles HTTP error responses gracefully', async () => {
    const errorFetch = async () => ({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      json: async () => ({ error: 'Invalid cryptographic signature' })
    });

    const client = new DocuTrustClient({ fetchFn: errorFetch });
    await assert.rejects(
      async () => {
        await client.verifyCredential({});
      },
      /DocuTrust API Error \[400\]: Invalid cryptographic signature/
    );
  });
});
