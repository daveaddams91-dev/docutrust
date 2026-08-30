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
