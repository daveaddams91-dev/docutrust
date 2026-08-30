/**
 * @fileoverview DocuTrust Sovereign Verifiable Credentials Client SDK (TypeScript / JavaScript).
 * Provides programmatic access to the DocuTrust REST API v1.1+ and local sovereign cryptography.
 * @module @docutrust/sdk
 */

export * from '@docutrust/core';

export interface DocuTrustClientOptions {
  apiUrl?: string;
  apiKey?: string;
  fetchFn?: typeof fetch;
}

export interface IssueCredentialOptions {
  credentialSubject: Record<string, any>;
  type?: string | string[];
  validUntil?: string;
  enableSelectiveDisclosure?: boolean;
  enablePQC?: boolean;
}

export interface BatchIssueOptions {
  records: Array<{ credentialSubject: Record<string, any> } | Record<string, any>>;
  type?: string | string[];
  anchorToLedger?: boolean;
}

export interface RenderPdfOptions {
  credential: Record<string, any>;
  title?: string;
}

export interface ZKRangeProveOptions {
  claimKey: string;
  actualValue: number;
  min: number;
  max: number;
  salt?: string;
}

export interface ZKAgeProveOptions {
  claimKey?: string;
  birthDate: string;
  minimumAgeYears: number;
  salt?: string;
  referenceDate?: string;
}

export interface ZKDateProveOptions {
  claimKey?: string;
  actualDate: string;
  minDate: string;
  maxDate: string;
  salt?: string;
}

export interface ZKMembershipProveOptions {
  claimKey: string;
  actualValue: string;
  allowedSet: string[];
  salt?: string;
}

export interface DIDCommPackOptions {
  message: Record<string, any>;
  recipientPublicKeyHex: string;
  recipientDid: string;
  senderKeyPair?: {
    publicKeyHex: string;
    secretKeyHex: string;
    did: string;
  };
}

export interface DIDCommUnpackOptions {
  envelope: Record<string, any>;
  recipientKeyPair: {
    publicKeyHex: string;
    secretKeyHex: string;
    did: string;
  };
  expectedSenderDid?: string;
}

export interface ShamirSplitOptions {
  secret: string;
  totalShares?: number;
  threshold?: number;
}

/**
 * Official client for interacting with the DocuTrust Sovereign Trust API.
 */
export class DocuTrustClient {
  private apiUrl: string;
  private apiKey?: string;
  private fetch: typeof fetch;

  constructor(options: DocuTrustClientOptions = {}) {
    this.apiUrl = (options.apiUrl || 'https://api.docutrust.org/api/v1').replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.fetch = options.fetchFn || globalThis.fetch.bind(globalThis);
  }

  private async request<T = any>(
    path: string,
    method: 'GET' | 'POST' = 'GET',
    body?: any
  ): Promise<T> {
    const url = `${this.apiUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers: Record<string, string> = {
      'Accept': 'application/json'
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await this.fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });

    if (!res.ok) {
      let errorDetail = res.statusText;
      try {
        const errorJson = await res.json();
        errorDetail = errorJson.error || errorJson.message || JSON.stringify(errorJson);
      } catch (_) {}
      throw new Error(`DocuTrust API Error [${res.status}]: ${errorDetail}`);
    }

    return (await res.json()) as T;
  }

  /**
   * Issues a W3C Verifiable Credential 2.0 with cryptographic signatures and optional PQC/Merkle disclosures.
   */
  public async issueCredential(options: IssueCredentialOptions): Promise<any> {
    const type = Array.isArray(options.type)
      ? options.type
      : ['VerifiableCredential', options.type || 'AchievementCredential'];

    return this.request('/credentials/issue', 'POST', {
      credentialSubject: options.credentialSubject,
      type,
      validUntil: options.validUntil,
      enableSelectiveDisclosure: options.enableSelectiveDisclosure,
      enablePQC: options.enablePQC
    });
  }

  /**
   * Batch issues multiple credentials anchored via Merkle Tree and Polygon Ledger receipts.
   */
  public async batchIssue(options: BatchIssueOptions): Promise<any> {
    const type = Array.isArray(options.type)
      ? options.type
      : ['VerifiableCredential', options.type || 'UniversityDegreeCredential'];

    const records = options.records.map(r => ('credentialSubject' in r ? r : { credentialSubject: r }));

    return this.request('/credentials/issue-batch', 'POST', {
      records,
      type,
      anchorToLedger: options.anchorToLedger !== false
    });
  }

  /**
   * Verifies a W3C Verifiable Credential against Ed25519 / Post-Quantum signatures and revocation status.
   */
  public async verifyCredential(
    credential: Record<string, any>,
    options: {
      expectedPublicKeyHex?: string;
      statusListCredential?: Record<string, any>;
      requiredSchema?: Record<string, any>;
      checkTrustRegistry?: boolean;
    } = {}
  ): Promise<any> {
    return this.request('/credentials/verify', 'POST', {
      credential,
      ...options
    });
  }

  /**
   * Extracts and cryptographically verifies an embedded Verifiable Credential from a PDF (base64 string or Uint8Array/Buffer).
   */
  public async verifyPdf(pdf: string | Uint8Array | Buffer): Promise<any> {
    let pdfBase64: string;
    if (typeof pdf === 'string') {
      pdfBase64 = pdf;
    } else {
      pdfBase64 = Buffer.from(pdf).toString('base64');
    }
    return this.request('/credentials/verify-pdf', 'POST', { pdfBase64 });
  }

  /**
   * Generates a tamper-evident visual PDF diploma with steganographic W3C metadata embedded.
   */
  public async renderPdf(options: RenderPdfOptions): Promise<any> {
    return this.request('/credentials/render-pdf', 'POST', options);
  }

  /**
   * Generates a Selective Disclosure Presentation with RFC 6962 Merkle inclusion proofs.
   */
  public async generateSelectiveDisclosure(credential: Record<string, any>, revealKeys: string[]): Promise<any> {
    return this.request('/credentials/selective-disclosure', 'POST', {
      credential,
      revealKeys
    });
  }

  /**
   * Generates a Zero-Knowledge Range Predicate Proof (e.g. GPA >= 3.5 or Age >= 21).
   */
  public async proveZKRange(options: ZKRangeProveOptions): Promise<any> {
    return this.request('/credentials/zk-predicate/prove', 'POST', {
      predicateType: 'range',
      claimKey: options.claimKey,
      actualValue: options.actualValue,
      salt: options.salt,
      min: options.min,
      max: options.max
    });
  }

  /**
   * Generates a Zero-Knowledge Age Predicate Proof (e.g. Age >= 18 or Age >= 21).
   */
  public async proveZKAge(options: ZKAgeProveOptions): Promise<any> {
    return this.request('/credentials/zk-predicate/prove-age', 'POST', {
      claimKey: options.claimKey || 'birthDate',
      birthDate: options.birthDate,
      minimumAgeYears: options.minimumAgeYears,
      salt: options.salt,
      referenceDate: options.referenceDate
    });
  }

  /**
   * Generates a Zero-Knowledge Date Range Proof.
   */
  public async proveZKDate(options: ZKDateProveOptions): Promise<any> {
    return this.request('/credentials/zk-predicate/prove-date', 'POST', {
      claimKey: options.claimKey || 'date',
      actualDate: options.actualDate,
      minDate: options.minDate,
      maxDate: options.maxDate,
      salt: options.salt
    });
  }

  /**
   * Verifies a Zero-Knowledge Predicate Proof.
   */
  public async verifyZKPredicate(proof: Record<string, any>, expectedCommitment?: string): Promise<any> {
    return this.request('/credentials/zk-predicate/verify', 'POST', {
      proof,
      expectedCommitment
    });
  }

  /**
   * Verifies a Zero-Knowledge Age Proof.
   */
  public async verifyZKAge(proof: Record<string, any>, expectedCommitment?: string): Promise<any> {
    return this.request('/credentials/zk-predicate/verify-age', 'POST', {
      proof,
      expectedCommitment
    });
  }

  /**
   * Verifies a Zero-Knowledge Date Proof.
   */
  public async verifyZKDate(proof: Record<string, any>, expectedCommitment?: string): Promise<any> {
    return this.request('/credentials/zk-predicate/verify-date', 'POST', {
      proof,
      expectedCommitment
    });
  }

  /**
   * Generates a Zero-Knowledge Set Membership Proof.
   */
  public async proveZKMembership(options: ZKMembershipProveOptions): Promise<any> {
    return this.request('/credentials/zk-predicate/prove', 'POST', {
      predicateType: 'membership',
      claimKey: options.claimKey,
      actualValue: options.actualValue,
      allowedSet: options.allowedSet,
      salt: options.salt
    });
  }

  /**
   * Verifies a Zero-Knowledge Set Membership Proof.
   */
  public async verifyZKMembership(proof: Record<string, any>, allowedSet: string[], expectedCommitment?: string): Promise<any> {
    return this.request('/credentials/zk-predicate/verify', 'POST', {
      proof,
      allowedSet,
      expectedCommitment
    });
  }

  /**
   * Generates NIST ML-KEM-768 quantum-safe hybrid recipient keys.
   */
  public async kemGenerateKeys(): Promise<any> {
    return this.request('/kem/generate-keys', 'POST', {});
  }

  /**
   * Encapsulates a symmetric key for quantum-resistant hybrid credential delivery.
   */
  public async kemEncapsulate(recipientPublicKeyHex: string): Promise<any> {
    return this.request('/kem/encapsulate', 'POST', { recipientPublicKeyHex });
  }

  /**
   * Decapsulates a shared secret using private ML-KEM keys.
   */
  public async kemDecapsulate(ciphertext: string, secretKeyHex: string): Promise<any> {
    return this.request('/kem/decapsulate', 'POST', { ciphertext, secretKeyHex });
  }

  /**
   * Creates an ephemeral challenge for Proof-of-Possession.
   */
  public async createPoPChallenge(audience: string = 'did:web:docutrust.org'): Promise<any> {
    return this.request('/credentials/pop/challenge', 'POST', { audience });
  }

  /**
   * Verifies a Proof-of-Possession presentation.
   */
  public async verifyPoPPresentation(presentation: Record<string, any>, expectedAudience?: string): Promise<any> {
    return this.request('/credentials/pop/verify', 'POST', {
      presentation,
      expectedAudience
    });
  }

  /**
   * Encrypts arbitrary data with AES-256-GCM authenticated envelope encryption.
   */
  public async encryptVault(data: any, passphrase: string): Promise<any> {
    return this.request('/vault/encrypt', 'POST', { data, passphrase });
  }

  /**
   * Decrypts an AES-256-GCM envelope payload.
   */
  public async decryptVault(encrypted: Record<string, any>, passphrase: string): Promise<any> {
    return this.request('/vault/decrypt', 'POST', { encrypted, passphrase });
  }

  /**
   * Splits a secret into K-of-N Shamir secret shares.
   */
  public async shamirSplit(options: ShamirSplitOptions): Promise<any> {
    return this.request('/keys/shamir/split', 'POST', {
      secret: options.secret,
      totalShares: options.totalShares || 5,
      threshold: options.threshold || 3
    });
  }

  /**
   * Reconstructs a secret from Shamir shares.
   */
  public async shamirCombine(shares: Array<Record<string, any>>): Promise<any> {
    return this.request('/keys/shamir/combine', 'POST', { shares });
  }

  /**
   * Issues an IETF SD-JWT package with salted disclosures.
   */
  public async issueSDJWT(claims: Record<string, any>, subjectDid?: string): Promise<any> {
    return this.request('/credentials/sd-jwt/issue', 'POST', {
      claims,
      subjectDid
    });
  }

  /**
   * Verifies an IETF SD-JWT presentation string.
   */
  public async verifySDJWT(presentation: string): Promise<any> {
    return this.request('/credentials/sd-jwt/verify', 'POST', { presentation });
  }

  /**
   * Validates issuer accreditation against the Decentralized Trust Registry.
   */
  public async verifyTrustIssuer(issuerDid: string, schemaType: string): Promise<any> {
    return this.request('/trust/verify-issuer', 'POST', { issuerDid, schemaType });
  }

  /**
   * Creates a signed Revocation Bloom Filter.
   */
  public async createBloomFilter(revokedIds: string[], sizeBits: number = 8192, hashCount: number = 5): Promise<any> {
    return this.request('/revocation/bloom/create', 'POST', {
      revokedIds,
      sizeBits,
      hashCount
    });
  }

  /**
   * Checks credential revocation status against a signed Bloom Filter.
   */
  public async checkBloomFilter(signedFilter: Record<string, any>, credentialId: string): Promise<any> {
    return this.request('/revocation/bloom/check', 'POST', {
      signedFilter,
      credentialId
    });
  }

  /**
   * Generates BBS+ keypair with generator commitments.
   */
  public async bbsGenerateKeys(maxMessages: number = 10): Promise<any> {
    return this.request('/credentials/bbs/generate-keys', 'POST', { maxMessages });
  }

  /**
   * Signs a message vector with BBS+ pairing signatures.
   */
  public async bbsIssue(messages: string[], keyPair?: Record<string, any>): Promise<any> {
    return this.request('/credentials/bbs/issue', 'POST', { messages, keyPair });
  }

  /**
   * Derives an unlinkable BBS+ zero-knowledge proof disclosing only specific message indices.
   */
  public async bbsDeriveProof(
    signature: Record<string, any>,
    allMessages: string[],
    disclosedIndices: number[],
    keyPair?: Record<string, any>,
    nonce?: string
  ): Promise<any> {
    return this.request('/credentials/bbs/derive-proof', 'POST', {
      signature,
      allMessages,
      disclosedIndices,
      keyPair,
      nonce
    });
  }

  /**
   * Verifies an unlinkable BBS+ zero-knowledge proof.
   */
  public async bbsVerifyProof(proof: Record<string, any>, expectedIssuerDid?: string): Promise<any> {
    return this.request('/credentials/bbs/verify-proof', 'POST', {
      proof,
      expectedIssuerDid
    });
  }

  /**
   * Issues an RFC 3161 cryptographic timestamp token from the TSA Oracle.
   */
  public async issueTimestampToken(data: string, nonce?: string): Promise<any> {
    return this.request('/oracle/timestamp', 'POST', { data, nonce });
  }

  /**
   * Verifies an RFC 3161 cryptographic timestamp token.
   */
  public async verifyTimestampToken(token: Record<string, any>, expectedData?: string): Promise<any> {
    return this.request('/oracle/verify-timestamp', 'POST', { token, expectedData });
  }

  /**
   * Packs an encrypted DIDComm v2 message envelope.
   */
  public async didcommPack(options: DIDCommPackOptions): Promise<any> {
    return this.request('/didcomm/pack', 'POST', options);
  }

  /**
   * Unpacks and decrypts a DIDComm v2 message envelope.
   */
  public async didcommUnpack(options: DIDCommUnpackOptions): Promise<any> {
    return this.request('/didcomm/unpack', 'POST', options);
  }

  /**
   * Appends a leaf to the streaming Merkle Mountain Range ledger.
   */
  public async mmrAppend(leaf: string): Promise<any> {
    return this.request('/ledger/mmr/append', 'POST', { leaf });
  }

  /**
   * Retrieves peaks and bagged root of Merkle Mountain Range.
   */
  public async mmrGetPeaks(): Promise<any> {
    return this.request('/ledger/mmr', 'GET');
  }

  /**
   * Gets peak inclusion proof for an element in the Merkle Mountain Range.
   */
  public async mmrGetProof(elementIndex: number): Promise<any> {
    return this.request('/ledger/mmr/proof', 'POST', { elementIndex });
  }

  /**
   * Verifies a Merkle Mountain Range peak inclusion proof.
   */
  public async mmrVerifyProof(proof: Record<string, any>): Promise<any> {
    return this.request('/ledger/mmr/verify', 'POST', { proof });
  }

  /**
   * Retrieves the tamper-evident hashchain and verifies audit integrity.
   */
  public async getHashchain(): Promise<any> {
    return this.request('/ledger/hashchain', 'GET');
  }

  /**
   * Retrieves credential vault metrics and telemetry.
   */
  public async getVaultMetrics(): Promise<any> {
    return this.request('/vault/metrics', 'GET');
  }

  /**
   * Triggers the batch auto-anchoring worker on unanchored vault credentials.
   */
  public async autoAnchorVault(): Promise<any> {
    return this.request('/vault/auto-anchor', 'POST', {});
  }

  /**
   * Generates Ethereum secp256k1 keypair and did:pkh DID.
   */
  public async generateSecp256k1Keys(chainId: number = 1): Promise<any> {
    return this.request('/crypto/secp256k1/generate', 'POST', { chainId });
  }

  /**
   * Signs W3C Verifiable Credential using EIP-712 structured typed data.
   */
  public async signVcEIP712(unsignedVc: Record<string, any>, keyPair: any, domain?: any): Promise<any> {
    return this.request('/credentials/eip712/sign', 'POST', { unsignedVc, keyPair, domain });
  }

  /**
   * Verifies EIP-712 structured signature on W3C Verifiable Credential.
   */
  public async verifyVcEIP712(credential: Record<string, any>, expectedSigner?: string): Promise<any> {
    return this.request('/credentials/eip712/verify', 'POST', { credential, expectedSigner });
  }

  /**
   * Sets up decentralized social recovery with guardian DIDs.
   */
  public async setupSocialRecovery(
    ownerDid: string,
    secret: string,
    guardians: Array<{ did: string; name: string }>,
    threshold: number = 3,
    challengePeriodHours: number = 48
  ): Promise<any> {
    return this.request('/recovery/social/setup', 'POST', {
      ownerDid,
      secret,
      guardians,
      threshold,
      challengePeriodHours
    });
  }

  /**
   * Initiates a timelocked social recovery session.
   */
  public async initiateSocialRecovery(
    ownerDid: string,
    requesterDid: string,
    config: any
  ): Promise<any> {
    return this.request('/recovery/social/initiate', 'POST', {
      ownerDid,
      requesterDid,
      config
    });
  }

  /**
   * Guardian casts a vote releasing recovery share.
   */
  public async castSocialRecoveryVote(
    session: any,
    guardianDid: string,
    shareIndex: number,
    rawShareHex: string
  ): Promise<any> {
    return this.request('/recovery/social/vote', 'POST', {
      session,
      guardianDid,
      shareIndex,
      rawShareHex
    });
  }

  /**
   * Genuine owner vetoes a fraudulent recovery session.
   */
  public async vetoSocialRecovery(
    session: any,
    reason: string = 'Unauthorized recovery attempt'
  ): Promise<any> {
    return this.request('/recovery/social/veto', 'POST', {
      session,
      reason
    });
  }

  /**
   * Finalizes social recovery and reconstructs the root secret.
   */
  public async finalizeSocialRecovery(
    session: any,
    forceTimelockOverride: boolean = false
  ): Promise<any> {
    return this.request('/recovery/social/finalize', 'POST', {
      session,
      forceTimelockOverride
    });
  }

  /**
   * Generates a Zero-Knowledge Set Non-Membership Proof.
   */
  public async proveSetNonMembership(
    claimKey: string,
    secretValue: string,
    salt: string,
    restrictedSet: string[]
  ): Promise<any> {
    return this.request('/zk/prove-non-membership', 'POST', {
      claimKey,
      secretValue,
      salt,
      restrictedSet
    });
  }

  /**
   * Verifies a Zero-Knowledge Set Non-Membership Proof.
   */
  public async verifySetNonMembership(
    proof: Record<string, any>,
    restrictedSet: string[],
    expectedCommitment?: string
  ): Promise<any> {
    return this.request('/zk/verify-non-membership', 'POST', {
      proof,
      restrictedSet,
      expectedCommitment
    });
  }

  /**
   * Combines multiple ZK predicate proofs into a composite proof.
   */
  public async proveCompositePredicate(proofs: any[]): Promise<any> {
    return this.request('/zk/prove-composite', 'POST', { proofs });
  }

  /**
   * Verifies a multi-predicate composite ZK proof.
   */
  public async verifyCompositePredicate(
    compositeProof: Record<string, any>,
    context?: { allowedSets?: Record<string, string[]>; restrictedSets?: Record<string, string[]> }
  ): Promise<any> {
    return this.request('/zk/verify-composite', 'POST', {
      compositeProof,
      context
    });
  }

  /**
   * Generates standardized multi-chain anchor payload and calldata.
   */
  public async formatMultiChainAnchor(
    chain: string,
    merkleRoot: string,
    batchCount: number,
    memo?: string
  ): Promise<any> {
    return this.request('/ledger/multichain/anchor', 'POST', {
      chain,
      merkleRoot,
      batchCount,
      memo
    });
  }

  /**
   * Validates arbitrary data against a JSON schema.
   */
  public async validateSchema(data: any, schema: Record<string, any>, path?: string): Promise<any> {
    return this.request('/schema/validate', 'POST', { data, schema, path });
  }

  /**
   * Validates a VC's credentialSubject against a JSON schema.
   */
  public async validateCredentialSubjectSchema(
    credential: Record<string, any>,
    schema: Record<string, any>
  ): Promise<any> {
    return this.request('/schema/validate-credential', 'POST', { credential, schema });
  }

  /**
   * Encrypts payload in General JWE format for multiple recipients.
   */
  public async encryptJWE(
    payload: any,
    recipients: Array<{ did: string; publicKey: string }>,
    customProtectedHeader?: Record<string, any>
  ): Promise<any> {
    return this.request('/jwe/encrypt', 'POST', {
      payload,
      recipients,
      customProtectedHeader
    });
  }

  /**
   * Decrypts General JWE for recipient DID.
   */
  public async decryptJWE(
    jwe: Record<string, any>,
    recipientDid: string,
    recipientPrivateKey: string
  ): Promise<any> {
    return this.request('/jwe/decrypt', 'POST', {
      jwe,
      recipientDid,
      recipientPrivateKey
    });
  }

  /**
   * Generates a Zero-Knowledge Set Intersection Proof.
   */
  public async proveSetIntersection(
    claimKey: string,
    secretValue: string,
    salt: string,
    targetSet: string[]
  ): Promise<any> {
    return this.request('/zk/prove-intersection', 'POST', {
      claimKey,
      secretValue,
      salt,
      targetSet
    });
  }

  /**
   * Verifies a Zero-Knowledge Set Intersection Proof.
   */
  public async verifySetIntersection(
    proof: Record<string, any>,
    targetSet: string[],
    expectedCommitment?: string
  ): Promise<any> {
    return this.request('/zk/verify-intersection', 'POST', {
      proof,
      targetSet,
      expectedCommitment
    });
  }

  /**
   * Generates a cryptographic Non-Membership Witness for an element not present in the accumulator.
   */
  public async createAccumulatorNonMembershipWitness(
    id: string,
    element: string
  ): Promise<any> {
    return this.request('/accumulator/non-membership-witness', 'POST', { id, element });
  }

  /**
   * Verifies an accumulator Non-Membership Witness.
   */
  public async verifyAccumulatorNonMembership(
    witness: Record<string, any>,
    currentAccumulatorHex: string,
    generatorHex?: string,
    modulusHex?: string
  ): Promise<any> {
    return this.request('/accumulator/verify-non-membership', 'POST', {
      witness,
      currentAccumulatorHex,
      generatorHex,
      modulusHex
    });
  }

  /**
   * Creates a W3C BitstringStatusList2024 bitstring instance and optional StatusList2024Credential.
   */
  public async createStatusList2024(
    length: number = 100000,
    statusSize: 1 | 2 | 4 | 8 = 1,
    statusPurpose: 'revocation' | 'suspension' = 'revocation',
    id?: string,
    issuer?: string
  ): Promise<any> {
    return this.request('/statuslist2024/create', 'POST', {
      length,
      statusSize,
      statusPurpose,
      id,
      issuer
    });
  }

  /**
   * Checks status at specified index within a BitstringStatusList2024.
   */
  public async checkStatusList2024(
    encodedList: string,
    index: number,
    statusSize: number = 1,
    length?: number
  ): Promise<any> {
    return this.request('/statuslist2024/check', 'POST', {
      encodedList,
      index,
      statusSize,
      length
    });
  }

  /**
   * Updates status at specified index within a BitstringStatusList2024.
   */
  public async updateStatusList2024(
    encodedList: string,
    index: number,
    status: number,
    statusSize: number = 1,
    length?: number
  ): Promise<any> {
    return this.request('/statuslist2024/update', 'POST', {
      encodedList,
      index,
      status,
      statusSize,
      length
    });
  }

  /**
   * Creates a DIF Presentation Exchange 2.0 Presentation Definition.
   */
  public async createPresentationDefinition(
    id: string,
    inputDescriptors: any[],
    name?: string,
    purpose?: string
  ): Promise<any> {
    return this.request('/pe/definition/create', 'POST', {
      id,
      inputDescriptors,
      name,
      purpose
    });
  }

  /**
   * Creates a DIF Presentation Exchange 2.0 Presentation Submission.
   */
  public async createPresentationSubmission(
    id: string,
    definitionId: string,
    descriptorMap: any[]
  ): Promise<any> {
    return this.request('/pe/submission/create', 'POST', {
      id,
      definitionId,
      descriptorMap
    });
  }

  /**
   * Evaluates a Verifiable Presentation against a DIF Presentation Definition and optional Submission.
   */
  public async evaluatePresentationExchange(
    presentation: Record<string, any>,
    definition: Record<string, any>,
    submission?: Record<string, any>
  ): Promise<any> {
    return this.request('/pe/evaluate', 'POST', {
      presentation,
      definition,
      submission
    });
  }

  /**
   * Generates a recursive Zero-Knowledge Predicate Graph Proof.
   */
  public async proveZKPredicateGraph(
    graphId: string,
    root: Record<string, any>
  ): Promise<any> {
    return this.request('/zk/prove-graph', 'POST', {
      graphId,
      root
    });
  }

  /**
   * Verifies a recursive Zero-Knowledge Predicate Graph Proof.
   */
  public async verifyZKPredicateGraph(
    graphProof: Record<string, any>,
    context?: Record<string, any>
  ): Promise<any> {
    return this.request('/zk/verify-graph', 'POST', {
      graphProof,
      context
    });
  }

  /**
   * Creates an unsigned Multi-Signature (M-of-N) Credential draft and canonical hash.
   */
  public async createMultiSigDraft(
    credential: Record<string, any>,
    policy: Record<string, any>
  ): Promise<any> {
    return this.request('/credentials/multisig/draft', 'POST', { credential, policy });
  }

  /**
   * Signs a canonical hash as an authorized institutional authority.
   */
  public async signMultiSigAsAuthority(
    canonicalHash: string,
    signerDid: string,
    signerRole: string,
    privateKeyHex: string
  ): Promise<any> {
    return this.request('/credentials/multisig/sign', 'POST', {
      canonicalHash,
      signerDid,
      signerRole,
      privateKeyHex
    });
  }

  /**
   * Assembles a finalized M-of-N MultiSig Verifiable Credential from collected signatures.
   */
  public async assembleMultiSigCredential(
    credential: Record<string, any>,
    policy: Record<string, any>,
    signatures: any[]
  ): Promise<any> {
    return this.request('/credentials/multisig/assemble', 'POST', {
      credential,
      policy,
      signatures
    });
  }

  /**
   * Cryptographically verifies an M-of-N MultiSig Verifiable Credential against policy.
   */
  public async verifyMultiSigCredential(
    credential: Record<string, any>,
    policy?: Record<string, any>
  ): Promise<any> {
    return this.request('/credentials/multisig/verify', 'POST', {
      credential,
      policy
    });
  }

  /**
   * Resolves a DID string to its complete W3C DID Document.
   */
  public async resolveDID(did: string): Promise<any> {
    return this.request(`/did/resolve?did=${encodeURIComponent(did)}`, 'GET');
  }

  /**
   * Retrieves all accredited issuers in the Decentralized Trust Registry.
   */
  public async getTrustRegistryIssuers(): Promise<any> {
    return this.request('/trust/registry', 'GET');
  }

  /**
   * Queries stored credentials from the institutional vault.
   */
  public async getVaultCredentials(query?: { search?: string; type?: string; limit?: number; offset?: number }): Promise<any> {
    const params = new URLSearchParams();
    if (query?.search) params.set('search', query.search);
    if (query?.type) params.set('type', query.type);
    if (query?.limit) params.set('limit', String(query.limit));
    if (query?.offset) params.set('offset', String(query.offset));
    const qs = params.toString();
    return this.request(`/vault/credentials${qs ? `?${qs}` : ''}`, 'GET');
  }

  // ==========================================
  // AnonCreds 2.0 & Blind Issuance Methods
  // ==========================================

  /**
   * Holder creates a blind credential request binding a holder master secret.
   */
  public async createAnonCredsBlindRequest(schemaId: string, issuerDid: string, masterSecret?: string): Promise<any> {
    return this.request('/anoncreds/blind-request', 'POST', { schemaId, issuerDid, masterSecret });
  }

  /**
   * Issuer issues a blinded BBS+ credential bound to the holder's master secret commitment.
   */
  public async issueAnonCredsBlindCredential(
    request: any,
    claims: Record<string, any>,
    issuerEdKeys: any,
    issuerKeys?: any
  ): Promise<any> {
    return this.request('/anoncreds/blind-issue', 'POST', { request, claims, issuerEdKeys, issuerKeys });
  }

  /**
   * Holder unblinds the blind credential and stores it with their master secret.
   */
  public async unblindAnonCredsCredential(blindCredential: any, masterSecret: string, blindingFactor: string): Promise<any> {
    return this.request('/anoncreds/unblind', 'POST', { blindCredential, masterSecret, blindingFactor });
  }

  /**
   * Holder generates an unlinkable Zero-Knowledge Presentation for a Verifier.
   */
  public async createAnonCredsPresentation(
    credential: any,
    masterSecret: string,
    revealKeys: string[],
    verifierNonce: string,
    predicateProofs?: any[]
  ): Promise<any> {
    return this.request('/anoncreds/create-presentation', 'POST', {
      credential,
      masterSecret,
      revealKeys,
      verifierNonce,
      predicateProofs
    });
  }

  /**
   * Verifier validates an AnonCreds Zero-Knowledge Presentation.
   */
  public async verifyAnonCredsPresentation(presentation: any, verifierNonce?: string, issuerDid?: string): Promise<any> {
    return this.request('/anoncreds/verify-presentation', 'POST', { presentation, verifierNonce, issuerDid });
  }

  // ==========================================
  // FROST DKG Distributed Key Generation
  // ==========================================

  /**
   * Runs a complete Distributed Key Generation (DKG) setup ceremony.
   */
  public async runDKGCeremony(participants: Array<{ name: string; did?: string }>, threshold: number): Promise<any> {
    return this.request('/dkg/ceremony', 'POST', { participants, threshold });
  }

  /**
   * Generates a partial signature share for a message using participant private share.
   */
  public async signDKGShare(participantIndex: number, privateShareHex: string, signerDid: string, message: string): Promise<any> {
    return this.request('/dkg/sign-share', 'POST', { participantIndex, privateShareHex, signerDid, message });
  }

  /**
   * Aggregates partial signature shares into a valid group Ed25519 signature.
   */
  public async aggregateDKGSignatures(groupPublicKeyHex: string, groupDid: string, threshold: number, shares: any[]): Promise<any> {
    return this.request('/dkg/aggregate', 'POST', { groupPublicKeyHex, groupDid, threshold, shares });
  }

  /**
   * Verifies an aggregated FROST threshold signature.
   */
  public async verifyDKGSignature(signature: any, message: string, groupPublicKeyHex?: string): Promise<any> {
    return this.request('/dkg/verify', 'POST', { signature, message, groupPublicKeyHex });
  }

  // ==========================================
  // EVM Solidity Smart Contract Verifier
  // ==========================================

  /**
   * Generates production-ready DocuTrustVerifier.sol Solidity source code.
   */
  public async generateSolidityVerifier(contractName?: string, ownerAddress?: string): Promise<any> {
    return this.request('/solidity/generate-verifier', 'POST', { contractName, ownerAddress });
  }

  /**
   * Encodes ABI calldata for calling on-chain verifyCredentialOnChain.
   */
  public async encodeSolidityCalldata(credentialHash: string, merkleProof: any[], rootHash: string): Promise<any> {
    return this.request('/solidity/calldata', 'POST', { credentialHash, merkleProof, rootHash });
  }

  // ==========================================
  // Cryptographic Audit Bundles (.dtbundle)
  // ==========================================

  /**
   * Creates a signed cryptographic audit bundle (.dtbundle).
   */
  public async createAuditBundle(organization?: string, signerKeyPair?: any, complianceStandards?: string[]): Promise<any> {
    return this.request('/audit/bundle/create', 'POST', { organization, signerKeyPair, complianceStandards });
  }

  /**
   * Verifies a cryptographic audit bundle (.dtbundle).
   */
  public async verifyAuditBundle(bundle: any, expectedSignerPublicKeyHex?: string): Promise<any> {
    return this.request('/audit/bundle/verify', 'POST', { bundle, expectedSignerPublicKeyHex });
  }

  /**
   * Verifies an audit bundle and generates a formal Markdown compliance report.
   */
  public async getAuditBundleComplianceReport(bundle: any, expectedSignerPublicKeyHex?: string): Promise<any> {
    return this.request('/audit/bundle/report', 'POST', { bundle, expectedSignerPublicKeyHex });
  }

  // ==========================================
  // W3C DataIntegrityProof Cryptosuites
  // ==========================================

  /**
   * Issues a W3C Verifiable Credential secured with DataIntegrityProof.
   */
  public async issueDataIntegrityCredential(options: {
    issuer: any;
    credentialSubject: any;
    cryptosuite?: string;
    keyPair: any;
  }): Promise<any> {
    return this.request('/credentials/dataintegrity/issue', 'POST', options);
  }

  /**
   * Verifies a W3C DataIntegrityProof credential.
   */
  public async verifyDataIntegrityCredential(credential: any): Promise<any> {
    return this.request('/credentials/dataintegrity/verify', 'POST', { credential });
  }
}



