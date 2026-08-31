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
   * Generates a constant-size batch membership witness for a subset of elements.
   */
  public async createAccumulatorBatchWitness(
    id: string,
    elements: string[]
  ): Promise<any> {
    return this.request('/accumulator/batch-witness', 'POST', { id, elements });
  }

  /**
   * Verifies a constant-size batch membership witness.
   */
  public async verifyAccumulatorBatchWitness(
    witness: Record<string, any>,
    currentAccumulatorHex?: string,
    modulusHex?: string
  ): Promise<any> {
    return this.request('/accumulator/verify-batch', 'POST', {
      witness,
      currentAccumulatorHex,
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

  // ==========================================
  // v6.0.0 Confidential Homomorphic Computing
  // ==========================================

  /**
   * Generates a Paillier KeyPair for confidential additive arithmetic.
   */
  public async generatePaillierKeyPair(bitLength: number = 512): Promise<any> {
    return this.request('/confidential/keys/generate', 'POST', { bitLength });
  }

  /**
   * Encrypts a numeric credential claim into a Paillier confidential payload.
   */
  public async encryptConfidentialClaim(claimKey: string, value: number, publicKey: any): Promise<any> {
    return this.request('/confidential/encrypt', 'POST', { claimKey, value, publicKey });
  }

  /**
   * Computes homomorphic addition over multiple encrypted claim ciphertexts.
   */
  public async homomorphicSum(ciphertexts: string[], publicKey: any): Promise<any> {
    return this.request('/confidential/compute/sum', 'POST', { ciphertexts, publicKey });
  }

  /**
   * Proves that a confidential claim satisfies a threshold condition without revealing the value.
   */
  public async proveConfidentialThreshold(
    claimKey: string,
    actualValue: number,
    threshold: number,
    operator: 'gte' | 'lte' | 'eq',
    publicKey: any
  ): Promise<any> {
    return this.request('/confidential/proof/threshold', 'POST', { claimKey, actualValue, threshold, operator, publicKey });
  }

  /**
   * Verifies a confidential zero-knowledge threshold proof.
   */
  public async verifyConfidentialThreshold(proof: any): Promise<any> {
    return this.request('/confidential/verify/threshold', 'POST', { proof });
  }

  /**
   * Evaluates a homomorphic linear combination (weighted sum) over encrypted Paillier ciphertexts.
   */
  public async evaluateConfidentialLinearCombination(
    terms: Array<{ ciphertext?: string; ciphertextHex?: string; weight: number }>,
    publicKey: any
  ): Promise<any> {
    return this.request('/confidential/compute/linear-combination', 'POST', { terms, publicKey });
  }

  // ==========================================
  // v6.0.0 W3C URDNA2015 JSON-LD Linked Data
  // ==========================================

  /**
   * Canonicalizes a JSON-LD document into deterministic URDNA2015 / RDFC-1.0 N-Quads.
   */
  public async canonicalizeJsonLd(document: any): Promise<any> {
    return this.request('/jsonld/canonicalize', 'POST', { document });
  }

  /**
   * Signs a JSON-LD document with Linked Data Signatures.
   */
  public async signJsonLd(document: any, keyPair: any, options?: any): Promise<any> {
    return this.request('/jsonld/sign', 'POST', { document, keyPair, options });
  }

  /**
   * Verifies a W3C Linked Data Signed JSON-LD document.
   */
  public async verifyJsonLd(document: any, expectedPublicKeyHex?: string): Promise<any> {
    return this.request('/jsonld/verify', 'POST', { document, expectedPublicKeyHex });
  }

  // ==========================================
  // v6.0.0 Hierarchical Verifiable Trust Chains
  // ==========================================

  /**
   * Issues a signed delegation token to a subordinate authority or department.
   */
  public async createDelegationToken(options: {
    delegatorKeyPair: any;
    delegateDid: string;
    allowedCredentialTypes?: string[];
    maxDepth?: number;
    validFrom?: string;
    validUntil?: string;
  }): Promise<any> {
    return this.request('/trustchain/token/create', 'POST', options);
  }

  /**
   * Recursively verifies an end-to-end delegation trust chain against an issued credential.
   */
  public async verifyTrustChain(options: {
    chain: any[];
    credential: any;
    accreditedRootDids: string[];
  }): Promise<any> {
    return this.request('/trustchain/verify', 'POST', options);
  }

  // ==========================================
  // v6.0.0 Post-Quantum Dual Hybrid KEM Armor
  // ==========================================

  /**
   * Generates a Dual-KEM Hybrid KeyPair (X25519 + NIST ML-KEM-768).
   */
  public async generateDualKEMKeys(): Promise<any> {
    return this.request('/quantum-armor/keys/generate', 'GET');
  }

  /**
   * Encrypts and seals any credential payload inside a Quantum-Sealed Envelope.
   */
  public async sealCredentialWithQuantumArmor(payload: any, recipientHybridPub: any): Promise<any> {
    return this.request('/quantum-armor/seal', 'POST', { payload, recipientHybridPub });
  }

  /**
   * Unseals and decrypts a Quantum-Sealed Envelope.
   */
  public async unsealCredentialWithQuantumArmor(envelope: any, recipientHybridPriv: any): Promise<any> {
    return this.request('/quantum-armor/unseal', 'POST', { envelope, recipientHybridPriv });
  }

  // ==========================================
  // Verifiable SVG Digital Badge Methods
  // ==========================================

  /**
   * Renders a tamper-evident Verifiable SVG digital badge for a credential.
   */
  public async renderBadgeSvg(credential: any, options?: { theme?: string; badgeTitle?: string; recipientName?: string; width?: number; height?: number }): Promise<{ success: boolean; svg: string }> {
    return this.request('/badge/render', 'POST', { credential, options });
  }

  /**
   * Verifies the cryptographic integrity and authenticity of an SVG badge.
   */
  public async verifyBadgeSvg(svg: string): Promise<{ success: boolean; valid: boolean; canonicalHash?: string; issuer?: string; error?: string }> {
    return this.request('/badge/verify', 'POST', { svg });
  }

  // ==========================================
  // v9.0.0 Sovereign Policy-as-Proof & did:peer
  // ==========================================

  /**
   * Evaluates a Verifiable Credential or Presentation against an AST Policy-as-Proof.
   */
  public async evaluatePolicy(payload: any, policy: any, evaluatorKeyPair?: any): Promise<any> {
    return this.request('/policy/evaluate', 'POST', { payload, policy, evaluatorKeyPair });
  }

  /**
   * Resolves a W3C did:peer identifier (Method 0 or Method 2).
   */
  public async resolveDidPeer(did: string): Promise<any> {
    return this.request(`/did/peer/resolve?did=${encodeURIComponent(did)}`, 'GET');
  }

  /**
   * Creates a W3C did:peer:0 inception key or did:peer:2 multiple keys URI.
   */
  public async createDidPeer(options: {
    method: 0 | 2;
    publicKeyHex?: string;
    verificationKeyHex?: string;
    encryptionKeyHex?: string;
    serviceEndpoint?: string;
  }): Promise<{ success: boolean; did: string }> {
    return this.request('/did/peer/create', 'POST', options);
  }

  /**
   * Validates multi-partition status list aggregation on-chain / off-chain.
   */
  public async checkAggregatedStatus(aggregateRoot: string, partitions: any[]): Promise<any> {
    return this.request('/statuslist/aggregate-check', 'POST', { aggregateRoot, partitions });
  }

  /**
   * Generates production-ready Solidity smart contract for the Sovereign Trust Registry.
   */
  public async generateSolidityRegistry(options?: { contractName?: string; solidityVersion?: string }): Promise<{ success: boolean; contractCode: string }> {
    return this.request('/solidity/export-registry', 'POST', options || {});
  }

  // ========================================================
  // v10.0.0 Linkable Ring Signatures (LSAG)
  // ========================================================

  /**
   * Generates a 1-of-N Linkable Ring Signature (LSAG) protecting signer identity.
   */
  public async signRingSignature(options: {
    message: any;
    ring: string[];
    signerPrivateKeyHex: string;
    signerPublicKeyHex?: string;
  }): Promise<{ success: boolean; signature: any }> {
    return this.request('/ringsig/sign', 'POST', options);
  }

  /**
   * Cryptographically verifies an LSAG Linkable Ring Signature and checks for double action tags.
   */
  public async verifyRingSignature(options: {
    message: any;
    signature: any;
    usedKeyImages?: string[];
  }): Promise<{ success: boolean; valid: boolean; ringSize: number; keyImage: string; isDoubleAction: boolean; error?: string }> {
    return this.request('/ringsig/verify', 'POST', options);
  }

  // ========================================================
  // v10.0.0 256-bit Sparse Merkle Trees (SMT) & Solidity Verifier
  // ========================================================

  /**
   * Updates or sets a key-value pair in a 256-bit Sparse Merkle Tree.
   */
  public async setSMTLeaf(key: string, value: string): Promise<{ success: boolean; key: string; value: string; root: string }> {
    return this.request('/smt/set', 'POST', { key, value });
  }

  /**
   * Generates a logarithmic audit proof (inclusion or non-membership) from an SMT.
   */
  public async generateSMTProof(key: string, entries?: Record<string, string>): Promise<{ success: boolean; proof: any }> {
    return this.request('/smt/prove', 'POST', { key, entries });
  }

  /**
   * Verifies an SMT cryptographic inclusion or non-membership proof.
   */
  public async verifySMTProof(proof: any, root?: string): Promise<{ success: boolean; valid: boolean; root: string; exists: boolean }> {
    return this.request('/smt/verify', 'POST', { proof, root });
  }

  /**
   * Generates production-ready Solidity smart contract for SMT verification (DocuTrustSMTVerifier.sol).
   */
  public async generateSoliditySMTVerifier(options?: { contractName?: string; solidityVersion?: string }): Promise<{ success: boolean; contractCode: string }> {
    return this.request('/solidity/export-smt', 'POST', options || {});
  }

  /**
   * Verifies a Sovereign Policy Evaluation Receipt.
   */
  public async verifyPolicyReceipt(receipt: any, publicKeyHex?: string): Promise<{ success: boolean; valid: boolean }> {
    return this.request('/policy/verify-receipt', 'POST', { receipt, publicKeyHex });
  }

  // ========================================================
  // v11.0.0 NIST FIPS 205 SLH-DSA Client Methods
  // ========================================================

  /**
   * Generates a NIST FIPS 205 SLH-DSA-SHA2-128s stateless hash-based keypair and DID.
   */
  public async generateSLHDSAKeyPair(): Promise<{ success: boolean; keyPair: any }> {
    return this.request('/slhdsa/keygen', 'POST', {});
  }

  /**
   * Signs a message using SLH-DSA post-quantum private key.
   */
  public async signSLHDSA(message: any, keyPair: any): Promise<{ success: boolean; signature: any }> {
    return this.request('/slhdsa/sign', 'POST', { message, keyPair });
  }

  /**
   * Cryptographically verifies an SLH-DSA post-quantum signature.
   */
  public async verifySLHDSA(message: any, signature: any, publicKey: string | any): Promise<{ success: boolean; valid: boolean; algorithm: string }> {
    return this.request('/slhdsa/verify', 'POST', { message, signature, publicKey });
  }

  // ========================================================
  // v11.0.0 WebAuthn / FIDO2 Passkey Client Methods
  // ========================================================

  /**
   * Generates a P-256 WebAuthn passkey keypair.
   */
  public async generateWebAuthnKeyPair(rpId?: string): Promise<{ success: boolean; keyPair: any }> {
    return this.request('/webauthn/keygen', 'POST', { rpId });
  }

  /**
   * Creates a signed WebAuthn passkey assertion.
   */
  public async createWebAuthnAssertion(challenge: string, keyPair: any, options?: { rpId?: string; origin?: string }): Promise<{ success: boolean; assertion: any }> {
    return this.request('/webauthn/assertion', 'POST', { challenge, keyPair, ...options });
  }

  /**
   * Verifies a WebAuthn passkey assertion with hardware flags (UP / UV).
   */
  public async verifyWebAuthnAssertion(assertion: any, challenge: string, publicKey: any, options?: { expectedRpId?: string; expectedOrigin?: string }): Promise<{
    success: boolean;
    valid: boolean;
    userPresent: boolean;
    userVerified: boolean;
    signCount: number;
    errors: string[];
  }> {
    return this.request('/webauthn/verify', 'POST', { assertion, challenge, publicKey, ...options });
  }

  // ========================================================
  // v11.0.0 Multi-Chain Verifiable Attestation Bridge Client Methods
  // ========================================================

  /**
   * Constructs a standard cross-chain attestation message.
   */
  public async createCrossChainMessage(options: {
    sourceChainId: number;
    destinationChainId: number;
    sequenceNonce: number;
    stateRoot: string;
    payloadHash: string;
    senderAddress?: string;
    recipientAddress?: string;
  }): Promise<{ success: boolean; message: any }> {
    return this.request('/crosschain/message', 'POST', options);
  }

  /**
   * Signs a cross-chain message packet as an authorized relayer.
   */
  public async signCrossChainMessage(message: any, relayerKeyPair: any): Promise<{ success: boolean; signature: any }> {
    return this.request('/crosschain/sign', 'POST', { message, relayerKeyPair });
  }

  /**
   * Assembles signatures into a verifiable multi-relayer cross-chain attestation.
   */
  public async assembleCrossChainAttestation(message: any, signatures: any[], quorumThreshold?: number): Promise<{ success: boolean; attestation: any }> {
    return this.request('/crosschain/attest', 'POST', { message, signatures, quorumThreshold });
  }

  /**
   * Verifies a multi-relayer cross-chain attestation against required quorum threshold.
   */
  public async verifyCrossChainAttestation(attestation: any, authorizedRelayers?: string[]): Promise<{
    success: boolean;
    valid: boolean;
    verifiedSignatures: number;
    requiredThreshold: number;
    errors: string[];
  }> {
    return this.request('/crosschain/verify', 'POST', { attestation, authorizedRelayers });
  }

  // ========================================================
  // v11.0.0 BN254 Groth16 Zero-Knowledge SNARK Client Methods
  // ========================================================

  /**
   * Performs trusted setup simulation for a Groth16 circuit verification key.
   */
  public async setupGroth16Circuit(circuitName?: string, publicInputCount?: number): Promise<{ success: boolean; verificationKey: any }> {
    return this.request('/groth16/setup', 'POST', { circuitName, publicInputCount });
  }

  /**
   * Generates a zero-knowledge Groth16 proof for specified public and witness inputs.
   */
  public async proveGroth16(circuitName: string, publicInputs: any[], privateWitness?: any): Promise<{ success: boolean; proof: any }> {
    return this.request('/groth16/prove', 'POST', { circuitName, publicInputs, privateWitness });
  }

  /**
   * Cryptographically verifies a Groth16 ZK-SNARK proof against a verification key.
   */
  public async verifyGroth16Proof(proof: any, verificationKey: any): Promise<{ success: boolean; valid: boolean; errors: string[] }> {
    return this.request('/groth16/verify', 'POST', { proof, verificationKey });
  }

  /**
   * Aggregates multiple Groth16 proofs into a batched verification payload.
   */
  public async aggregateGroth16Proofs(proofs: any[]): Promise<{ success: boolean; aggregated: any }> {
    return this.request('/groth16/aggregate', 'POST', { proofs });
  }

  // ========================================================
  // v11.0.0 Solidity Bridge & Groth16 Contract Exporters
  // ========================================================

  /**
   * Generates production-ready DocuTrustBridgeRelayer.sol EVM smart contract.
   */
  public async generateSolidityBridgeRelayer(options?: { contractName?: string; solidityVersion?: string }): Promise<{ success: boolean; contractCode: string }> {
    return this.request('/solidity/export-bridge', 'POST', options || {});
  }

  /**
   * Generates production-ready DocuTrustGroth16Verifier.sol EVM smart contract.
   */
  public async generateSolidityGroth16Verifier(options?: { contractName?: string; solidityVersion?: string }): Promise<{ success: boolean; contractCode: string }> {
    return this.request('/solidity/export-groth16', 'POST', options || {});
  }

  // ========================================================
  // v12.0.0 Autonomous Sovereign Trust Mesh & Verifiable Compute Client Methods
  // ========================================================

  /**
   * Quantitatively evaluates credential trust score (0-1000) and optionally signs a tamper-proof Risk Receipt.
   */
  public async evaluateTrustScore(
    credential: Record<string, any>,
    evaluatorKeyPair?: any,
    options?: { minimumAcceptableScore?: number; issuerAccreditationTiers?: Record<string, number> }
  ): Promise<{ success: boolean; evaluation: any; receipt?: any }> {
    return this.request('/trustscore/evaluate', 'POST', { credential, evaluatorKeyPair, options });
  }

  /**
   * Cryptographically verifies a signed DocuTrustRiskReceipt2026.
   */
  public async verifyTrustScoreReceipt(
    receipt: any,
    evaluatorPublicKey: string
  ): Promise<{ success: boolean; valid: boolean; overallScore: number; riskTier: string; isAcceptable: boolean; errors: string[] }> {
    return this.request('/trustscore/verify', 'POST', { receipt, evaluatorPublicKey });
  }

  /**
   * Executes a deterministic credential compute program and generates a verifiable execution trace and receipt.
   */
  public async executeVerifiableCompute(
    program: any,
    inputs: Record<string, any>,
    proverKeyPair: any
  ): Promise<{ success: boolean; finalOutputs: Record<string, any>; trace: any[]; receipt: any }> {
    return this.request('/compute/execute', 'POST', { program, inputs, proverKeyPair });
  }

  /**
   * Verifies an off-chain compute execution receipt and cryptographic state trace root.
   */
  public async verifyComputeReceipt(
    receipt: any,
    proverPublicKey: string,
    inputs?: Record<string, any>
  ): Promise<{ success: boolean; valid: boolean; errors: string[] }> {
    return this.request('/compute/verify', 'POST', { receipt, proverPublicKey, inputs });
  }

  /**
   * Issues an ephemeral forward-secret token that self-expires and decays past its TTL window.
   */
  public async issueVanishToken(
    claims: Record<string, any>,
    issuerKeyPair: any,
    subjectDid: string,
    options?: { ttlSeconds?: number; epochWindowSeconds?: number }
  ): Promise<{ success: boolean; token: any; ephemeralKey: string; expiresAtEpoch: number }> {
    return this.request('/vanish/issue', 'POST', { claims, issuerKeyPair, subjectDid, options });
  }

  /**
   * Verifies and decrypts an active ephemeral vanish token.
   */
  public async verifyVanishToken(
    token: any,
    ephemeralKey: string,
    issuerPublicKey: string,
    currentEpoch?: number
  ): Promise<{ success: boolean; valid: boolean; claims?: Record<string, any>; errors?: string[]; error?: string }> {
    return this.request('/vanish/verify', 'POST', { token, ephemeralKey, issuerPublicKey, currentEpoch });
  }

  /**
   * Computes a compact O(Δ) cryptographic delta proof between registry state replicas.
   */
  public async generateStateDelta(
    baseState: Record<string, any>,
    targetState: Record<string, any>,
    relayerKeyPair: any,
    options?: { source?: string; destination?: string }
  ): Promise<{ success: boolean; deltaProof: any }> {
    return this.request('/statesync/delta', 'POST', { baseState, targetState, relayerKeyPair, options });
  }

  /**
   * Reconciles and verifies a cross-ledger delta proof against an initial base state.
   */
  public async verifyStateDelta(
    baseState: Record<string, any>,
    deltaProof: any,
    relayerPublicKey: string
  ): Promise<{ success: boolean; valid: boolean; reconciledTargetRoot?: string; deltaAppliedCount?: number; errors: string[] }> {
    return this.request('/statesync/verify', 'POST', { baseState, deltaProof, relayerPublicKey });
  }

  /**
   * Generates production-ready DocuTrustUniversalVerifier.sol EVM smart contract.
   */
  public async generateUniversalSolidityVerifier(
    options?: { contractName?: string; solidityVersion?: string }
  ): Promise<{ success: boolean; soliditySource: string }> {
    return this.request('/solidity/export-universal', 'POST', options || {});
  }

  /**
   * Aggregates multiple heterogeneous zero-knowledge proofs into a recursively folded proof (v13.0.0).
   */
  public async aggregateRecursiveZKProofs(
    subProofs: Array<any>,
    options?: { aggregatorKeyPair?: any; depth?: number; generateEvmCalldata?: boolean; customMetadata?: Record<string, any> }
  ): Promise<{ success: boolean; recursiveProof: any }> {
    return this.request('/zk/recursive/aggregate', 'POST', { subProofs, options });
  }

  /**
   * Verifies a recursively folded zero-knowledge proof (v13.0.0).
   */
  public async verifyRecursiveZKProof(
    proof: any,
    aggregatorPublicKey: string
  ): Promise<{ success: boolean; valid: boolean; recursiveProofId?: string; subProofCount?: number; depth?: number; linearizedPublicInputsCommitment?: string; errors: string[] }> {
    return this.request('/zk/recursive/verify', 'POST', { proof, aggregatorPublicKey });
  }

  /**
   * Initializes a 2D temporal-spatial multi-epoch revocation lattice (v13.0.0).
   */
  public async initializeRevocationLattice(
    latticeId: string,
    issuerDid: string,
    shardsCount?: number
  ): Promise<{ success: boolean; latticeState: any }> {
    return this.request('/revocation/lattice/init', 'POST', { latticeId, issuerDid, shardsCount });
  }

  /**
   * Accumulates revoked credentials into the active lattice slice and optionally advances epoch (v13.0.0).
   */
  public async accumulateRevocationLattice(
    state: any,
    revokedCredentialIds: string[],
    advanceEpoch?: boolean
  ): Promise<{ success: boolean; latticeState: any }> {
    return this.request('/revocation/lattice/accumulate', 'POST', { state, revokedCredentialIds, advanceEpoch });
  }

  /**
   * Generates an O(1) non-revocation or revocation witness proof for a credential (v13.0.0).
   */
  public async generateRevocationLatticeProof(
    state: any,
    credentialId: string,
    issuerKeyPair: any,
    targetEpoch?: number
  ): Promise<{ success: boolean; proof: any }> {
    return this.request('/revocation/lattice/prove', 'POST', { state, credentialId, issuerKeyPair, targetEpoch });
  }

  /**
   * Verifies a cryptographic revocation lattice proof (v13.0.0).
   */
  public async verifyRevocationLatticeProof(
    proof: any,
    issuerPublicKey: string,
    expectedLatticeRoot?: string
  ): Promise<{ success: boolean; valid: boolean; isRevoked?: boolean; targetEpoch?: number; latticeRoot?: string; errors: string[] }> {
    return this.request('/revocation/lattice/verify', 'POST', { proof, issuerPublicKey, expectedLatticeRoot });
  }

  /**
   * Issues an autonomous AI Agent Action Attestation with model card fingerprinting and trace commitment (v13.0.0).
   */
  public async issueAgentAttestation(
    payload: {
      modelCard: any;
      promptText?: string;
      contextSnapshot?: Record<string, any> | string;
      executionTrace?: Array<any>;
      outputArtifact: Record<string, any> | string;
      guardrailPolicyId?: string;
      guardrailPassed?: boolean;
    },
    agentKeyPair: any
  ): Promise<{ success: boolean; attestation: any }> {
    return this.request('/agent/attest', 'POST', { payload, agentKeyPair });
  }

  /**
   * Verifies an autonomous AI Agent Action Attestation and guardrail compliance (v13.0.0).
   */
  public async verifyAgentAttestation(
    attestation: any,
    agentPublicKey: string,
    expectedOutput?: Record<string, any> | string
  ): Promise<{ success: boolean; valid: boolean; attestationId?: string; agentDid?: string; modelFingerprint?: string; stepCount?: number; guardrailPassed?: boolean; outputCommitment?: string; errors: string[] }> {
    return this.request('/agent/verify', 'POST', { attestation, agentPublicKey, expectedOutput });
  }

  // ==========================================
  // Version 14.0.0 Methods
  // ==========================================

  /**
   * Evaluates a deterministic Verifiable Random Function (VRF) with proof (v14.0.0).
   */
  public async evaluateVRF(
    inputSeed: string,
    keyPair: { publicKeyHex: string; privateKeyHex?: string; secretKeyHex?: string }
  ): Promise<{ success: boolean; evaluation: any }> {
    return this.request('/vrf/evaluate', 'POST', { inputSeed, keyPair });
  }

  /**
   * Cryptographically verifies a VRF evaluation and deterministic output (v14.0.0).
   */
  public async verifyVRF(
    evaluation: any
  ): Promise<{ success: boolean; valid: boolean; vrfOutputHex?: string; errors: string[] }> {
    return this.request('/vrf/verify', 'POST', { evaluation });
  }

  /**
   * Creates a multi-oracle threshold randomness beacon round (v14.0.0).
   */
  public async createVRFBeacon(options: {
    epoch: number;
    round: number;
    previousBeaconHash: string;
    oracleKeyPairs: Array<any>;
    thresholdRequired?: number;
  }): Promise<{ success: boolean; beacon: any }> {
    return this.request('/vrf/beacon/create', 'POST', options);
  }

  /**
   * Verifies a multi-oracle threshold randomness beacon (v14.0.0).
   */
  public async verifyVRFBeacon(
    beacon: any,
    expectedBeaconHash?: string
  ): Promise<{ success: boolean; valid: boolean; epoch?: number; round?: number; quorumReached?: boolean; validEvaluationsCount?: number; errors: string[] }> {
    return this.request('/vrf/beacon/verify', 'POST', { beacon, expectedBeaconHash });
  }

  /**
   * Issues a signed multi-oracle threshold data feed (v14.0.0).
   */
  public async createOracleFeed(options: {
    feedId: string;
    round: number;
    dataPayload: any;
    oracleKeyPairs: Array<any>;
    thresholdRequired?: number;
  }): Promise<{ success: boolean; feed: any }> {
    return this.request('/oracle/feed/create', 'POST', options);
  }

  /**
   * Verifies a multi-oracle threshold consensus data feed (v14.0.0).
   */
  public async verifyOracleFeed(
    feed: any,
    trustedOraclePublicKeys?: Array<string> | Record<string, string>
  ): Promise<{ success: boolean; valid: boolean; quorumReached?: boolean; validSignaturesCount?: number; errors: string[] }> {
    return this.request('/oracle/feed/verify', 'POST', { feed, trustedOraclePublicKeys });
  }

  /**
   * Compiles a declarative predicate expression into an AST & constraint system (v14.0.0).
   */
  public async compileZKDSL(
    expression: string
  ): Promise<{ success: boolean; ast: any; astJson?: string }> {
    return this.request('/zk/dsl/compile', 'POST', { expression });
  }

  /**
   * Synthesizes a non-interactive zero-knowledge proof for a predicate DSL (v14.0.0).
   */
  public async proveZKDSL(
    expression: string,
    attributes: Record<string, any>
  ): Promise<{ success: boolean; proof: any }> {
    return this.request('/zk/dsl/prove', 'POST', { expression, attributes });
  }

  /**
   * Verifies a Zero-Knowledge predicate DSL proof (v14.0.0).
   */
  public async verifyZKDSL(
    proof: any,
    expression?: string
  ): Promise<{ success: boolean; valid: boolean; expression?: string; errors: string[] }> {
    return this.request('/zk/dsl/verify', 'POST', { proof, expression });
  }

  /**
   * Computes a weights Merkle root and creates an AI-BOM cryptographic receipt (v14.0.0).
   */
  public async createAIBOMReceipt(
    manifest: any,
    certifierKeyPair: any
  ): Promise<{ success: boolean; receipt: any }> {
    return this.request('/aibom/manifest', 'POST', { manifest, certifierKeyPair });
  }

  /**
   * Verifies an AI Bill of Materials (AI-BOM) receipt and weights root (v14.0.0).
   */
  public async verifyAIBOMReceipt(
    receipt: any,
    certifierPublicKey: string,
    expectedWeightsRoot?: string
  ): Promise<{ success: boolean; valid: boolean; weightsRootMatches?: boolean; errors: string[] }> {
    return this.request('/aibom/verify', 'POST', { receipt, certifierPublicKey, expectedWeightsRoot });
  }

  /**
   * Generates a Merkle inclusion proof for a single neural network layer (v14.0.0).
   */
  public async generateAIBOMLayerProof(
    manifest: any,
    layerIndex: number
  ): Promise<{ success: boolean; layer: any; proof: string[]; root: string }> {
    return this.request('/aibom/layer-proof', 'POST', { manifest, layerIndex });
  }

  /**
   * Verifies a single layer Merkle inclusion proof against a weights root (v14.0.0).
   */
  public async verifyAIBOMLayerProof(
    proof: { layer: any; proof: string[]; root?: string },
    expectedRoot: string
  ): Promise<{ success: boolean; valid: boolean; layerName?: string; layerIndex?: number; errors: string[] }> {
    return this.request('/aibom/verify-layer-proof', 'POST', { proof, expectedRoot });
  }

  /**
   * Generates a Falcon-512 / Falcon-1024 dual-lattice key pair (v14.0.0).
   */
  public async generateFalconKeyPair(
    options: { mode?: 'Falcon-512' | 'Falcon-1024' } = {}
  ): Promise<{ success: boolean; keyPair: any }> {
    return this.request('/pqc/falcon/keygen', 'POST', options);
  }

  /**
   * Signs a payload using post-quantum Falcon lattice signature (v14.0.0).
   */
  public async signFalcon(
    message: any,
    privateKeyHex: string,
    options: { mode?: 'Falcon-512' | 'Falcon-1024' } = {}
  ): Promise<{ success: boolean; signatureHex: string; mode: string; digestHex: string }> {
    return this.request('/pqc/falcon/sign', 'POST', { message, privateKeyHex, mode: options.mode });
  }

  /**
   * Verifies a post-quantum Falcon lattice signature (v14.0.0).
   */
  public async verifyFalcon(
    message: any,
    signatureHex: string,
    publicKeyHex: string
  ): Promise<{ success: boolean; valid: boolean; mode?: string; digestHex?: string; errors: string[] }> {
    return this.request('/pqc/falcon/verify', 'POST', { message, signatureHex, publicKeyHex });
  }

  // ========================================================
  // v15.0.0 Post-Quantum Double Ratchet Client Methods
  // ========================================================

  public async generateRatchetKeyPair(): Promise<{ success: boolean; keyPair: any }> {
    return this.request('/ratchet/keygen', 'POST', {});
  }

  public async initInitiatorRatchetSession(
    bobCombinedPublicKey: string
  ): Promise<{ success: boolean; session: any; initialMessageHeader: any }> {
    return this.request('/ratchet/init/initiator', 'POST', { bobCombinedPublicKey });
  }

  public async initResponderRatchetSession(
    bobKeyData: any
  ): Promise<{ success: boolean; session: any }> {
    return this.request('/ratchet/init/responder', 'POST', { bobKeyData });
  }

  public async encryptRatchet(
    session: any,
    payload: any
  ): Promise<{ success: boolean; message: any; updatedSession: any }> {
    return this.request('/ratchet/encrypt', 'POST', { session, payload });
  }

  public async decryptRatchet(
    session: any,
    message: any
  ): Promise<{ success: boolean; plaintext: string; parsed: any; updatedSession: any }> {
    return this.request('/ratchet/decrypt', 'POST', { session, message });
  }

  // ========================================================
  // v15.0.0 Polynomial Commitments Client Methods
  // ========================================================

  public async generatePolySRS(
    maxDegree: number = 16
  ): Promise<{ success: boolean; srs: any }> {
    return this.request('/zk/poly/srs', 'POST', { maxDegree });
  }

  public async commitPolynomial(
    coefficients: number[] | string[],
    srs: any
  ): Promise<{ success: boolean; commitment: any }> {
    return this.request('/zk/poly/commit', 'POST', { coefficients, srs });
  }

  public async evaluatePolynomial(
    coefficients: number[] | string[],
    pointZ: number | string
  ): Promise<{ success: boolean; pointZ: string; valueY: string; formatted: string }> {
    return this.request('/zk/poly/evaluate', 'POST', { coefficients, pointZ });
  }

  public async createPolyEvaluationProof(
    coefficients: number[] | string[],
    pointZ: number | string,
    srs: any
  ): Promise<{ success: boolean; proof: any }> {
    return this.request('/zk/poly/prove', 'POST', { coefficients, pointZ, srs });
  }

  public async verifyPolyEvaluationProof(
    commitment: any,
    proof: any,
    srs: any
  ): Promise<{ success: boolean; valid: boolean; evaluationPointZ: string; evaluationValueY: string; errors: string[] }> {
    return this.request('/zk/poly/verify', 'POST', { commitment, proof, srs });
  }

  public async createPolyMultiProof(
    polynomials: Array<number[] | string[]>,
    pointZ: number | string,
    srs: any
  ): Promise<{ success: boolean; multiProof: any }> {
    return this.request('/zk/poly/multi-prove', 'POST', { polynomials, pointZ, srs });
  }

  public async aggregatePolyProofs(
    commitments: any[],
    proofs: any[],
    srs: any
  ): Promise<{ success: boolean; batchProof: any }> {
    return this.request('/zk/poly/aggregate', 'POST', { commitments, proofs, srs });
  }

  // ========================================================
  // v15.0.0 Hardware TEE Remote Attestation Client Methods
  // ========================================================

  public async generateTEEAttestationQuote(
    platform: string,
    measurements: any,
    payload: any
  ): Promise<{ success: boolean; quote: any }> {
    return this.request('/tee/quote/generate', 'POST', { platform, measurements, payload });
  }

  public async verifyTEEAttestationQuote(
    quote: any,
    options: any = {}
  ): Promise<{ success: boolean; valid: boolean; platform?: string; mrEnclave?: string; mrSigner?: string; errors: string[] }> {
    return this.request('/tee/quote/verify', 'POST', { quote, options });
  }

  public async issueTEEBoundCredential(
    claims: any,
    enclaveKeyPair: any,
    quote: any,
    issuerPrivateKeyHex: string
  ): Promise<{ success: boolean; credential: any }> {
    return this.request('/tee/vc/issue', 'POST', { claims, enclaveKeyPair, quote, issuerPrivateKeyHex });
  }

  public async verifyTEEBoundCredential(
    credential: any,
    options: any = {}
  ): Promise<{ success: boolean; valid: boolean; quoteValid?: boolean; signatureValid?: boolean; mrEnclave?: string; mrSigner?: string; errors: string[] }> {
    return this.request('/tee/vc/verify', 'POST', { credential, options });
  }

  // ========================================================
  // v15.0.0 IBC Relayer Client Methods
  // ========================================================

  public async computeIBCPacketCommitment(
    packet: any
  ): Promise<{ success: boolean; commitment: any }> {
    return this.request('/ibc/packet/commit', 'POST', { packet });
  }

  public async generateIBCMerkleProof(
    key: string,
    valueHex: string,
    options: any = {}
  ): Promise<{ success: boolean; proof: any }> {
    return this.request('/ibc/proof/generate', 'POST', { key, valueHex, ...options });
  }

  public async verifyIBCMerkleProof(
    proof: any,
    expectedRootAppHash?: string
  ): Promise<{ success: boolean; valid: boolean; rootAppHash: string; key: string; errors: string[] }> {
    return this.request('/ibc/proof/verify', 'POST', { proof, expectedRootAppHash });
  }

  public async createIBCLightClient(
    chainId: string,
    genesisHeader: any,
    trustPeriodSeconds: number = 1209600
  ): Promise<{ success: boolean; clientState: any }> {
    return this.request('/ibc/client/create', 'POST', { chainId, genesisHeader, trustPeriodSeconds });
  }

  public async updateIBCLightClient(
    clientState: any,
    newHeader: any
  ): Promise<{ success: boolean; clientState: any }> {
    return this.request('/ibc/client/update', 'POST', { clientState, newHeader });
  }

  public async relayIBCPacket(
    packet: any,
    commitmentProof: any,
    clientState: any
  ): Promise<{ success: boolean; acknowledgement: any; receiptProof: any; updatedClientState: any }> {
    return this.request('/ibc/packet/relay', 'POST', { packet, commitmentProof, clientState });
  }

  // ========================================================
  // v16.0.0 Fully Homomorphic Encryption (FHE) Client Methods
  // ========================================================

  public async generateFHEKeyPair(
    dimension: number = 8,
    modulus: number = 2147483647
  ): Promise<{ success: boolean; keypair: any }> {
    return this.request('/fhe/keypair', 'POST', { dimension, modulus });
  }

  public async encryptFHEValue(
    value: number,
    publicKey: any,
    tag: string = 'scalar'
  ): Promise<{ success: boolean; ciphertext: any }> {
    return this.request('/fhe/encrypt', 'POST', { value, publicKey, tag });
  }

  public async decryptFHEValue(
    ciphertext: any,
    privateKey: any
  ): Promise<{ success: boolean; value: number }> {
    return this.request('/fhe/decrypt', 'POST', { ciphertext, privateKey });
  }

  public async addFHECiphertexts(
    c1: any,
    c2: any
  ): Promise<{ success: boolean; sumCiphertext: any }> {
    return this.request('/fhe/add', 'POST', { c1, c2 });
  }

  public async multiplyFHECiphertexts(
    c1: any,
    c2: any
  ): Promise<{ success: boolean; productCiphertext: any }> {
    return this.request('/fhe/multiply', 'POST', { c1, c2 });
  }

  public async queryFHEDatabase(
    encryptedRecords: any[],
    predicate: any
  ): Promise<{ success: boolean; queryResult: any }> {
    return this.request('/fhe/query-db', 'POST', { encryptedRecords, predicate });
  }

  public async createFHEQueryReceipt(
    queryId: string,
    encryptedResult: any,
    serverDid: string,
    serverPrivateKeyHex: string
  ): Promise<{ success: boolean; receipt: any }> {
    return this.request('/fhe/receipt/create', 'POST', { queryId, encryptedResult, serverDid, serverPrivateKeyHex });
  }

  public async verifyFHEQueryReceipt(
    receipt: any,
    serverPublicKeyHex?: string
  ): Promise<{ success: boolean; result: any }> {
    return this.request('/fhe/receipt/verify', 'POST', { receipt, serverPublicKeyHex });
  }

  // ========================================================
  // v16.0.0 FROST Threshold Signature Client Methods
  // ========================================================

  public async generateFROSTDKG(
    threshold: number = 2,
    totalParticipants: number = 3
  ): Promise<{ success: boolean; dkg: any }> {
    return this.request('/frost/dkg', 'POST', { threshold, totalParticipants });
  }

  public async generateFROSTRound1Commitment(
    signerId: number
  ): Promise<{ success: boolean; nonces: any }> {
    return this.request('/frost/round1', 'POST', { signerId });
  }

  public async generateFROSTRound2Share(
    signerId: number,
    keyPackage: any,
    round1Commitments: any[],
    message: string
  ): Promise<{ success: boolean; signatureShare: any }> {
    return this.request('/frost/round2', 'POST', { signerId, keyPackage, round1Commitments, message });
  }

  public async aggregateFROSTSignatures(
    message: string,
    commitments: any[],
    shares: any[],
    groupPublicKey: string
  ): Promise<{ success: boolean; signature: any }> {
    return this.request('/frost/aggregate', 'POST', { message, commitments, shares, groupPublicKey });
  }

  public async verifyFROSTThresholdSignature(
    message: string,
    signature: any,
    groupPublicKey: string
  ): Promise<{ success: boolean; result: any }> {
    return this.request('/frost/verify', 'POST', { message, signature, groupPublicKey });
  }

  public async issueFROSTThresholdCredential(
    credentialSubject: any,
    groupPublicKey: string,
    thresholdSignature: any,
    issuerDid: string,
    options: any = {}
  ): Promise<{ success: boolean; credential: any }> {
    return this.request('/frost/credential/issue', 'POST', { credentialSubject, groupPublicKey, thresholdSignature, issuerDid, options });
  }

  public async verifyFROSTThresholdCredential(
    credential: any,
    expectedGroupPublicKey?: string
  ): Promise<{ success: boolean; result: any }> {
    return this.request('/frost/credential/verify', 'POST', { credential, expectedGroupPublicKey });
  }

  // ========================================================
  // v16.0.0 ZK-PlonK Client Methods
  // ========================================================

  public async compilePlonKCircuit(
    circuitId: string,
    gates: any[],
    publicInputKeys: string[] = [],
    lookupTables: Record<string, number[]> = {}
  ): Promise<{ success: boolean; compiled: any }> {
    return this.request('/zk/plonk/compile', 'POST', { circuitId, gates, publicInputKeys, lookupTables });
  }

  public async generatePlonKProof(
    circuit: any,
    witness: Record<string, number>,
    publicInputs: Record<string, number> = {}
  ): Promise<{ success: boolean; proof: any }> {
    return this.request('/zk/plonk/prove', 'POST', { circuit, witness, publicInputs });
  }

  public async verifyPlonKProof(
    proof: any,
    verificationKey: any,
    publicInputs?: Record<string, number>
  ): Promise<{ success: boolean; result: any }> {
    return this.request('/zk/plonk/verify', 'POST', { proof, verificationKey, publicInputs });
  }

  // ========================================================
  // v16.0.0 Agentic Capability & Delegation Client Methods
  // ========================================================

  public async issueRootCapability(
    issuerDid: string,
    audienceDid: string,
    capabilities: any[],
    caveats: any[] = [],
    expiresInSeconds: number = 3600,
    issuerPrivateKeyHex: string
  ): Promise<{ success: boolean; token: any }> {
    return this.request('/capability/root/issue', 'POST', { issuerDid, audienceDid, capabilities, caveats, expiresInSeconds, issuerPrivateKeyHex });
  }

  public async attenuateCapability(
    parentToken: any,
    delegatorDid: string,
    audienceDid: string,
    capabilities: any[],
    caveats: any[] = [],
    expiresInSeconds: number = 1800,
    delegatorPrivateKeyHex: string
  ): Promise<{ success: boolean; token: any }> {
    return this.request('/capability/attenuate', 'POST', { parentToken, delegatorDid, audienceDid, capabilities, caveats, expiresInSeconds, delegatorPrivateKeyHex });
  }

  public async verifyDelegationChain(
    chain: any[],
    requiredAction: string,
    requiredResource: string,
    context: any = {}
  ): Promise<{ success: boolean; result: any }> {
    return this.request('/capability/chain/verify', 'POST', { chain, requiredAction, requiredResource, context });
  }

  public async createAgentExecutionReceipt(
    agentDid: string,
    capabilityExercised: any,
    delegationChain: any[],
    executionPayload: any,
    agentPrivateKeyHex: string
  ): Promise<{ success: boolean; receipt: any }> {
    return this.request('/capability/receipt/create', 'POST', { agentDid, capabilityExercised, delegationChain, executionPayload, agentPrivateKeyHex });
  }

  public async verifyAgentExecutionReceipt(
    receipt: any,
    agentPublicKeyHex?: string
  ): Promise<{ success: boolean; result: any }> {
    return this.request('/capability/receipt/verify', 'POST', { receipt, agentPublicKeyHex });
  }
}







