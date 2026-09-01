/**
 * @file packages/core/src/agent-federation/index.ts
 * @description Decentralized AI Agent Identity & Epistemic Trust Federation Engine (DocuTrust v21.0.0)
 * Enables cross-domain sovereign agent identity delegation, hierarchical capability bounding,
 * multi-hop transitive trust attestation paths, epistemic credibility scoring, and mutual ZK handshakes.
 */

import * as crypto from 'crypto';
import { canonicalizeJson, encodeBase58, decodeBase58, sha256Hex, signData, verifySignature, generateKeyPair } from '../crypto/index.js';

export interface AgentIdentity {
  did: string;
  publicKeyHex: string;
  authorityType: 'root_authority' | 'delegated_agent' | 'autonomous_worker';
  allowedCapabilities: string[];
  maxDelegationDepth: number;
  epistemicBaseScore: number; // 0 to 100
  createdAt: string;
}

export interface FederatedDelegationToken {
  tokenId: string;
  tokenType: 'DocuTrustFederatedDelegationToken2026';
  issuerDid: string;
  subjectDid: string;
  grantedCapabilities: string[];
  currentDepth: number;
  maxDepth: number;
  epistemicWeight: number; // 0.0 to 1.0 multiplier
  validUntil: string;
  issuedAt: string;
  nonce: string;
  signature: string;
}

export interface TransitiveTrustPathVerification {
  isValid: boolean;
  rootAuthorityDid: string;
  leafAgentDid: string;
  pathLength: number;
  effectiveCapabilities: string[];
  cumulativeEpistemicScore: number;
  attenuationHistory: Array<{ depth: number; issuer: string; subject: string; capabilities: string[] }>;
  error?: string;
}

export interface AgentHandshakeInit {
  sessionId: string;
  initiatorDid: string;
  responderDid: string;
  ephemeralPublicKeyHex: string;
  challengeNonce: string;
  timestamp: number;
  initiatorSignature: string;
}

export interface AgentHandshakeResponse {
  sessionId: string;
  responderDid: string;
  ephemeralPublicKeyHex: string;
  challengeResponseHash: string;
  responderSignature: string;
  timestamp: number;
}

export interface EstablishedHandshakeSession {
  sessionId: string;
  initiatorDid: string;
  responderDid: string;
  sharedSecretHex: string;
  sessionKeyHex: string;
  authenticatedAt: string;
  status: 'ESTABLISHED' | 'FAILED';
}

export class AgentFederationEngine {
  /**
   * Generates a new sovereign agent identity descriptor.
   */
  public static createAgentIdentity(options: {
    authorityType?: 'root_authority' | 'delegated_agent' | 'autonomous_worker';
    capabilities?: string[];
    maxDelegationDepth?: number;
    epistemicBaseScore?: number;
  } = {}): { identity: AgentIdentity; keyPair: any } {
    const keyPair = generateKeyPair();
    const identity: AgentIdentity = {
      did: keyPair.did,
      publicKeyHex: keyPair.publicKeyHex,
      authorityType: options.authorityType || 'delegated_agent',
      allowedCapabilities: options.capabilities || ['inference:execute', 'knowledge:query'],
      maxDelegationDepth: options.maxDelegationDepth !== undefined ? options.maxDelegationDepth : 3,
      epistemicBaseScore: options.epistemicBaseScore !== undefined ? options.epistemicBaseScore : 85,
      createdAt: new Date().toISOString()
    };

    return { identity, keyPair };
  }

  /**
   * Issues a signed cryptographic delegation token from an issuer agent to a subject agent.
   */
  public static issueDelegationToken(
    issuerKeyPair: { did: string; privateKeyPem?: string; privateKeyHex?: string; publicKeyHex?: string },
    subjectDid: string,
    capabilities: string[],
    options: {
      parentToken?: FederatedDelegationToken;
      maxDepth?: number;
      epistemicWeight?: number;
      validityDurationSeconds?: number;
    } = {}
  ): FederatedDelegationToken {
    let currentDepth = 1;
    let maxAllowedDepth = options.maxDepth || 3;

    if (options.parentToken) {
      currentDepth = options.parentToken.currentDepth + 1;
      maxAllowedDepth = options.parentToken.maxDepth;

      if (currentDepth > maxAllowedDepth) {
        throw new Error(`Delegation depth limit exceeded: ${currentDepth} > ${maxAllowedDepth}`);
      }

      // Capability attenuation check: granted capabilities must be subset of parent
      const parentCaps = new Set(options.parentToken.grantedCapabilities);
      for (const cap of capabilities) {
        if (!parentCaps.has(cap) && !parentCaps.has('*')) {
          throw new Error(`Capability '${cap}' exceeds parent delegation scope.`);
        }
      }
    }

    const validityDuration = options.validityDurationSeconds || 86400 * 7; // 7 days
    const issuedAt = new Date().toISOString();
    const validUntil = new Date(Date.now() + validityDuration * 1000).toISOString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const tokenId = `del_tok_${sha256Hex(issuerKeyPair.did + ':' + subjectDid + ':' + nonce).substring(0, 16)}`;

    const tokenPayload = {
      tokenId,
      tokenType: 'DocuTrustFederatedDelegationToken2026' as const,
      issuerDid: issuerKeyPair.did,
      subjectDid,
      grantedCapabilities: capabilities,
      currentDepth,
      maxDepth: maxAllowedDepth,
      epistemicWeight: options.epistemicWeight !== undefined ? options.epistemicWeight : 0.95,
      validUntil,
      issuedAt,
      nonce
    };

    const canonical = canonicalizeJson(tokenPayload);
    const signature = signData(canonical, (issuerKeyPair.privateKeyPem || issuerKeyPair.privateKeyHex)!);

    return {
      ...tokenPayload,
      signature
    };
  }

  /**
   * Verifies a single delegation token's signature and expiration.
   */
  public static verifyDelegationToken(
    token: FederatedDelegationToken,
    issuerPublicKey: string
  ): boolean {
    if (!token || !token.signature) return false;

    if (new Date(token.validUntil).getTime() < Date.now()) {
      return false;
    }

    const { signature, ...unsignedPayload } = token;
    const canonical = canonicalizeJson(unsignedPayload);
    return verifySignature(canonical, signature, issuerPublicKey);
  }

  /**
   * Verifies a multi-hop transitive trust delegation chain from a root authority to the executing agent.
   */
  public static verifyTransitiveTrustChain(
    chain: FederatedDelegationToken[],
    rootAuthority: { did: string; publicKeyHex: string; baseEpistemicScore?: number },
    targetCapability?: string
  ): TransitiveTrustPathVerification {
    if (!chain || chain.length === 0) {
      return {
        isValid: false,
        rootAuthorityDid: rootAuthority.did,
        leafAgentDid: '',
        pathLength: 0,
        effectiveCapabilities: [],
        cumulativeEpistemicScore: 0,
        attenuationHistory: [],
        error: 'Empty delegation chain provided'
      };
    }

    const attenuationHistory: Array<{ depth: number; issuer: string; subject: string; capabilities: string[] }> = [];
    let currentIssuerDid = rootAuthority.did;
    let currentPublicKeyHex = rootAuthority.publicKeyHex;
    let allowedCaps = new Set<string>();
    let cumulativeScore = rootAuthority.baseEpistemicScore || 100.0;

    for (let i = 0; i < chain.length; i++) {
      const link = chain[i];

      // 1. Verify Issuer linkage
      if (link.issuerDid !== currentIssuerDid) {
        return {
          isValid: false,
          rootAuthorityDid: rootAuthority.did,
          leafAgentDid: chain[chain.length - 1].subjectDid,
          pathLength: chain.length,
          effectiveCapabilities: Array.from(allowedCaps),
          cumulativeEpistemicScore: 0,
          attenuationHistory,
          error: `Chain broken at step ${i + 1}: expected issuer ${currentIssuerDid}, got ${link.issuerDid}`
        };
      }

      // 2. Verify signature of the link
      const isValidSig = this.verifyDelegationToken(link, currentPublicKeyHex);
      if (!isValidSig) {
        return {
          isValid: false,
          rootAuthorityDid: rootAuthority.did,
          leafAgentDid: chain[chain.length - 1].subjectDid,
          pathLength: chain.length,
          effectiveCapabilities: Array.from(allowedCaps),
          cumulativeEpistemicScore: 0,
          attenuationHistory,
          error: `Cryptographic signature verification failed at step ${i + 1} for issuer ${link.issuerDid}`
        };
      }

      // 3. Verify monotonic depth
      if (link.currentDepth !== i + 1 || link.currentDepth > link.maxDepth) {
        return {
          isValid: false,
          rootAuthorityDid: rootAuthority.did,
          leafAgentDid: chain[chain.length - 1].subjectDid,
          pathLength: chain.length,
          effectiveCapabilities: Array.from(allowedCaps),
          cumulativeEpistemicScore: 0,
          attenuationHistory,
          error: `Depth violation at step ${i + 1}: currentDepth=${link.currentDepth}, maxDepth=${link.maxDepth}`
        };
      }

      // 4. Update capability intersection
      if (i === 0) {
        allowedCaps = new Set(link.grantedCapabilities);
      } else {
        const nextCaps = new Set<string>();
        for (const cap of link.grantedCapabilities) {
          if (allowedCaps.has(cap) || allowedCaps.has('*')) {
            nextCaps.add(cap);
          }
        }
        allowedCaps = nextCaps;
      }

      // 5. Attenuate epistemic credibility score
      cumulativeScore = cumulativeScore * (link.epistemicWeight || 0.95);

      attenuationHistory.push({
        depth: link.currentDepth,
        issuer: link.issuerDid,
        subject: link.subjectDid,
        capabilities: Array.from(allowedCaps)
      });

      // Prepare for next link: subject becomes next issuer (for did:key, extract public key)
      currentIssuerDid = link.subjectDid;
      try {
        if (link.subjectDid.startsWith('did:key:z')) {
          const multibase = link.subjectDid.replace('did:key:z', '').split('#')[0];
          const decoded = decodeBase58(multibase);
          const rawPub = decoded.subarray(2);
          currentPublicKeyHex = rawPub.toString('hex');
        }
      } catch (e) {
        // Leave previous or fallback
      }
    }

    const effectiveCapabilities = Array.from(allowedCaps);

    if (targetCapability && !allowedCaps.has(targetCapability) && !allowedCaps.has('*')) {
      return {
        isValid: false,
        rootAuthorityDid: rootAuthority.did,
        leafAgentDid: chain[chain.length - 1].subjectDid,
        pathLength: chain.length,
        effectiveCapabilities,
        cumulativeEpistemicScore: Math.round(cumulativeScore * 100) / 100,
        attenuationHistory,
        error: `Required capability '${targetCapability}' not held by leaf agent.`
      };
    }

    return {
      isValid: true,
      rootAuthorityDid: rootAuthority.did,
      leafAgentDid: chain[chain.length - 1].subjectDid,
      pathLength: chain.length,
      effectiveCapabilities,
      cumulativeEpistemicScore: Math.round(cumulativeScore * 100) / 100,
      attenuationHistory
    };
  }

  /**
   * Initiates a mutual Zero-Knowledge Agent Handshake session.
   */
  public static initiateHandshake(
    initiatorKeyPair: { did: string; privateKeyPem?: string; privateKeyHex?: string },
    responderDid: string
  ): { handshakeInit: AgentHandshakeInit; ephemeralSecret: string } {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const ephemeralPublicKeyHex = ecdh.getPublicKey('hex');
    const ephemeralSecret = ecdh.getPrivateKey('hex');

    const sessionId = `ses_${crypto.randomBytes(12).toString('hex')}`;
    const challengeNonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    const payload = {
      sessionId,
      initiatorDid: initiatorKeyPair.did,
      responderDid,
      ephemeralPublicKeyHex,
      challengeNonce,
      timestamp
    };

    const canonical = canonicalizeJson(payload);
    const initiatorSignature = signData(canonical, (initiatorKeyPair.privateKeyPem || initiatorKeyPair.privateKeyHex)!);

    return {
      handshakeInit: {
        ...payload,
        initiatorSignature
      },
      ephemeralSecret
    };
  }

  /**
   * Responds to an agent handshake initialization.
   */
  public static respondHandshake(
    responderKeyPair: { did: string; privateKeyPem?: string; privateKeyHex?: string },
    handshakeInit: AgentHandshakeInit,
    initiatorPublicKeyHex: string
  ): { handshakeResponse: AgentHandshakeResponse; session: EstablishedHandshakeSession } {
    // 1. Verify initiator signature
    const { initiatorSignature, ...initPayload } = handshakeInit;
    const valid = verifySignature(canonicalizeJson(initPayload), initiatorSignature, initiatorPublicKeyHex);
    if (!valid) {
      throw new Error('Handshake initialization signature invalid.');
    }

    // 2. Generate responder ephemeral key and compute ECDH shared secret
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const responderEphemeralPub = ecdh.getPublicKey('hex');

    const sharedSecret = ecdh.computeSecret(Buffer.from(handshakeInit.ephemeralPublicKeyHex, 'hex'));
    const sharedSecretHex = sharedSecret.toString('hex');

    // 3. Derive HKDF session key
    const sessionKey = crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(handshakeInit.sessionId, 'utf-8'),
      Buffer.from('DocuTrustAgentHandshake2026', 'utf-8'),
      32
    );
    const sessionKeyHex = Buffer.from(sessionKey).toString('hex');

    // 4. Compute challenge response hash
    const challengeResponseHash = sha256Hex(handshakeInit.challengeNonce + ':' + sharedSecretHex);
    const timestamp = Date.now();

    const responsePayload = {
      sessionId: handshakeInit.sessionId,
      responderDid: responderKeyPair.did,
      ephemeralPublicKeyHex: responderEphemeralPub,
      challengeResponseHash,
      timestamp
    };

    const canonicalResponse = canonicalizeJson(responsePayload);
    const responderSignature = signData(canonicalResponse, (responderKeyPair.privateKeyPem || responderKeyPair.privateKeyHex)!);

    const handshakeResponse: AgentHandshakeResponse = {
      ...responsePayload,
      responderSignature
    };

    const session: EstablishedHandshakeSession = {
      sessionId: handshakeInit.sessionId,
      initiatorDid: handshakeInit.initiatorDid,
      responderDid: responderKeyPair.did,
      sharedSecretHex,
      sessionKeyHex,
      authenticatedAt: new Date().toISOString(),
      status: 'ESTABLISHED'
    };

    return { handshakeResponse, session };
  }

  /**
   * Finalizes the handshake on the initiator side and verifies the responder's proof.
   */
  public static completeHandshake(
    initiatorEphemeralSecretHex: string,
    handshakeInit: AgentHandshakeInit,
    handshakeResponse: AgentHandshakeResponse,
    responderPublicKeyHex: string
  ): EstablishedHandshakeSession {
    // 1. Verify responder signature
    const { responderSignature, ...respPayload } = handshakeResponse;
    const valid = verifySignature(canonicalizeJson(respPayload), responderSignature, responderPublicKeyHex);
    if (!valid) {
      throw new Error('Handshake response signature invalid.');
    }

    // 2. Compute ECDH shared secret using initiator ephemeral private key
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(initiatorEphemeralSecretHex, 'hex'));
    const sharedSecret = ecdh.computeSecret(Buffer.from(handshakeResponse.ephemeralPublicKeyHex, 'hex'));
    const sharedSecretHex = sharedSecret.toString('hex');

    // 3. Verify challenge response hash
    const expectedChallengeHash = sha256Hex(handshakeInit.challengeNonce + ':' + sharedSecretHex);
    if (expectedChallengeHash !== handshakeResponse.challengeResponseHash) {
      throw new Error('Handshake challenge response verification failed.');
    }

    // 4. Derive symmetric session key
    const sessionKey = crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(handshakeInit.sessionId, 'utf-8'),
      Buffer.from('DocuTrustAgentHandshake2026', 'utf-8'),
      32
    );
    const sessionKeyHex = Buffer.from(sessionKey).toString('hex');

    return {
      sessionId: handshakeInit.sessionId,
      initiatorDid: handshakeInit.initiatorDid,
      responderDid: handshakeResponse.responderDid,
      sharedSecretHex,
      sessionKeyHex,
      authenticatedAt: new Date().toISOString(),
      status: 'ESTABLISHED'
    };
  }
}
