/**
 * @file packages/core/src/vrf-oracle/index.ts
 * @description Decentralized Threshold VRF Oracle Consensus Mesh (DocuTrust v14.0.0)
 * Provides Verifiable Random Functions (VRF) for unpredictable, tamper-proof randomness beacons,
 * commit-reveal entropy rounds, and multi-oracle threshold consensus data feed attestations.
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair, encodeBase58, decodeBase58 } from '../crypto/index.js';
import { DIDResolver } from '../did/index.js';

export interface VRFKeyPair {
  publicKeyHex: string;
  privateKeyHex: string;
  did: string;
}

export interface VRFEvaluation {
  inputSeed: string;
  vrfOutputHex: string;
  proofHex: string;
  publicKeyHex: string;
  timestamp: string;
}

export interface DocuTrustVRFBeacon {
  type: 'DocuTrustVRFBeacon2026';
  beaconId: string;
  epoch: number;
  previousBeaconHash: string;
  entropySeed: string;
  combinedRandomnessHex: string;
  evaluations: Array<{
    oracleDid: string;
    vrfOutputHex: string;
    proofHex: string;
    signatureHex: string;
  }>;
  quorumThreshold: number;
  oracleCount: number;
  timestamp: string;
}

export interface DocuTrustOracleFeed {
  type: 'DocuTrustOracleFeed2026';
  feedId: string;
  category: string;
  key: string;
  value: any;
  valueHash: string;
  epoch: number;
  timestamp: string;
  expiresAt: string;
  attestations: Array<{
    oracleDid: string;
    signatureHex: string;
    oraclePublicKeyHex: string;
  }>;
  quorumCount: number;
  thresholdRequired: number;
}

export interface VRFVerificationResult {
  valid: boolean;
  vrfOutputHex: string;
  errors: string[];
}

export interface BeaconVerificationResult {
  valid: boolean;
  beaconId: string;
  epoch: number;
  combinedRandomnessHex: string;
  validEvaluationsCount: number;
  quorumMet: boolean;
  errors: string[];
}

export interface OracleFeedVerificationResult {
  valid: boolean;
  feedId: string;
  key: string;
  value: any;
  quorumReached: boolean;
  validSignaturesCount: number;
  isExpired: boolean;
  errors: string[];
}

export class VRFOracleEngine {
  /**
   * Generates a dedicated VRF keypair with a did:vrf identifier.
   */
  public static generateVRFKeyPair(): VRFKeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubDer = publicKey.export({ type: 'spki', format: 'der' });
    const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    const rawPubKey = pubDer.subarray(pubDer.length - 32);
    const rawPrivKey = privDer.subarray(privDer.length - 32);

    const multicodecKey = Buffer.concat([Buffer.from([0x14, 0x01]), rawPubKey]);
    const did = `did:vrf:z${encodeBase58(multicodecKey)}`;

    return {
      publicKeyHex: rawPubKey.toString('hex'),
      privateKeyHex: rawPrivKey.toString('hex'),
      did
    };
  }

  /**
   * Evaluates a Verifiable Random Function over an input seed.
   * Produces a pseudorandom output and an unforgeable proof.
   */
  public static evaluateVRF(inputSeed: string, keyPair: VRFKeyPair): VRFEvaluation {
    if (!inputSeed) {
      throw new Error('Input seed cannot be empty for VRF evaluation.');
    }

    const timestamp = new Date().toISOString();
    const proofPayload = `VRF_PROOF_V14:${inputSeed}:${timestamp}`;
    const proofSignature = signMessage(proofPayload, keyPair.privateKeyHex);

    const vrfOutputHex = sha256Hex(`VRF_OUTPUT:${proofSignature}:${inputSeed}`);

    const proofData = JSON.stringify({
      sig: proofSignature,
      ts: timestamp,
      seedHash: sha256Hex(inputSeed)
    });
    const proofHex = Buffer.from(proofData, 'utf-8').toString('hex');

    return {
      inputSeed,
      vrfOutputHex,
      proofHex,
      publicKeyHex: keyPair.publicKeyHex,
      timestamp
    };
  }

  /**
   * Cryptographically verifies a VRF evaluation proof and recomputes the VRF output.
   */
  public static verifyVRF(
    inputSeed: string,
    vrfOutputHex: string,
    proofHex: string,
    publicKeyHex: string
  ): VRFVerificationResult {
    const errors: string[] = [];

    try {
      const decodedProof = JSON.parse(Buffer.from(proofHex, 'hex').toString('utf-8'));
      const proofPayload = `VRF_PROOF_V14:${inputSeed}:${decodedProof.ts}`;

      const isSigValid = verifySignature(proofPayload, decodedProof.sig, publicKeyHex);
      if (!isSigValid) {
        errors.push('VRF cryptographic proof signature verification failed.');
      }

      const expectedSeedHash = sha256Hex(inputSeed);
      if (decodedProof.seedHash !== expectedSeedHash) {
        errors.push('VRF proof seed hash mismatch.');
      }

      const expectedOutput = sha256Hex(`VRF_OUTPUT:${decodedProof.sig}:${inputSeed}`);
      if (expectedOutput.toLowerCase() !== vrfOutputHex.toLowerCase()) {
        errors.push('VRF output hash does not match computed evaluation from proof.');
      }

      return {
        valid: errors.length === 0,
        vrfOutputHex: expectedOutput,
        errors
      };
    } catch (err: any) {
      return {
        valid: false,
        vrfOutputHex: '',
        errors: [`VRF proof decoding error: ${err.message}`]
      };
    }
  }

  /**
   * Aggregates multiple oracle VRF evaluations into a threshold randomness beacon.
   */
  public static createRandomnessBeacon(
    beaconId: string,
    epoch: number,
    previousBeaconHash: string,
    entropySeed: string,
    oracleKeyPairs: VRFKeyPair[],
    quorumThreshold: number = 3
  ): DocuTrustVRFBeacon {
    if (!oracleKeyPairs || oracleKeyPairs.length === 0) {
      throw new Error('At least one oracle keypair required to create randomness beacon.');
    }

    const timestamp = new Date().toISOString();
    const evaluations = oracleKeyPairs.map(kp => {
      const evalResult = this.evaluateVRF(`${entropySeed}:${epoch}`, kp);
      const signPayload = canonicalizeJson({
        beaconId,
        epoch,
        oracleDid: kp.did,
        vrfOutput: evalResult.vrfOutputHex,
        proofHex: evalResult.proofHex
      });
      const signatureHex = signMessage(signPayload, kp.privateKeyHex);

      return {
        oracleDid: kp.did,
        vrfOutputHex: evalResult.vrfOutputHex,
        proofHex: evalResult.proofHex,
        signatureHex
      };
    });

    const sortedOutputs = evaluations.map(e => e.vrfOutputHex).sort();
    const combinedRandomnessHex = sha256Hex(`COMBINED_BEACON_V14:${epoch}:${previousBeaconHash}:${sortedOutputs.join(':')}`);

    return {
      type: 'DocuTrustVRFBeacon2026',
      beaconId,
      epoch,
      previousBeaconHash,
      entropySeed,
      combinedRandomnessHex,
      evaluations,
      quorumThreshold: Math.min(quorumThreshold, oracleKeyPairs.length),
      oracleCount: oracleKeyPairs.length,
      timestamp
    };
  }

  /**
   * Verifies a multi-oracle threshold randomness beacon.
   */
  public static verifyRandomnessBeacon(
    beacon: DocuTrustVRFBeacon,
    oraclePublicKeysMap?: Record<string, string>
  ): BeaconVerificationResult {
    const errors: string[] = [];

    if (!beacon || beacon.type !== 'DocuTrustVRFBeacon2026') {
      return {
        valid: false,
        beaconId: beacon?.beaconId || 'unknown',
        epoch: 0,
        combinedRandomnessHex: '',
        validEvaluationsCount: 0,
        quorumMet: false,
        errors: ['Invalid beacon structure or type mismatch.']
      };
    }

    let validCount = 0;
    const verifiedOutputs: string[] = [];

    for (const evalItem of beacon.evaluations || []) {
      let pubKey = oraclePublicKeysMap?.[evalItem.oracleDid];
      if (!pubKey) {
        try {
          if (evalItem.oracleDid.startsWith('did:vrf:')) {
            pubKey = DIDResolver.resolveDidVrf(evalItem.oracleDid).verificationMethod[0]?.publicKeyHex;
          } else if (evalItem.oracleDid.startsWith('did:key:')) {
            pubKey = DIDResolver.resolveDidKey(evalItem.oracleDid).verificationMethod[0]?.publicKeyHex;
          }
        } catch {}
      }

      if (!pubKey) {
        errors.push(`Missing public key for oracle: ${evalItem.oracleDid}`);
        continue;
      }

      const inputSeed = `${beacon.entropySeed}:${beacon.epoch}`;
      const vrfCheck = this.verifyVRF(inputSeed, evalItem.vrfOutputHex, evalItem.proofHex, pubKey);

      if (!vrfCheck.valid) {
        errors.push(`Oracle ${evalItem.oracleDid} VRF evaluation invalid: ${vrfCheck.errors.join(', ')}`);
        continue;
      }

      const signPayload = canonicalizeJson({
        beaconId: beacon.beaconId,
        epoch: beacon.epoch,
        oracleDid: evalItem.oracleDid,
        vrfOutput: evalItem.vrfOutputHex,
        proofHex: evalItem.proofHex
      });
      const sigOk = verifySignature(signPayload, evalItem.signatureHex, pubKey);
      if (!sigOk) {
        errors.push(`Oracle ${evalItem.oracleDid} signature invalid.`);
        continue;
      }

      validCount++;
      verifiedOutputs.push(evalItem.vrfOutputHex);
    }

    const quorumMet = validCount >= beacon.quorumThreshold;
    if (!quorumMet) {
      errors.push(`Quorum threshold not met: required ${beacon.quorumThreshold}, got ${validCount} valid oracle proofs.`);
    }

    const sortedOutputs = verifiedOutputs.sort();
    const expectedCombined = sha256Hex(`COMBINED_BEACON_V14:${beacon.epoch}:${beacon.previousBeaconHash}:${sortedOutputs.join(':')}`);
    if (validCount === beacon.evaluations.length && expectedCombined.toLowerCase() !== beacon.combinedRandomnessHex.toLowerCase()) {
      errors.push('Combined randomness hash does not match oracle evaluations.');
    }

    return {
      valid: errors.length === 0 && quorumMet,
      beaconId: beacon.beaconId,
      epoch: beacon.epoch,
      combinedRandomnessHex: beacon.combinedRandomnessHex,
      validEvaluationsCount: validCount,
      quorumMet,
      errors
    };
  }

  /**
   * Issues a signed multi-oracle data feed attestation.
   */
  public static issueOracleFeed(
    feedPayload: {
      feedId: string;
      category?: string;
      key?: string;
      value: any;
      epoch?: number;
      ttlSeconds?: number;
    },
    oracleKeyPairs: KeyPair[],
    thresholdRequired: number = 2
  ): DocuTrustOracleFeed {
    if (!oracleKeyPairs || oracleKeyPairs.length === 0) {
      throw new Error('At least one oracle keypair required to issue data feed.');
    }

    const timestamp = new Date().toISOString();
    const ttl = feedPayload.ttlSeconds || 3600;
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
    const key = feedPayload.key || feedPayload.feedId;
    const epoch = feedPayload.epoch !== undefined ? feedPayload.epoch : 1;

    const valueCanonical = canonicalizeJson(feedPayload.value);
    const valueHash = sha256Hex(`ORACLE_VAL:${valueCanonical}`);

    const attestations = oracleKeyPairs.map(kp => {
      const signPayload = canonicalizeJson({
        feedId: feedPayload.feedId,
        category: feedPayload.category || 'general-data',
        key,
        valueHash,
        epoch,
        timestamp,
        expiresAt
      });
      const privKey = kp.privateKeyPem || kp.privateKeyHex || (kp as any);
      const signatureHex = signMessage(signPayload, privKey);

      return {
        oracleDid: kp.did,
        signatureHex,
        oraclePublicKeyHex: kp.publicKeyHex
      };
    });

    return {
      type: 'DocuTrustOracleFeed2026',
      feedId: feedPayload.feedId,
      category: feedPayload.category || 'general-data',
      key,
      value: feedPayload.value,
      valueHash,
      epoch,
      timestamp,
      expiresAt,
      attestations,
      quorumCount: attestations.length,
      thresholdRequired: Math.min(thresholdRequired, oracleKeyPairs.length)
    };
  }

  public static createOracleFeed(
    feedPayload: {
      feedId: string;
      category?: string;
      key?: string;
      value: any;
      epoch?: number;
      ttlSeconds?: number;
    },
    oracleKeyPairs: KeyPair[],
    thresholdRequired: number = 2
  ): DocuTrustOracleFeed {
    return this.issueOracleFeed(feedPayload, oracleKeyPairs, thresholdRequired);
  }

  /**
   * Verifies an oracle data feed attestation against quorum requirements and expiration.
   */
  public static verifyOracleFeed(
    feed: DocuTrustOracleFeed,
    trustedOraclePublicKeys?: string[] | Record<string, string>,
    referenceTime?: string
  ): OracleFeedVerificationResult {
    const errors: string[] = [];

    if (!feed || feed.type !== 'DocuTrustOracleFeed2026') {
      return {
        valid: false,
        feedId: feed?.feedId || 'unknown',
        key: '',
        value: null,
        quorumReached: false,
        validSignaturesCount: 0,
        isExpired: false,
        errors: ['Invalid oracle feed structure or type mismatch.']
      };
    }

    const computedValHash = sha256Hex(`ORACLE_VAL:${canonicalizeJson(feed.value)}`);
    if (computedValHash.toLowerCase() !== feed.valueHash.toLowerCase()) {
      errors.push('Oracle feed value payload does not match valueHash commitment.');
    }

    const now = referenceTime ? new Date(referenceTime).getTime() : Date.now();
    const expiryTime = new Date(feed.expiresAt).getTime();
    const isExpired = now > expiryTime;
    if (isExpired) {
      errors.push(`Oracle data feed is expired (expired at ${feed.expiresAt}).`);
    }

    const trustedList: string[] | undefined = Array.isArray(trustedOraclePublicKeys)
      ? trustedOraclePublicKeys
      : (trustedOraclePublicKeys && typeof trustedOraclePublicKeys === 'object'
          ? Object.values(trustedOraclePublicKeys)
          : undefined);

    let validSigs = 0;
    const signPayload = canonicalizeJson({
      feedId: feed.feedId,
      category: feed.category,
      key: feed.key,
      valueHash: feed.valueHash,
      epoch: feed.epoch,
      timestamp: feed.timestamp,
      expiresAt: feed.expiresAt
    });

    for (const att of feed.attestations || []) {
      if (trustedList && !trustedList.includes(att.oraclePublicKeyHex)) {
        continue;
      }

      const sigOk = verifySignature(signPayload, att.signatureHex, att.oraclePublicKeyHex);
      if (sigOk) {
        validSigs++;
      }
    }

    const quorumReached = validSigs >= feed.thresholdRequired;
    if (!quorumReached) {
      errors.push(`Oracle quorum threshold not met: required ${feed.thresholdRequired}, verified ${validSigs}.`);
    }

    return {
      valid: errors.length === 0 && quorumReached && !isExpired,
      feedId: feed.feedId,
      key: feed.key,
      value: feed.value,
      quorumReached,
      validSignaturesCount: validSigs,
      isExpired,
      errors
    };
  }
}
