import { generateSalt, sha256Hex, canonicalizeJson } from '../crypto';
import { MerkleTree, MerkleInclusionProof } from '../merkle';

export interface BlindedClaim {
  key: string;
  value: any;
  salt: string;
  blindedHash: string;
}

export interface DisclosedClaim {
  key: string;
  value: any;
  salt: string;
  proof: MerkleInclusionProof;
}

export interface SelectiveDisclosurePackage {
  claimsRoot: string;
  blindedClaims: BlindedClaim[];
  merkleTree: MerkleTree;
}

export interface SelectiveDisclosurePresentation {
  claimsRoot: string;
  totalClaims: number;
  disclosedClaims: DisclosedClaim[];
  hiddenClaimHashes: { [keyIndex: number]: string };
}

/**
 * Computes the blinded hash of a salted claim:
 * Hash = SHA-256( salt + "::" + key + "::" + canonicalJson(value) )
 */
export function computeBlindedClaimHash(key: string, value: any, salt: string): string {
  const payload = `${salt}::${key}::${canonicalizeJson(value)}`;
  return sha256Hex(payload);
}

/**
 * Creates a salted claims Merkle tree from raw claim object.
 */
export function createSelectiveDisclosurePackage(claims: Record<string, any>): SelectiveDisclosurePackage {
  const keys = Object.keys(claims).sort();
  const blindedClaims: BlindedClaim[] = [];

  for (const key of keys) {
    const value = claims[key];
    const salt = generateSalt(16);
    const blindedHash = computeBlindedClaimHash(key, value, salt);

    blindedClaims.push({
      key,
      value,
      salt,
      blindedHash
    });
  }

  // Construct Merkle tree over the blinded hashes
  const tree = new MerkleTree(blindedClaims.map(c => c.blindedHash));

  return {
    claimsRoot: tree.getRoot(),
    blindedClaims,
    merkleTree: tree
  };
}

/**
 * Holder generates a selective presentation by picking specific claim keys to reveal.
 */
export function generateSelectiveDisclosurePresentation(
  pkg: SelectiveDisclosurePackage,
  revealKeys: string[]
): SelectiveDisclosurePresentation {
  const revealSet = new Set(revealKeys);
  const disclosedClaims: DisclosedClaim[] = [];
  const hiddenClaimHashes: { [keyIndex: number]: string } = {};

  for (let idx = 0; idx < pkg.blindedClaims.length; idx++) {
    const claim = pkg.blindedClaims[idx];
    if (revealSet.has(claim.key)) {
      disclosedClaims.push({
        key: claim.key,
        value: claim.value,
        salt: claim.salt,
        proof: pkg.merkleTree.getProof(idx)
      });
    } else {
      hiddenClaimHashes[idx] = claim.blindedHash;
    }
  }

  return {
    claimsRoot: pkg.claimsRoot,
    totalClaims: pkg.blindedClaims.length,
    disclosedClaims,
    hiddenClaimHashes
  };
}

/**
 * Verifier verifies that disclosed claims mathematically match the signed claimsRoot.
 */
export function verifySelectiveDisclosurePresentation(
  presentation: SelectiveDisclosurePresentation,
  expectedClaimsRoot?: string
): { valid: boolean; verifiedClaims: Record<string, any>; error?: string } {
  const targetRoot = expectedClaimsRoot || presentation.claimsRoot;
  const verifiedClaims: Record<string, any> = {};

  if (!presentation.disclosedClaims || presentation.disclosedClaims.length === 0) {
    return { valid: false, verifiedClaims: {}, error: 'No disclosed claims found in presentation' };
  }

  for (const disclosed of presentation.disclosedClaims) {
    const recomputedHash = computeBlindedClaimHash(disclosed.key, disclosed.value, disclosed.salt);
    const isProofValid = MerkleTree.verifyProof(
      null,
      {
        ...disclosed.proof,
        leafHash: recomputedHash
      },
      targetRoot
    );

    if (!isProofValid) {
      return {
        valid: false,
        verifiedClaims: {},
        error: `Cryptographic proof validation failed for claim: ${disclosed.key}`
      };
    }

    verifiedClaims[disclosed.key] = disclosed.value;
  }

  return {
    valid: true,
    verifiedClaims
  };
}
