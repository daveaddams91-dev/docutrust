import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';

export interface TrustAuthorityAccreditation {
  issuerDid: string;
  issuerName: string;
  jurisdiction: string;
  allowedSchemas: string[];
  validFrom: string;
  validUntil: string;
  trustLevel: 'TIER_1_ACCREDITED' | 'TIER_2_VERIFIED' | 'COMMUNITY_PROVISIONAL';
  governanceAnchorDid: string;
  authoritySignature: string;
}

export class DecentralizedTrustRegistry {
  private accreditations: Map<string, TrustAuthorityAccreditation> = new Map();

  constructor(initialAccreditations: TrustAuthorityAccreditation[] = []) {
    initialAccreditations.forEach(acc => this.accreditations.set(acc.issuerDid, acc));
  }

  /**
   * Governance Authority signs an accreditation certificate for an Issuer DID.
   */
  public static issueAccreditation(
    issuerDid: string,
    issuerName: string,
    jurisdiction: string,
    allowedSchemas: string[],
    validDays: number = 365,
    trustLevel: 'TIER_1_ACCREDITED' | 'TIER_2_VERIFIED' | 'COMMUNITY_PROVISIONAL' = 'TIER_1_ACCREDITED',
    governanceKeyPair: KeyPair
  ): TrustAuthorityAccreditation {
    const validFrom = new Date().toISOString();
    const validUntil = new Date(Date.now() + validDays * 86400000).toISOString();

    const payload = canonicalizeJson({
      issuerDid,
      issuerName,
      jurisdiction,
      allowedSchemas: allowedSchemas.slice().sort(),
      validFrom,
      validUntil,
      trustLevel,
      governanceAnchorDid: governanceKeyPair.did
    });

    const authoritySignature = signData(sha256Hex(payload), governanceKeyPair);

    return {
      issuerDid,
      issuerName,
      jurisdiction,
      allowedSchemas,
      validFrom,
      validUntil,
      trustLevel,
      governanceAnchorDid: governanceKeyPair.did,
      authoritySignature
    };
  }

  public registerAccreditation(accreditation: TrustAuthorityAccreditation): boolean {
    const payload = canonicalizeJson({
      issuerDid: accreditation.issuerDid,
      issuerName: accreditation.issuerName,
      jurisdiction: accreditation.jurisdiction,
      allowedSchemas: accreditation.allowedSchemas.slice().sort(),
      validFrom: accreditation.validFrom,
      validUntil: accreditation.validUntil,
      trustLevel: accreditation.trustLevel,
      governanceAnchorDid: accreditation.governanceAnchorDid
    });

    const isValid = verifySignature(sha256Hex(payload), accreditation.authoritySignature, accreditation.governanceAnchorDid);
    if (!isValid) {
      throw new Error('Invalid governance authority signature on accreditation.');
    }

    this.accreditations.set(accreditation.issuerDid, accreditation);
    return true;
  }

  public getAccreditation(issuerDid: string): TrustAuthorityAccreditation | null {
    return this.accreditations.get(issuerDid) || null;
  }

  /**
   * Verifies if an issuer is trusted to issue a specific credential schema.
   */
  public verifyIssuerAuthorization(
    issuerDid: string,
    schemaType: string
  ): { authorized: boolean; reason?: string; accreditation?: TrustAuthorityAccreditation } {
    const acc = this.accreditations.get(issuerDid);
    if (!acc) {
      return { authorized: false, reason: `Issuer ${issuerDid} is not registered in the decentralized trust registry.` };
    }

    const now = new Date().toISOString();
    if (now < acc.validFrom || now > acc.validUntil) {
      return { authorized: false, reason: `Accreditation for ${acc.issuerName} has expired or is not yet valid.` };
    }

    if (!acc.allowedSchemas.includes(schemaType) && !acc.allowedSchemas.includes('*')) {
      return { authorized: false, reason: `Issuer ${acc.issuerName} is not authorized to issue schema ${schemaType}. Allowed: ${acc.allowedSchemas.join(', ')}` };
    }

    return { authorized: true, accreditation: acc };
  }

  public listAllIssuers(): TrustAuthorityAccreditation[] {
    return Array.from(this.accreditations.values());
  }
}

