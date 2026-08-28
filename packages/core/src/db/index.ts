import * as fs from 'fs';
import * as path from 'path';
import { VerifiableCredential } from '../vc';
import { AnchorReceipt, LocalLedgerAnchor } from '../ledger';
import { MerkleTree } from '../merkle';
import { sha256Hex } from '../crypto';

export interface StoredCredentialRecord {
  id: string;
  type: string[];
  issuerId: string;
  issuerName: string;
  recipientName: string;
  recipientId: string;
  issuanceDate: string;
  validUntil?: string;
  status: 'valid' | 'revoked' | 'expired';
  anchored: boolean;
  anchorReceipt?: AnchorReceipt;
  rawCredential: VerifiableCredential;
}

export interface ApiKeyRecord {
  keyId: string;
  apiKey: string;
  organizationName: string;
  issuerDid: string;
  rateLimitPerMinute: number;
  createdAt: string;
  active: boolean;
}

export interface VaultMetrics {
  totalCredentials: number;
  totalAnchored: number;
  totalRevoked: number;
  totalIssuers: number;
  quantumSafeCount: number;
  lastAnchorTimestamp?: number;
}

/**
 * Persistent Vault & Index Registry for Multi-Tenant Credentials.
 */
export class CredentialVault {
  private dataDir: string;
  private credentialsFile: string;
  private apiKeysFile: string;
  private anchorsFile: string;

  private credentialsMap: Map<string, StoredCredentialRecord> = new Map();
  private apiKeysMap: Map<string, ApiKeyRecord> = new Map();
  private anchorsList: AnchorReceipt[] = [];

  constructor(dataDir: string = './data') {
    this.dataDir = path.resolve(dataDir);
    this.credentialsFile = path.join(this.dataDir, 'credentials.json');
    this.apiKeysFile = path.join(this.dataDir, 'api_keys.json');
    this.anchorsFile = path.join(this.dataDir, 'anchors.json');

    this.initStorage();
  }

  private initStorage(): void {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    if (fs.existsSync(this.credentialsFile)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.credentialsFile, 'utf-8'));
        raw.forEach((r: StoredCredentialRecord) => this.credentialsMap.set(r.id, r));
      } catch (e) {}
    }

    if (fs.existsSync(this.apiKeysFile)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.apiKeysFile, 'utf-8'));
        raw.forEach((k: ApiKeyRecord) => this.apiKeysMap.set(k.apiKey, k));
      } catch (e) {}
    }

    if (fs.existsSync(this.anchorsFile)) {
      try {
        this.anchorsList = JSON.parse(fs.readFileSync(this.anchorsFile, 'utf-8'));
      } catch (e) {}
    }
  }

  private persistCredentials(): void {
    try {
      const records = Array.from(this.credentialsMap.values());
      fs.writeFileSync(this.credentialsFile, JSON.stringify(records, null, 2), 'utf-8');
    } catch (e) {}
  }

  private persistApiKeys(): void {
    try {
      const records = Array.from(this.apiKeysMap.values());
      fs.writeFileSync(this.apiKeysFile, JSON.stringify(records, null, 2), 'utf-8');
    } catch (e) {}
  }

  private persistAnchors(): void {
    try {
      fs.writeFileSync(this.anchorsFile, JSON.stringify(this.anchorsList, null, 2), 'utf-8');
    } catch (e) {}
  }

  public saveCredential(vc: VerifiableCredential): StoredCredentialRecord {
    const issuerId = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
    const issuerName = typeof vc.issuer === 'object' ? vc.issuer.name || 'Authority' : 'Authority';
    const recipientName = vc.credentialSubject?.name || 'Recipient';
    const recipientId = vc.credentialSubject?.id || 'did:key:unknown';

    const record: StoredCredentialRecord = {
      id: vc.id,
      type: vc.type,
      issuerId,
      issuerName,
      recipientName,
      recipientId,
      issuanceDate: vc.validFrom,
      validUntil: vc.validUntil,
      status: 'valid',
      anchored: Boolean(vc.proof?.anchorReceipt),
      anchorReceipt: vc.proof?.anchorReceipt,
      rawCredential: vc
    };

    this.credentialsMap.set(vc.id, record);
    this.persistCredentials();
    return record;
  }

  public getCredential(id: string): StoredCredentialRecord | null {
    return this.credentialsMap.get(id) || null;
  }

  public listCredentials(options: {
    issuerId?: string;
    status?: 'valid' | 'revoked' | 'expired';
    search?: string;
    limit?: number;
    offset?: number;
  } = {}): { records: StoredCredentialRecord[]; total: number } {
    let list = Array.from(this.credentialsMap.values());

    if (options.issuerId) {
      list = list.filter(r => r.issuerId === options.issuerId);
    }
    if (options.status) {
      list = list.filter(r => r.status === options.status);
    }
    if (options.search) {
      const q = options.search.toLowerCase();
      list = list.filter(r =>
        r.recipientName.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q) ||
        r.type.some(t => t.toLowerCase().includes(q))
      );
    }

    const total = list.length;
    const offset = options.offset || 0;
    const limit = options.limit || 50;
    const records = list.slice(offset, offset + limit);

    return { records, total };
  }

  public setStatus(id: string, status: 'valid' | 'revoked' | 'expired'): boolean {
    const record = this.credentialsMap.get(id);
    if (!record) return false;
    record.status = status;
    this.credentialsMap.set(id, record);
    this.persistCredentials();
    return true;
  }

  public getUnanchored(): StoredCredentialRecord[] {
    return Array.from(this.credentialsMap.values()).filter(r => !r.anchored);
  }

  public async executeAutoBatchAnchor(): Promise<AnchorReceipt | null> {
    const unanchored = this.getUnanchored();
    if (unanchored.length === 0) return null;

    const leaves = unanchored.map(u => u.rawCredential.proof.jcsCanonicalHash || sha256Hex(JSON.stringify(u.rawCredential)));
    const tree = new MerkleTree(leaves);
    const root = tree.getRoot();

    const anchor = new LocalLedgerAnchor();
    const receipt = await anchor.anchorRoot(root, unanchored.length);

    unanchored.forEach((rec, idx) => {
      rec.anchored = true;
      rec.anchorReceipt = receipt;
      rec.rawCredential.proof.merkleProof = tree.getProof(idx);
      rec.rawCredential.proof.anchorReceipt = receipt;
      this.credentialsMap.set(rec.id, rec);
    });

    this.anchorsList.push(receipt);
    this.persistCredentials();
    this.persistAnchors();

    return receipt;
  }

  public createApiKey(orgName: string, issuerDid: string): ApiKeyRecord {
    const apiKey = `dt_live_${crypto.randomBytes(24).toString('hex')}`;
    const record: ApiKeyRecord = {
      keyId: `key_${crypto.randomBytes(8).toString('hex')}`,
      apiKey,
      organizationName: orgName,
      issuerDid,
      rateLimitPerMinute: 1000,
      createdAt: new Date().toISOString(),
      active: true
    };
    this.apiKeysMap.set(apiKey, record);
    this.persistApiKeys();
    return record;
  }

  public getMetrics(): VaultMetrics {
    const records = Array.from(this.credentialsMap.values());
    const issuers = new Set(records.map(r => r.issuerId));
    const anchored = records.filter(r => r.anchored).length;
    const revoked = records.filter(r => r.status === 'revoked').length;
    const pqcCount = records.filter(r => r.rawCredential.proof?.type?.includes('Hybrid') || r.rawCredential.proof?.type?.includes('ML-DSA')).length;

    return {
      totalCredentials: records.length,
      totalAnchored: anchored,
      totalRevoked: revoked,
      totalIssuers: issuers.size || 1,
      quantumSafeCount: pqcCount,
      lastAnchorTimestamp: this.anchorsList.length > 0 ? this.anchorsList[this.anchorsList.length - 1].timestamp : undefined
    };
  }
}
