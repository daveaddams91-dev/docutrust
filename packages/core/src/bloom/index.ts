import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';

export interface SignedBloomFilter {
  type: 'SignedRevocationBloomFilter2026';
  issuerDid: string;
  sizeBits: number;
  hashCount: number;
  bitArrayHex: string;
  revokedCount: number;
  timestamp: string;
  signature: string;
}

export class RevocationBloomFilter {
  private sizeBits: number;
  private hashCount: number;
  private bits: Uint8Array;
  private count: number = 0;

  constructor(sizeBits: number = 8192, hashCount: number = 5) {
    this.sizeBits = sizeBits;
    this.hashCount = hashCount;
    this.bits = new Uint8Array(Math.ceil(sizeBits / 8));
  }

  private getProbes(element: string): number[] {
    const probes: number[] = [];
    const hash = crypto.createHash('sha512').update(element).digest();
    for (let i = 0; i < this.hashCount; i++) {
      const offset = (i * 4) % 60;
      const num = hash.readUInt32BE(offset);
      probes.push(num % this.sizeBits);
    }
    return probes;
  }

  public add(element: string): void {
    const probes = this.getProbes(element);
    for (const bitIdx of probes) {
      const byteIdx = Math.floor(bitIdx / 8);
      const bitOffset = bitIdx % 8;
      this.bits[byteIdx] |= (1 << bitOffset);
    }
    this.count++;
  }

  public has(element: string): boolean {
    const probes = this.getProbes(element);
    for (const bitIdx of probes) {
      const byteIdx = Math.floor(bitIdx / 8);
      const bitOffset = bitIdx % 8;
      if ((this.bits[byteIdx] & (1 << bitOffset)) === 0) {
        return false;
      }
    }
    return true;
  }

  public sign(issuerKeyPair: KeyPair): SignedBloomFilter {
    const timestamp = new Date().toISOString();
    const bitArrayHex = Buffer.from(this.bits).toString('hex');

    const header = {
      type: 'SignedRevocationBloomFilter2026' as const,
      issuerDid: issuerKeyPair.did,
      sizeBits: this.sizeBits,
      hashCount: this.hashCount,
      bitArrayHex,
      revokedCount: this.count,
      timestamp
    };

    const signature = signData(sha256Hex(canonicalizeJson(header)), issuerKeyPair);

    return {
      ...header,
      signature
    };
  }

  public static verifyAndCheck(
    signedFilter: SignedBloomFilter,
    credentialId: string
  ): { isRevoked: boolean; signatureValid: boolean; error?: string } {
    const header = {
      type: signedFilter.type,
      issuerDid: signedFilter.issuerDid,
      sizeBits: signedFilter.sizeBits,
      hashCount: signedFilter.hashCount,
      bitArrayHex: signedFilter.bitArrayHex,
      revokedCount: signedFilter.revokedCount,
      timestamp: signedFilter.timestamp
    };

    const isSigValid = verifySignature(sha256Hex(canonicalizeJson(header)), signedFilter.signature, signedFilter.issuerDid);
    if (!isSigValid) {
      return { isRevoked: false, signatureValid: false, error: 'Invalid issuer signature on Bloom filter.' };
    }

    const filter = new RevocationBloomFilter(signedFilter.sizeBits, signedFilter.hashCount);
    filter.bits = new Uint8Array(Buffer.from(signedFilter.bitArrayHex, 'hex'));

    const isRevoked = filter.has(credentialId);
    return { isRevoked, signatureValid: true };
  }
}
