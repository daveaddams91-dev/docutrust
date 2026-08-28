import * as zlib from 'zlib';

export interface StatusList2021Credential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id: string;
    type: string;
    statusPurpose: 'revocation' | 'suspension';
    encodedList: string;
  };
}

/**
 * StatusList2021 Bitstring Implementation (W3C standard)
 * 100,000 to 1,000,000 credentials tracked in a few kilobytes of compressed bitstring.
 */
export class StatusList2021 {
  private bits: Uint8Array;
  public readonly length: number;

  constructor(length: number = 100000) {
    this.length = length;
    const byteLength = Math.ceil(length / 8);
    this.bits = new Uint8Array(byteLength);
  }

  /**
   * Check if index is revoked (1 = revoked, 0 = valid)
   */
  public isRevoked(index: number): boolean {
    if (index < 0 || index >= this.length) {
      throw new Error(`Index ${index} out of range (0..${this.length - 1})`);
    }
    const byteIndex = Math.floor(index / 8);
    const bitIndex = 7 - (index % 8);
    return ((this.bits[byteIndex] >> bitIndex) & 1) === 1;
  }

  /**
   * Set revocation bit (true = revoked, false = valid)
   */
  public setStatus(index: number, revoked: boolean): void {
    if (index < 0 || index >= this.length) {
      throw new Error(`Index ${index} out of range (0..${this.length - 1})`);
    }
    const byteIndex = Math.floor(index / 8);
    const bitIndex = 7 - (index % 8);

    if (revoked) {
      this.bits[byteIndex] |= (1 << bitIndex);
    } else {
      this.bits[byteIndex] &= ~(1 << bitIndex);
    }
  }

  /**
   * Compresses the bitstring using GZIP and encodes as base64url string.
   */
  public encode(): string {
    const compressed = zlib.gzipSync(Buffer.from(this.bits));
    return compressed.toString('base64url');
  }

  /**
   * Decodes an encoded base64url GZIP bitstring.
   */
  public static decode(encodedList: string, length?: number): StatusList2021 {
    const compressedBuffer = Buffer.from(encodedList, 'base64url');
    const decompressed = zlib.gunzipSync(compressedBuffer);
    const totalBits = length || decompressed.length * 8;

    const list = new StatusList2021(totalBits);
    list.bits = new Uint8Array(decompressed);
    return list;
  }
}
