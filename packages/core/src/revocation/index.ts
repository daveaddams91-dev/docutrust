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

export type BitstringStatusPurpose = 'revocation' | 'suspension' | 'message' | 'compliance' | string;

export interface BitstringStatusListEntry {
  id: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: BitstringStatusPurpose;
  statusListIndex: string;
  statusListCredential: string;
  statusSize?: number;
}

export interface BitstringStatusListCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  credentialSubject: {
    id: string;
    type: 'BitstringStatusList';
    statusPurpose: BitstringStatusPurpose;
    statusSize: number;
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
    const raw = encodedList.startsWith('u') ? encodedList.slice(1) : encodedList;
    const compressedBuffer = Buffer.from(raw, 'base64url');
    const decompressed = zlib.gunzipSync(compressedBuffer);
    const totalBits = length || decompressed.length * 8;

    const list = new StatusList2021(totalBits);
    list.bits = new Uint8Array(decompressed);
    return list;
  }
}

/**
 * BitstringStatusList2024 (W3C Bitstring Status List v1.0)
 * Supports configurable status bit sizes:
 * - 1 bit (0 = Valid, 1 = Revoked / Suspended)
 * - 2 bits (00 = Valid, 01 = Revoked, 10 = Suspended, 11 = Under Review)
 * - 4 bits / 8 bits for arbitrary custom status categories.
 */
export class BitstringStatusList2024 {
  private bits: Uint8Array;
  public readonly length: number;
  public readonly statusSize: number;
  public readonly statusPurpose: BitstringStatusPurpose;

  constructor(length: number = 100000, statusSize: number = 1, statusPurpose: BitstringStatusPurpose = 'revocation') {
    if (![1, 2, 4, 8].includes(statusSize)) {
      throw new Error('BitstringStatusList2024 statusSize must be 1, 2, 4, or 8');
    }
    this.length = length;
    this.statusSize = statusSize;
    this.statusPurpose = statusPurpose;
    const totalBits = length * statusSize;
    const byteLength = Math.ceil(totalBits / 8);
    this.bits = new Uint8Array(byteLength);
  }

  /**
   * Returns numeric status value at specified index.
   */
  public getStatus(index: number): number {
    if (index < 0 || index >= this.length) {
      throw new Error(`Index ${index} out of range (0..${this.length - 1})`);
    }

    const bitOffset = index * this.statusSize;
    const byteIndex = Math.floor(bitOffset / 8);
    const bitShift = 8 - this.statusSize - (bitOffset % 8);
    const mask = (1 << this.statusSize) - 1;

    return (this.bits[byteIndex] >> bitShift) & mask;
  }

  /**
   * Sets numeric status value at specified index.
   */
  public setStatus(index: number, status: number): void {
    if (index < 0 || index >= this.length) {
      throw new Error(`Index ${index} out of range (0..${this.length - 1})`);
    }
    const mask = (1 << this.statusSize) - 1;
    if (status < 0 || status > mask) {
      throw new Error(`Status ${status} out of range for statusSize ${this.statusSize} (0..${mask})`);
    }

    const bitOffset = index * this.statusSize;
    const byteIndex = Math.floor(bitOffset / 8);
    const bitShift = 8 - this.statusSize - (bitOffset % 8);

    // Clear target bits and set new status
    this.bits[byteIndex] &= ~(mask << bitShift);
    this.bits[byteIndex] |= (status << bitShift);
  }

  /**
   * Helper: check if index is Revoked (bit/status == 1).
   */
  public isRevoked(index: number): boolean {
    return this.getStatus(index) === 1;
  }

  /**
   * Helper: check if index is Suspended (status == 2 when statusSize >= 2, or status == 1 when statusPurpose == 'suspension').
   */
  public isSuspended(index: number): boolean {
    if (this.statusSize >= 2) {
      return this.getStatus(index) === 2;
    }
    return this.statusPurpose === 'suspension' && this.getStatus(index) === 1;
  }

  /**
   * Helper: check if index is Valid (status == 0).
   */
  public isValid(index: number): boolean {
    return this.getStatus(index) === 0;
  }

  /**
   * Compresses bitstring using GZIP and returns multibase encoded string prefixed with 'u'.
   */
  public encode(includeMultibasePrefix: boolean = true): string {
    const compressed = zlib.gzipSync(Buffer.from(this.bits));
    const base64url = compressed.toString('base64url');
    return includeMultibasePrefix ? `u${base64url}` : base64url;
  }

  /**
   * Decodes a multibase or base64url GZIP bitstring into a BitstringStatusList2024 instance.
   */
  public static decode(
    encodedList: string,
    options: { length?: number; statusSize?: number; statusPurpose?: BitstringStatusPurpose } = {}
  ): BitstringStatusList2024 {
    const raw = encodedList.startsWith('u') ? encodedList.slice(1) : encodedList;
    const compressedBuffer = Buffer.from(raw, 'base64url');
    const decompressed = zlib.gunzipSync(compressedBuffer);
    
    const statusSize = options.statusSize || 1;
    const totalBits = decompressed.length * 8;
    const length = options.length || Math.floor(totalBits / statusSize);
    const purpose = options.statusPurpose || 'revocation';

    const list = new BitstringStatusList2024(length, statusSize, purpose);
    list.bits = new Uint8Array(decompressed);
    return list;
  }

  /**
   * Generates a standard W3C BitstringStatusListCredential metadata block.
   */
  public generateCredential(id: string, issuerDid: string): BitstringStatusListCredential {
    return {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/vc/status-list/v1'
      ],
      id,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: issuerDid,
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: `${id}#list`,
        type: 'BitstringStatusList',
        statusPurpose: this.statusPurpose,
        statusSize: this.statusSize,
        encodedList: this.encode(true)
      }
    };
  }

  /**
   * Creates a BitstringStatusListEntry reference descriptor for embedding into a Verifiable Credential.
   */
  public static createEntry(
    statusListCredentialUrl: string,
    statusListIndex: number | string,
    statusPurpose: BitstringStatusPurpose = 'revocation',
    statusSize: number = 1
  ): BitstringStatusListEntry {
    return {
      id: `${statusListCredentialUrl}#${statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose,
      statusListIndex: String(statusListIndex),
      statusListCredential: statusListCredentialUrl,
      statusSize
    };
  }
}
