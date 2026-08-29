import * as crypto from 'crypto';

export interface ShamirShare {
  index: number;
  shareHex: string;
  threshold: number;
  totalShares: number;
  checksum: string;
}

// GF(256) Math tables with irreducible polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1)
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(function initGF256() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    EXP[i + 255] = x;
    LOG[x] = i;
    const highBit = x & 0x80;
    x = ((x << 1) & 0xff) ^ (highBit ? 0x1d : 0);
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a] + 255 - LOG[b]) % 255];
}

/**
 * Splits arbitrary secret (string or Buffer) into N shares with threshold K.
 */
export function splitSecret(secret: string | Buffer, totalShares: number, threshold: number): ShamirShare[] {
  if (threshold < 2 || threshold > totalShares || totalShares > 255) {
    throw new Error(`Invalid threshold ${threshold} or total shares ${totalShares}. Must satisfy 2 <= threshold <= totalShares <= 255.`);
  }

  const secretBuf = typeof secret === 'string' ? Buffer.from(secret, 'utf-8') : secret;
  const checksum = crypto.createHash('sha256').update(secretBuf).digest('hex').substring(0, 16);
  const shares: Uint8Array[] = Array.from({ length: totalShares }, () => new Uint8Array(secretBuf.length));

  for (let byteIdx = 0; byteIdx < secretBuf.length; byteIdx++) {
    const s = secretBuf[byteIdx];
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = s;
    for (let c = 1; c < threshold; c++) {
      coeffs[c] = crypto.randomBytes(1)[0];
    }

    for (let x = 1; x <= totalShares; x++) {
      let y = 0;
      for (let c = threshold - 1; c >= 0; c--) {
        y = gfMul(y, x) ^ coeffs[c];
      }
      shares[x - 1][byteIdx] = y;
    }
  }

  return shares.map((shareBuf, idx) => ({
    index: idx + 1,
    shareHex: Buffer.from(shareBuf).toString('hex'),
    threshold,
    totalShares,
    checksum
  }));
}

/**
 * Reconstructs the secret from any K valid Shamir shares using Lagrange interpolation in GF(256).
 */
export function combineShares(shares: ShamirShare[]): Buffer {
  if (shares.length < 2) {
    throw new Error('At least 2 shares are required for reconstruction.');
  }

  const threshold = shares[0].threshold;
  if (shares.length < threshold) {
    throw new Error(`Insufficient shares: provided ${shares.length}, threshold is ${threshold}.`);
  }

  const selected = shares.slice(0, threshold);
  const shareBuffers = selected.map(s => Buffer.from(s.shareHex, 'hex'));
  const secretLen = shareBuffers[0].length;
  const secret = Buffer.alloc(secretLen);

  const xVals = selected.map(s => s.index);

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let secretByte = 0;

    for (let i = 0; i < threshold; i++) {
      let numerator = 1;
      let denominator = 1;

      for (let j = 0; j < threshold; j++) {
        if (i === j) continue;
        numerator = gfMul(numerator, xVals[j]);
        denominator = gfMul(denominator, xVals[i] ^ xVals[j]);
      }

      const lagrangeBasis = gfDiv(numerator, denominator);
      const term = gfMul(shareBuffers[i][byteIdx], lagrangeBasis);
      secretByte ^= term;
    }

    secret[byteIdx] = secretByte;
  }

  const reconstructedChecksum = crypto.createHash('sha256').update(secret).digest('hex').substring(0, 16);
  if (shares[0].checksum && reconstructedChecksum !== shares[0].checksum) {
    throw new Error('Checksum mismatch during Shamir secret reconstruction. Invalid or corrupted shares provided.');
  }

  return secret;
}
