import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';

export interface SDJWTDisclosure {
  salt: string;
  key: string;
  value: any;
  rawDisclosure: string; // Base64URL
  digest: string;        // SHA-256 of raw disclosure in Base64URL
}

export interface SDJWTPackage {
  issuerJwt: string;
  disclosures: SDJWTDisclosure[];
  combinedSdJwt: string;
  issuerDid: string;
}

function base64UrlEncode(strOrBuf: string | Buffer): string {
  const buf = typeof strOrBuf === 'string' ? Buffer.from(strOrBuf, 'utf-8') : strOrBuf;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Encodes a credential claims object into an IETF Selective Disclosure JWT (SD-JWT).
 */
export function issueSDJWT(
  claims: Record<string, any>,
  issuerKeyPair: KeyPair,
  subjectDid?: string
): SDJWTPackage {
  const disclosures: SDJWTDisclosure[] = [];
  const sdDigests: string[] = [];

  for (const [key, value] of Object.entries(claims)) {
    const salt = crypto.randomBytes(16).toString('base64url');
    const disclosureArray = [salt, key, value];
    const rawDisclosure = base64UrlEncode(JSON.stringify(disclosureArray));
    const digest = crypto.createHash('sha256').update(rawDisclosure).digest('base64url');

    disclosures.push({
      salt,
      key,
      value,
      rawDisclosure,
      digest
    });
    sdDigests.push(digest);
  }

  // Construct issuer payload with _sd hash array
  const header = {
    alg: 'EdDSA',
    typ: 'vc+sd-jwt'
  };

  const payload = {
    iss: issuerKeyPair.did,
    sub: subjectDid || issuerKeyPair.did,
    iat: Math.floor(Date.now() / 1000),
    _sd: sdDigests,
    _sd_alg: 'sha-256'
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signatureHex = signData(sha256Hex(signingInput), issuerKeyPair);
  const signatureB64 = base64UrlEncode(Buffer.from(signatureHex, 'hex'));

  const issuerJwt = `${signingInput}.${signatureB64}`;
  const combinedSdJwt = `${issuerJwt}~${disclosures.map(d => d.rawDisclosure).join('~')}~`;

  return {
    issuerJwt,
    disclosures,
    combinedSdJwt,
    issuerDid: issuerKeyPair.did
  };
}

/**
 * Holder selectively presents only a subset of disclosures to a verifier.
 */
export function createSDJWTPresentation(
  sdJwtPackage: SDJWTPackage,
  discloseKeys: string[]
): string {
  const selectedDisclosures = sdJwtPackage.disclosures.filter(d => discloseKeys.includes(d.key));
  return `${sdJwtPackage.issuerJwt}~${selectedDisclosures.map(d => d.rawDisclosure).join('~')}~`;
}

/**
 * Verifier validates an SD-JWT presentation against the issuer's public key.
 */
export function verifySDJWTPresentation(
  presentationString: string
): {
  valid: boolean;
  issuerDid: string;
  subjectDid: string;
  disclosedClaims: Record<string, any>;
  error?: string;
} {
  const parts = presentationString.split('~');
  if (parts.length < 2) {
    return { valid: false, issuerDid: '', subjectDid: '', disclosedClaims: {}, error: 'Malformed SD-JWT string.' };
  }

  const issuerJwt = parts[0];
  // Disclosures are single base64url strings without periods; optional KB-JWT contains 2 periods (3 parts)
  const disclosureStrings = parts.slice(1).filter(p => p.length > 0 && p.split('.').length !== 3);

  const jwtParts = issuerJwt.split('.');
  if (jwtParts.length !== 3) {
    return { valid: false, issuerDid: '', subjectDid: '', disclosedClaims: {}, error: 'Invalid JWT structure.' };
  }

  const [headerB64, payloadB64, sigB64] = jwtParts;
  const signingInput = `${headerB64}.${payloadB64}`;
  
  let payload: any;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64));
  } catch (err: any) {
    return { valid: false, issuerDid: '', subjectDid: '', disclosedClaims: {}, error: 'Failed to decode JWT payload JSON.' };
  }

  const issuerDid = payload.iss;
  const subjectDid = payload.sub;
  const sdArray: string[] = payload._sd || [];

  const sigHex = Buffer.from(sigB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex');
  const isSigValid = verifySignature(sha256Hex(signingInput), sigHex, issuerDid);
  if (!isSigValid) {
    return { valid: false, issuerDid, subjectDid, disclosedClaims: {}, error: 'Issuer signature verification failed.' };
  }

  const disclosedClaims: Record<string, any> = {};

  for (const rawDisc of disclosureStrings) {
    const digest = crypto.createHash('sha256').update(rawDisc).digest('base64url');
    if (!sdArray.includes(digest)) {
      return { valid: false, issuerDid, subjectDid, disclosedClaims: {}, error: `Disclosure digest ${digest} is not in issuer's _sd commitment list.` };
    }

    try {
      const decodedJson = JSON.parse(base64UrlDecode(rawDisc));
      if (Array.isArray(decodedJson) && decodedJson.length === 3) {
        const [, key, value] = decodedJson;
        disclosedClaims[key] = value;
      }
    } catch (e) {
      return { valid: false, issuerDid, subjectDid, disclosedClaims: {}, error: 'Failed to decode disclosure JSON.' };
    }
  }

  return {
    valid: true,
    issuerDid,
    subjectDid,
    disclosedClaims
  };
}
