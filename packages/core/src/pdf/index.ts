import * as crypto from 'crypto';
import { VerifiableCredential, VerifiableCredentialsEngine, VerificationResult } from '../vc';
import { sha256Hex, canonicalizeJson } from '../crypto';

export interface VerifiablePdfResult {
  pdfBuffer: Buffer;
  pdfBase64: string;
  documentHash: string;
  credentialId: string;
}

function escapePdfText(str: string): string {
  // Normalize string, sanitize unicode to clean printable ASCII representation for standard PDF Type1 fonts
  const clean = String(str)
    .normalize('NFKD')
    .replace(/[^\x20-\x7E]/g, c => {
      // Map common accented latin characters or fallback to ascii
      const code = c.charCodeAt(0);
      return code < 256 ? String.fromCharCode(code) : '?';
    });
  return clean
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

/**
 * Generates an ISO 32000-1 compliant Verifiable PDF with embedded W3C Verifiable Credential metadata.
 */
export function generateVerifiablePdf(credential: VerifiableCredential): VerifiablePdfResult {
  const subject = credential.credentialSubject || {};
  const rawRecipientName = String(subject.name || subject.recipientName || subject.studentName || 'Recipient Name');
  const rawDegree = String(subject.title || subject.degree || 'Official Certificate');
  const rawIssuerName = String((typeof credential.issuer === 'object' ? credential.issuer.name : credential.issuer) || 'Authorized Issuing Authority');

  const recipientName = escapePdfText(rawRecipientName);
  const degree = escapePdfText(rawDegree);
  const issuerName = escapePdfText(rawIssuerName);

  const issueDate = escapePdfText(new Date(credential.validFrom || new Date().toISOString()).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  }));
  const certId = escapePdfText(credential.id.replace('urn:uuid:', ''));
  const signatureHex = credential.proof?.proofValue || '';

  // Encode credential JSON as Base64 for clean PDF metadata embedding
  const vcJson = JSON.stringify(credential);
  const vcBase64 = Buffer.from(vcJson, 'utf-8').toString('base64');

  const streamContent = `BT
/F1 20 Tf
100 700 Td
(${issuerName}) Tj
/F2 12 Tf
0 -30 Td
(SOVEREIGN VERIFIABLE CREDENTIAL - W3C VC 2.0) Tj
/F2 10 Tf
0 -40 Td
(This certifies that:) Tj
/F1 24 Tf
0 -35 Td
(${recipientName}) Tj
/F2 12 Tf
0 -30 Td
(Has successfully completed requirements for:) Tj
/F1 16 Tf
0 -25 Td
(${degree}) Tj
/F2 9 Tf
0 -50 Td
(CREDENTIAL ID: ${certId}) Tj
0 -15 Td
(ISSUANCE DATE: ${issueDate}) Tj
0 -15 Td
(ED25519 SIGNATURE: ${signatureHex.substring(0, 48)}...) Tj
0 -30 Td
(Cryptographically sealed by DocuTrust. Verify at https://docutrust.org/verify) Tj
ET`;

  const streamLength = Buffer.byteLength(streamContent, 'utf-8');

  // Modular objects for exact byte offset calculation
  const header = '%PDF-1.7\n';
  const obj1 = `1 0 obj\n<< /Type /Catalog /Pages 2 0 R /DocuTrustProof << /Type /VerifiableCredential /Payload (${vcBase64}) >> >>\nendobj\n`;
  const obj2 = `2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n`;
  const obj3 = `3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n`;
  const obj4 = `4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`;
  const obj5 = `5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`;
  const obj6 = `6 0 obj\n<< /Length ${streamLength} >>\nstream\n${streamContent}\nendstream\nendobj\n`;

  const offset1 = Buffer.byteLength(header, 'utf-8');
  const offset2 = offset1 + Buffer.byteLength(obj1, 'utf-8');
  const offset3 = offset2 + Buffer.byteLength(obj2, 'utf-8');
  const offset4 = offset3 + Buffer.byteLength(obj3, 'utf-8');
  const offset5 = offset4 + Buffer.byteLength(obj4, 'utf-8');
  const offset6 = offset5 + Buffer.byteLength(obj5, 'utf-8');

  const formatOffset = (offset: number) => String(offset).padStart(10, '0');

  const objectsBody = header + obj1 + obj2 + obj3 + obj4 + obj5 + obj6;
  const startXref = Buffer.byteLength(objectsBody, 'utf-8');

  const xrefSection = `xref\n0 7\n0000000000 65535 f \n${formatOffset(offset1)} 00000 n \n${formatOffset(offset2)} 00000 n \n${formatOffset(offset3)} 00000 n \n${formatOffset(offset4)} 00000 n \n${formatOffset(offset5)} 00000 n \n${formatOffset(offset6)} 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n${startXref}\n%%EOF`;

  const pdfBody = objectsBody + xrefSection;
  const pdfBuffer = Buffer.from(pdfBody, 'utf-8');
  const documentHash = sha256Hex(pdfBuffer);

  return {
    pdfBuffer,
    pdfBase64: pdfBuffer.toString('base64'),
    documentHash,
    credentialId: credential.id
  };
}

/**
 * Extracts embedded W3C Verifiable Credential from a PDF byte stream.
 */
export function extractVerifiablePdfProof(pdfData: Buffer | string): VerifiableCredential | null {
  const content = typeof pdfData === 'string' ? pdfData : pdfData.toString('utf-8');

  // Search for /DocuTrustProof << /Type /VerifiableCredential /Payload (BASE64) >>
  const match = content.match(/\/DocuTrustProof\s*<<\s*\/Type\s*\/VerifiableCredential\s*\/Payload\s*\(([\s\S]*?)\)\s*>>/);
  if (!match || !match[1]) {
    return null;
  }

  try {
    const rawBase64 = match[1].replace(/\s+/g, '');
    const rawJson = Buffer.from(rawBase64, 'base64').toString('utf-8');
    return JSON.parse(rawJson) as VerifiableCredential;
  } catch (err) {
    return null;
  }
}

/**
 * Validates a PDF file directly: extracts embedded credential and runs full cryptographic verification.
 */
export async function verifyPdfDocument(pdfData: Buffer | string): Promise<VerificationResult & { isPdfValid: boolean }> {
  const credential = extractVerifiablePdfProof(pdfData);

  if (!credential) {
    return {
      valid: false,
      isPdfValid: false,
      issuer: 'unknown',
      issuanceDate: 'unknown',
      isExpired: false,
      isRevoked: false,
      signatureValid: false,
      errors: ['No embedded cryptographic DocuTrust proof found in PDF document.']
    };
  }

  const result = await VerifiableCredentialsEngine.verify(credential);
  return {
    ...result,
    isPdfValid: result.valid
  };
}
