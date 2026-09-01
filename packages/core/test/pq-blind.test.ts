import { describe, it, expect } from 'vitest';
import { PQBlindSignatureEngine } from '../src/pq-blind';

describe('PQBlindSignatureEngine (v19.0.0)', () => {
  it('should complete full lattice blind signature lifecycle: blind -> sign -> unblind -> verify', () => {
    // 1. Signer generates post-quantum lattice keys
    const signerKey = PQBlindSignatureEngine.generateKeyPair();
    expect(signerKey.signerDid).toBeDefined();
    expect(signerKey.publicKeyHex).toBeDefined();

    // 2. User blinds private message
    const message = {
      subject: 'did:key:z6MkuUserAnonymous',
      vote: 'APPROVE_TREASURY_TRANSFER',
      entropy: '98471928471928'
    };
    const { request, blindingSecretHex, messageHash } = PQBlindSignatureEngine.blindMessage(message, signerKey);
    expect(request.blindedMessageHash).toBeDefined();

    // 3. Signer issues blind signature without seeing message
    const blindSignature = PQBlindSignatureEngine.signBlindedMessage(request, signerKey);
    expect(blindSignature.blindSignatureHex).toBeDefined();

    // 4. User unblinds signature locally
    const receipt = PQBlindSignatureEngine.unblindSignature(
      messageHash,
      blindSignature,
      blindingSecretHex,
      signerKey
    );
    expect(receipt.unblindedSignatureHex).toBeDefined();

    // 5. Anyone verifies unblinded signature against original message & signer public key
    const verification = PQBlindSignatureEngine.verifySignature(message, receipt, signerKey.publicKeyHex);
    expect(verification.valid).toBe(true);

    // 6. Verification with tampered message fails
    const tamperedMessage = { ...message, vote: 'REJECT_TREASURY_TRANSFER' };
    const tamperedVerify = PQBlindSignatureEngine.verifySignature(tamperedMessage, receipt, signerKey.publicKeyHex);
    expect(tamperedVerify.valid).toBe(false);
  });
});
