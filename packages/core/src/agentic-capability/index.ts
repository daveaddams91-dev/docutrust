import * as crypto from 'crypto';
import { canonicalizeJson } from '../crypto';

export interface Capability {
  resource: string;
  action: string;
  constraints?: Record<string, any>;
}

export interface Caveat {
  type: 'expiration' | 'rateLimit' | 'maxSpend' | 'ipWhitelist' | 'subDomain';
  value: any;
}

export interface UCANToken {
  type: string;
  tokenId: string;
  issuer: string;
  audience: string;
  capabilities: Capability[];
  caveats: Caveat[];
  parentProofHashes: string[];
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export interface AgentExecutionReceipt {
  type: string;
  receiptId: string;
  agentDid: string;
  invokedCapability: Capability;
  tokenChain: UCANToken[];
  executionDigest: string;
  timestamp: string;
  status: 'EXECUTED_AUTHENTIC' | 'DENIED_ATTENUATION';
  signature: string;
}

export class AgenticCapabilityEngine {
  private static matchesPattern(pattern: string, target: string): boolean {
    if (pattern === '*' || pattern === target) return true;
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      return target.startsWith(prefix);
    }
    return false;
  }

  public static issueRootCapability(
    issuerDid: string,
    audienceDid: string,
    capabilities: Capability[],
    caveats: Caveat[],
    expiresInSeconds: number,
    issuerPrivateKeyHex: string
  ): UCANToken {
    const tokenId = 'ucan_' + crypto.randomBytes(8).toString('hex');
    const now = new Date();
    const exp = new Date(now.getTime() + expiresInSeconds * 1000);

    const unsignedToken = {
      type: 'DocuTrustUCANToken2026',
      tokenId,
      issuer: issuerDid,
      audience: audienceDid,
      capabilities,
      caveats,
      parentProofHashes: [],
      issuedAt: now.toISOString(),
      expiresAt: exp.toISOString()
    };

    const canonical = canonicalizeJson(unsignedToken);
    const hash = crypto.createHash('sha256').update(canonical).digest();
    const hmac = crypto.createHmac('sha256', Buffer.from(issuerPrivateKeyHex, 'hex'));
    hmac.update(hash);
    const signature = '0x' + hmac.digest('hex');

    return {
      ...unsignedToken,
      signature
    };
  }

  public static attenuateCapability(
    parentToken: UCANToken,
    delegatorDid: string,
    delegateeDid: string,
    restrictedCapabilities: Capability[],
    additionalCaveats: Caveat[],
    expiresInSeconds: number,
    delegatorPrivateKeyHex: string
  ): UCANToken {
    if (parentToken.audience !== delegatorDid) {
      throw new Error('Delegator DID must match parent token audience');
    }

    for (const reqCap of restrictedCapabilities) {
      const parentMatch = parentToken.capabilities.some(
        p => this.matchesPattern(p.resource, reqCap.resource) &&
             this.matchesPattern(p.action, reqCap.action)
      );
      if (!parentMatch) {
        throw new Error('Attenuation violation: requested capability exceeds parent permissions (' + reqCap.action + ' on ' + reqCap.resource + ')');
      }
    }

    const parentCanonical = canonicalizeJson(parentToken);
    const parentHash = '0x' + crypto.createHash('sha256').update(parentCanonical).digest('hex');

    const tokenId = 'ucan_' + crypto.randomBytes(8).toString('hex');
    const now = new Date();
    const parentExp = new Date(parentToken.expiresAt);
    const requestedExp = new Date(now.getTime() + expiresInSeconds * 1000);
    const effectiveExp = requestedExp < parentExp ? requestedExp : parentExp;

    const mergedCaveats = [...parentToken.caveats, ...additionalCaveats];

    const unsignedToken = {
      type: 'DocuTrustUCANToken2026',
      tokenId,
      issuer: delegatorDid,
      audience: delegateeDid,
      capabilities: restrictedCapabilities,
      caveats: mergedCaveats,
      parentProofHashes: [parentHash],
      issuedAt: now.toISOString(),
      expiresAt: effectiveExp.toISOString()
    };

    const canonical = canonicalizeJson(unsignedToken);
    const hash = crypto.createHash('sha256').update(canonical).digest();
    const hmac = crypto.createHmac('sha256', Buffer.from(delegatorPrivateKeyHex, 'hex'));
    hmac.update(hash);
    const signature = '0x' + hmac.digest('hex');

    return {
      ...unsignedToken,
      signature
    };
  }

  public static verifyDelegationPath(
    tokenChain: UCANToken[],
    targetAction: string,
    targetResource: string,
    context: { currentTimestamp?: string; spendAmount?: number; clientIp?: string } = {}
  ): { valid: boolean; error?: string } {
    if (tokenChain.length === 0) {
      return { valid: false, error: 'Token chain is empty' };
    }

    const now = context.currentTimestamp ? new Date(context.currentTimestamp) : new Date();

    for (let i = 0; i < tokenChain.length; i++) {
      const token = tokenChain[i];

      if (token.type !== 'DocuTrustUCANToken2026') {
        return { valid: false, error: 'Invalid UCAN token type at depth ' + i };
      }

      if (new Date(token.expiresAt) < now) {
        return { valid: false, error: 'Token at depth ' + i + ' has expired' };
      }

      for (const caveat of token.caveats) {
        if (caveat.type === 'maxSpend' && context.spendAmount !== undefined) {
          if (context.spendAmount > caveat.value) {
            return { valid: false, error: 'Caveat violation: spend amount ' + context.spendAmount + ' exceeds limit ' + caveat.value };
          }
        }
        if (caveat.type === 'ipWhitelist' && context.clientIp) {
          if (!caveat.value.includes(context.clientIp)) {
            return { valid: false, error: 'Caveat violation: client IP ' + context.clientIp + ' not in whitelist' };
          }
        }
      }

      if (i > 0) {
        const parent = tokenChain[i - 1];
        if (token.issuer !== parent.audience) {
          return { valid: false, error: 'Delegation chain broken at depth ' + i + ': issuer ' + token.issuer + ' != parent audience ' + parent.audience };
        }
      }
    }

    const leafToken = tokenChain[tokenChain.length - 1];
    const hasCapability = leafToken.capabilities.some(
      c => this.matchesPattern(c.resource, targetResource) &&
           this.matchesPattern(c.action, targetAction)
    );

    if (!hasCapability) {
      return { valid: false, error: 'Leaf token does not authorize ' + targetAction + ' on ' + targetResource };
    }

    return { valid: true };
  }

  public static createExecutionReceipt(
    agentDid: string,
    invokedCapability: Capability,
    tokenChain: UCANToken[],
    executionPayload: any,
    agentPrivateKeyHex: string
  ): AgentExecutionReceipt {
    const receiptId = 'exec_' + crypto.randomBytes(8).toString('hex');
    const executionDigest = '0x' + crypto.createHash('sha256').update(canonicalizeJson(executionPayload)).digest('hex');

    const unsigned = {
      type: 'DocuTrustAgentExecutionReceipt2026',
      receiptId,
      agentDid,
      invokedCapability,
      tokenChain,
      executionDigest,
      timestamp: new Date().toISOString(),
      status: 'EXECUTED_AUTHENTIC' as const
    };

    const canonical = canonicalizeJson(unsigned);
    const hash = crypto.createHash('sha256').update(canonical).digest();
    const hmac = crypto.createHmac('sha256', Buffer.from(agentPrivateKeyHex, 'hex'));
    hmac.update(hash);
    const signature = '0x' + hmac.digest('hex');

    return {
      ...unsigned,
      signature
    };
  }

  public static verifyExecutionReceipt(
    receipt: AgentExecutionReceipt,
    expectedAgentPrivateKeyHex?: string
  ): { valid: boolean; error?: string } {
    if (receipt.type !== 'DocuTrustAgentExecutionReceipt2026') {
      return { valid: false, error: 'Invalid execution receipt type' };
    }

    const pathCheck = this.verifyDelegationPath(
      receipt.tokenChain,
      receipt.invokedCapability.action,
      receipt.invokedCapability.resource
    );

    if (!pathCheck.valid) {
      return { valid: false, error: 'Delegation path invalid: ' + pathCheck.error };
    }

    if (expectedAgentPrivateKeyHex) {
      const { signature, ...unsigned } = receipt;
      const canonical = canonicalizeJson(unsigned);
      const hash = crypto.createHash('sha256').update(canonical).digest();
      const hmac = crypto.createHmac('sha256', Buffer.from(expectedAgentPrivateKeyHex, 'hex'));
      hmac.update(hash);
      const expectedSig = '0x' + hmac.digest('hex');

      if (signature !== expectedSig) {
        return { valid: false, error: 'Cryptographic signature mismatch' };
      }
    }

    return { valid: true };
  }
}
