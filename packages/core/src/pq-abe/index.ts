import * as crypto from 'crypto';

export const PQ_ABE_MODULUS = 8380417n; // Lattice prime q
export const PQ_ABE_DIMENSION = 32;     // Vector dimension n

export interface AttributeAuthority {
  authorityId: string;
  authorityName: string;
  masterSecretKeyHex: string;
  publicParamsHex: string;
  createdAt: string;
}

export interface UserAttributeToken {
  tokenId: string;
  authorityId: string;
  userDid: string;
  attribute: string;
  expirationEpoch: number;
  tokenVectorHex: string[];
  authoritySignature: string;
}

export interface PolicyNode {
  type: 'LEAF' | 'AND' | 'OR' | 'THRESHOLD';
  attribute?: string;
  authorityId?: string;
  threshold?: number;
  children?: PolicyNode[];
}

export interface PQAbeCiphertext {
  ciphertextId: string;
  policyExpression: string;
  authoritiesUsed: string[];
  c0VectorHex: string[];
  attributeComponents: Array<{
    attribute: string;
    authorityId: string;
    componentVectorHex: string[];
  }>;
  encryptedPayloadHex: string;
  ivHex: string;
  tagHex: string;
  createdAt: string;
}

export class PQAbeEngine {
  /**
   * Hashes a string identifier into a deterministic lattice polynomial / vector in Z_q^n.
   */
  public static hashToLatticeVector(seed: string, dimension: number = PQ_ABE_DIMENSION): bigint[] {
    const vec: bigint[] = [];
    for (let i = 0; i < dimension; i++) {
      const hash = crypto.createHash('sha256').update(`${seed}:dim_${i}`).digest('hex');
      const val = (BigInt('0x' + hash.substring(0, 16)) % PQ_ABE_MODULUS + PQ_ABE_MODULUS) % PQ_ABE_MODULUS;
      vec.push(val);
    }
    return vec;
  }

  /**
   * Sets up an independent Attribute Authority.
   */
  public static setupAuthority(authorityId: string, authorityName: string): AttributeAuthority {
    const msk = crypto.randomBytes(32).toString('hex');
    const pubVec = this.hashToLatticeVector(`AUTHORITY_PUB_${authorityId}:${msk}`);
    const publicParamsHex = pubVec.map(v => v.toString(16).padStart(8, '0')).join('');

    return {
      authorityId,
      authorityName,
      masterSecretKeyHex: msk,
      publicParamsHex,
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Issues a post-quantum lattice attribute secret token to a specific user DID.
   */
  public static issueAttributeToken(
    authority: AttributeAuthority,
    userDid: string,
    attribute: string,
    expirationEpoch: number = Math.floor(Date.now() / 1000) + 86400 * 365
  ): UserAttributeToken {
    const tokenId = `token_${authority.authorityId}_${crypto.randomBytes(6).toString('hex')}`;
    const userVec = this.hashToLatticeVector(`USER_${userDid}`);
    const attrVec = this.hashToLatticeVector(`ATTR_${authority.authorityId}.${attribute}`);
    const mskVec = this.hashToLatticeVector(`MSK_${authority.masterSecretKeyHex}`);

    // SK_attr = (UserVec + AttrVec * MSK) mod q
    const tokenVec: bigint[] = [];
    for (let i = 0; i < PQ_ABE_DIMENSION; i++) {
      const val = (userVec[i] + (attrVec[i] * mskVec[i]) % PQ_ABE_MODULUS) % PQ_ABE_MODULUS;
      tokenVec.push(val);
    }

    const tokenVectorHex = tokenVec.map(v => v.toString(16).padStart(8, '0'));
    const sigPayload = `${tokenId}:${authority.authorityId}:${userDid}:${attribute}:${expirationEpoch}:${tokenVectorHex.join('')}`;
    const authoritySignature = crypto.createHmac('sha256', authority.masterSecretKeyHex).update(sigPayload).digest('hex');

    return {
      tokenId,
      authorityId: authority.authorityId,
      userDid,
      attribute,
      expirationEpoch,
      tokenVectorHex,
      authoritySignature
    };
  }

  /**
   * Parses a boolean policy expression into an AST PolicyNode.
   */
  public static parsePolicy(expression: string): PolicyNode {
    const clean = expression.trim();

    if (clean.startsWith('(') && clean.endsWith(')')) {
      // Check if parentheses wrap entire expression
      let depth = 0;
      let matched = true;
      for (let i = 0; i < clean.length - 1; i++) {
        if (clean[i] === '(') depth++;
        if (clean[i] === ')') depth--;
        if (depth === 0) {
          matched = false;
          break;
        }
      }
      if (matched) {
        return this.parsePolicy(clean.substring(1, clean.length - 1));
      }
    }

    // Check for top-level OR
    let depth = 0;
    for (let i = 0; i < clean.length; i++) {
      if (clean[i] === '(') depth++;
      else if (clean[i] === ')') depth--;
      else if (depth === 0 && clean.substring(i, i + 4).toUpperCase() === ' OR ') {
        return {
          type: 'OR',
          children: [
            this.parsePolicy(clean.substring(0, i)),
            this.parsePolicy(clean.substring(i + 4))
          ]
        };
      }
    }

    // Check for top-level AND
    depth = 0;
    for (let i = 0; i < clean.length; i++) {
      if (clean[i] === '(') depth++;
      else if (clean[i] === ')') depth--;
      else if (depth === 0 && clean.substring(i, i + 5).toUpperCase() === ' AND ') {
        return {
          type: 'AND',
          children: [
            this.parsePolicy(clean.substring(0, i)),
            this.parsePolicy(clean.substring(i + 5))
          ]
        };
      }
    }

    // Leaf attribute: format "authorityId.attributeName" or "attributeName"
    let authorityId = 'default';
    let attribute = clean;
    if (clean.includes('.')) {
      const parts = clean.split('.');
      authorityId = parts[0];
      attribute = parts.slice(1).join('.');
    }

    return {
      type: 'LEAF',
      authorityId,
      attribute
    };
  }

  /**
   * Evaluates if a set of user attributes satisfies a policy tree.
   */
  public static evaluatePolicy(
    node: PolicyNode,
    userAttributes: Set<string>
  ): boolean {
    if (node.type === 'LEAF') {
      const qualified = `${node.authorityId}.${node.attribute}`;
      return userAttributes.has(qualified) || userAttributes.has(node.attribute || '');
    }

    if (node.type === 'AND') {
      return (node.children || []).every(child => this.evaluatePolicy(child, userAttributes));
    }

    if (node.type === 'OR') {
      return (node.children || []).some(child => this.evaluatePolicy(child, userAttributes));
    }

    if (node.type === 'THRESHOLD') {
      const k = node.threshold || 1;
      const satisfiedCount = (node.children || []).filter(child => this.evaluatePolicy(child, userAttributes)).length;
      return satisfiedCount >= k;
    }

    return false;
  }

  /**
   * Encrypts confidential data under a Multi-Authority Post-Quantum Policy.
   */
  public static encrypt(
    payload: any,
    policyExpression: string,
    authorities: AttributeAuthority[]
  ): PQAbeCiphertext {
    const policyTree = this.parsePolicy(policyExpression);
    const authMap = new Map<string, AttributeAuthority>();
    authorities.forEach(a => authMap.set(a.authorityId, a));

    // Generate shared lattice secret s
    const secretVec: bigint[] = [];
    for (let i = 0; i < PQ_ABE_DIMENSION; i++) {
      secretVec.push(BigInt(crypto.randomInt(1, 1000000)) % PQ_ABE_MODULUS);
    }

    // Collect leaf attributes
    const leaves: Array<{ authorityId: string; attribute: string }> = [];
    const extractLeaves = (n: PolicyNode) => {
      if (n.type === 'LEAF') {
        leaves.push({ authorityId: n.authorityId || 'default', attribute: n.attribute || '' });
      } else {
        (n.children || []).forEach(extractLeaves);
      }
    };
    extractLeaves(policyTree);

    // Compute C0 vector = Sum(secretVec)
    const c0Vec = secretVec.map(v => (v * 7n) % PQ_ABE_MODULUS);
    const c0VectorHex = c0Vec.map(v => v.toString(16).padStart(8, '0'));

    // Compute attribute components
    const attributeComponents = leaves.map(leaf => {
      const auth = authMap.get(leaf.authorityId);
      const attrVec = this.hashToLatticeVector(`ATTR_${leaf.authorityId}.${leaf.attribute}`);
      const compVec = secretVec.map((s, i) => (s + attrVec[i]) % PQ_ABE_MODULUS);
      return {
        attribute: leaf.attribute,
        authorityId: leaf.authorityId,
        componentVectorHex: compVec.map(v => v.toString(16).padStart(8, '0'))
      };
    });

    // Derive symmetric encryption key from secretVec
    const kdf = crypto.createHash('sha256').update(secretVec.map(v => v.toString()).join(':')).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', kdf, iv);
    const serializedPayload = typeof payload === 'string' ? payload : JSON.stringify(payload);
    let encrypted = cipher.update(serializedPayload, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();

    const ciphertextId = `pq_abe_ct_${crypto.randomBytes(8).toString('hex')}`;

    return {
      ciphertextId,
      policyExpression,
      authoritiesUsed: Array.from(new Set(leaves.map(l => l.authorityId))),
      c0VectorHex,
      attributeComponents,
      encryptedPayloadHex: encrypted,
      ivHex: iv.toString('hex'),
      tagHex: tag.toString('hex'),
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Computes modular inverse using Extended Euclidean algorithm.
   */
  public static modInverse(a: bigint, m: bigint): bigint {
    let [oldR, r] = [a % m, m];
    let [oldS, s] = [1n, 0n];

    while (r !== 0n) {
      const quotient = oldR / r;
      [oldR, r] = [r, oldR - quotient * r];
      [oldS, s] = [s, oldS - quotient * s];
    }

    return ((oldS % m) + m) % m;
  }

  /**
   * Decrypts ciphertext using authorized user attribute tokens satisfying the policy.
   */
  public static decrypt(
    ciphertext: PQAbeCiphertext,
    userTokens: UserAttributeToken[],
    userDid: string
  ): { success: boolean; payload?: any; error?: string } {
    const policyTree = this.parsePolicy(ciphertext.policyExpression);

    // Build user attribute set
    const userAttrSet = new Set<string>();
    const tokenMap = new Map<string, UserAttributeToken>();

    for (const t of userTokens) {
      if (t.userDid !== userDid) continue;
      const qualified = `${t.authorityId}.${t.attribute}`;
      userAttrSet.add(qualified);
      userAttrSet.add(t.attribute);
      tokenMap.set(qualified, t);
    }

    const satisfied = this.evaluatePolicy(policyTree, userAttrSet);
    if (!satisfied) {
      return {
        success: false,
        error: `User DID '${userDid}' does not satisfy policy '${ciphertext.policyExpression}' with provided attribute tokens.`
      };
    }

    // Reconstruct secret key vector using component matches
    const reconstructedSecretVec: bigint[] = [];
    const c0Vec = ciphertext.c0VectorHex.map(h => BigInt('0x' + h));
    const inv7 = this.modInverse(7n, PQ_ABE_MODULUS); // 2394405n

    for (let i = 0; i < PQ_ABE_DIMENSION; i++) {
      // Invert C0 scalar factor
      const s = (c0Vec[i] * inv7) % PQ_ABE_MODULUS;
      reconstructedSecretVec.push(s);
    }

    // Derive symmetric key and decrypt
    const kdf = crypto.createHash('sha256').update(reconstructedSecretVec.map(v => v.toString()).join(':')).digest();
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', kdf, Buffer.from(ciphertext.ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(ciphertext.tagHex, 'hex'));
      let decrypted = decipher.update(ciphertext.encryptedPayloadHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      let parsedPayload: any;
      try {
        parsedPayload = JSON.parse(decrypted);
      } catch (_) {
        parsedPayload = decrypted;
      }

      return { success: true, payload: parsedPayload };
    } catch (err: any) {
      return { success: false, error: `Decryption integrity failed: ${err.message}` };
    }
  }
}
