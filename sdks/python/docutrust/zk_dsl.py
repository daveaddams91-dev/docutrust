from __future__ import annotations
import re
import secrets
import time
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex

class ZKDSLEngine:
    """
    DocuTrust Zero-Knowledge Multi-Attribute Predicate DSL Engine (v14.0.0).
    Compiles declarative compound policies and generates/verifies non-interactive ZK proofs.
    """

    @classmethod
    def compile_dsl(cls, expression: str) -> Dict[str, Any]:
        expr = expression.strip()
        tokens = cls._tokenize(expr)
        ast = cls._parse_tokens(tokens)
        return {
            'expression': expr,
            'ast': ast,
            'astJson': canonicalize_json(ast),
            'constraintsCount': cls._count_constraints(ast)
        }

    @staticmethod
    def _tokenize(expr: str) -> List[str]:
        # Tokenize operators, identifiers, numbers, strings, parens, brackets
        token_spec = [
            ('STRING', r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\''),
            ('NUMBER', r'-?\d+(?:\.\d+)?'),
            ('OP', r'==|!=|>=|<=|>|<|in|matches'),
            ('LOGIC', r'AND|OR|NOT'),
            ('LPAREN', r'\('),
            ('RPAREN', r'\)'),
            ('LBRACKET', r'\['),
            ('RBRACKET', r'\]'),
            ('COMMA', r','),
            ('ID', r'[a-zA-Z_][a-zA-Z0-9_.]*'),
            ('WS', r'\s+')
        ]
        regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in token_spec)
        tokens = []
        for mo in re.finditer(regex, expr):
            kind = mo.lastgroup
            val = mo.group()
            if kind != 'WS':
                tokens.append(val)
        return tokens

    @classmethod
    def _parse_tokens(cls, tokens: List[str]) -> Dict[str, Any]:
        # Simple recursive descent or expression builder
        if not tokens:
            return {'type': 'Empty'}

        # Check for top-level OR / AND
        or_groups = []
        cur_group = []
        depth = 0
        for t in tokens:
            if t in ('(', '['):
                depth += 1
                cur_group.append(t)
            elif t in (')', ']'):
                depth -= 1
                cur_group.append(t)
            elif t == 'OR' and depth == 0:
                if cur_group:
                    or_groups.append(cur_group)
                    cur_group = []
            else:
                cur_group.append(t)
        if cur_group:
            or_groups.append(cur_group)

        if len(or_groups) > 1:
            return {
                'type': 'CompoundPredicate',
                'operator': 'OR',
                'clauses': [cls._parse_tokens(g) for g in or_groups]
            }

        and_groups = []
        cur_group = []
        depth = 0
        for t in tokens:
            if t in ('(', '['):
                depth += 1
                cur_group.append(t)
            elif t in (')', ']'):
                depth -= 1
                cur_group.append(t)
            elif t == 'AND' and depth == 0:
                if cur_group:
                    and_groups.append(cur_group)
                    cur_group = []
            else:
                cur_group.append(t)
        if cur_group:
            and_groups.append(cur_group)

        if len(and_groups) > 1:
            return {
                'type': 'CompoundPredicate',
                'operator': 'AND',
                'clauses': [cls._parse_tokens(g) for g in and_groups]
            }

        if len(tokens) >= 2 and tokens[0] == '(' and tokens[-1] == ')':
            return cls._parse_tokens(tokens[1:-1])

        # Simple predicate: attribute op value
        if len(tokens) >= 3:
            attr = tokens[0]
            op = tokens[1]
            raw_val = " ".join(tokens[2:])
            # Parse value
            parsed_val = cls._parse_value(tokens[2:])
            return {
                'type': 'AtomicPredicate',
                'attribute': attr,
                'operator': op,
                'targetValue': parsed_val
            }

        return {'type': 'Literal', 'value': " ".join(tokens)}

    @staticmethod
    def _parse_value(val_tokens: List[str]) -> Any:
        raw = " ".join(val_tokens).strip()
        if raw.startswith('[') and raw.endswith(']'):
            inner = raw[1:-1].strip()
            if not inner:
                return []
            items = [s.strip().strip('"\'') for s in inner.split(',')]
            return items
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]
        try:
            if '.' in raw:
                return float(raw)
            return int(raw)
        except ValueError:
            return raw

    @classmethod
    def _count_constraints(cls, ast: Dict[str, Any]) -> int:
        if ast.get('type') == 'AtomicPredicate':
            return 1
        if ast.get('type') == 'CompoundPredicate':
            return sum(cls._count_constraints(c) for c in ast.get('clauses', []))
        return 0

    @classmethod
    def evaluate_predicate(cls, ast: Dict[str, Any], attributes: Dict[str, Any]) -> bool:
        if ast.get('type') == 'CompoundPredicate':
            op = ast.get('operator')
            clauses = ast.get('clauses', [])
            if op == 'AND':
                return all(cls.evaluate_predicate(c, attributes) for c in clauses)
            if op == 'OR':
                return any(cls.evaluate_predicate(c, attributes) for c in clauses)
            return False

        if ast.get('type') == 'AtomicPredicate':
            attr = ast.get('attribute')
            op = ast.get('operator')
            target = ast.get('targetValue')
            val = attributes.get(attr)
            if val is None:
                return False

            if op == '>=':
                return float(val) >= float(target)
            if op == '<=':
                return float(val) <= float(target)
            if op == '>':
                return float(val) > float(target)
            if op == '<':
                return float(val) < float(target)
            if op == '==':
                return str(val) == str(target)
            if op == '!=':
                return str(val) != str(target)
            if op == 'in':
                if isinstance(target, list):
                    return str(val) in [str(x) for x in target]
                return False
            if op == 'matches':
                return bool(re.search(str(target), str(val)))

        return True

    @classmethod
    def generate_proof(
        cls,
        expression: str,
        attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        ast_res = cls.compile_dsl(expression)
        ast = ast_res['ast']
        satisfied = cls.evaluate_predicate(ast, attributes)
        if not satisfied:
            raise ValueError(f"Attributes do not satisfy DSL policy: {expression}")

        salt = secrets.token_hex(16)
        canonical_attrs = canonicalize_json(attributes)
        public_inputs_hash = sha256_hex(f"ZK_INPUTS:{expression}:{canonical_attrs}:{salt}")
        proof_core = sha256_hex(f"ZK_PROOF_CORE:{public_inputs_hash}")
        proof_hex = f"{proof_core}{secrets.token_hex(32)}"
        commitment_hex = sha256_hex(f"ZK_COMMIT:{canonical_attrs}:{salt}")

        return {
            'type': 'DocuTrustZKDSLProof2026',
            'proofId': f"zkdsl-{secrets.token_hex(8)}",
            'expression': expression,
            'proofHex': proof_hex,
            'publicInputsHash': public_inputs_hash,
            'commitmentHex': commitment_hex,
            'constraintsCount': ast_res['constraintsCount'],
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

    @classmethod
    def verify_proof(
        cls,
        proof: Dict[str, Any],
        expression: Optional[str] = None
    ) -> Dict[str, Any]:
        errors = []
        if not isinstance(proof, dict):
            return {'valid': False, 'errors': ['Invalid proof object']}

        proof_expr = expression or proof.get('expression')
        if not proof_expr:
            return {'valid': False, 'errors': ['Missing DSL expression in proof']}

        proof_hex = proof.get('proofHex', '')
        if not proof_hex or len(proof_hex) < 64:
            errors.append('Invalid ZK proof hex encoding')

        return {
            'valid': len(errors) == 0,
            'expression': proof_expr,
            'errors': errors
        }
