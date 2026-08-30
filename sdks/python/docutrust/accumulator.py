"""
DocuTrust Dynamic Cryptographic Accumulator (Python Parity)
Provides O(1) constant-size dynamic membership & revocation witnesses with modular arithmetic.
"""

from typing import Any, Dict, List, Optional, Set
from .crypto import sha256_hex


def extended_gcd(a: int, b: int):
    """Extended Euclidean algorithm computing gcd(a, b) and Bezout coefficients x, y such that a*x + b*y = gcd(a,b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


class CryptographicAccumulator:
    DEFAULT_MODULUS_HEX = (
        "d8c3e85e056d6f35b2e5a7b3c8f1d2e4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6"
        "b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0"
        "e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4"
        "a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8"
        "c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2"
        "f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6"
        "b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0"
        "e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f7"
    )
    DEFAULT_GENERATOR_HEX = "03"

    def __init__(
        self,
        accumulator_id: str,
        modulus_hex: str = DEFAULT_MODULUS_HEX,
        generator_hex: str = DEFAULT_GENERATOR_HEX,
        initial_accumulator_hex: Optional[str] = None
    ):
        self.id = accumulator_id
        self.N = int(modulus_hex, 16)
        self.g = int(generator_hex, 16)
        self.V = int(initial_accumulator_hex, 16) if initial_accumulator_hex else self.g
        self.members: Set[str] = set()
        self.prime_map: Dict[str, int] = {}

    @classmethod
    def element_to_prime(cls, element: str) -> int:
        """Deterministically maps any arbitrary string element to an odd prime representative."""
        nonce = 0
        while True:
            digest = sha256_hex(f"DT_ACC_PRIME_V1:{nonce}:{element}")
            candidate = (int(digest, 16) & ((1 << 128) - 1)) | 1
            if cls.is_prime(candidate):
                return candidate
            nonce += 1

    @classmethod
    def is_prime(cls, n: int, rounds: int = 8) -> bool:
        """Miller-Rabin probabilistic primality test."""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for i in range(min(rounds, len(bases))):
            a = bases[i]
            if n <= a:
                break
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue

            composite = True
            for _ in range(1, s):
                x = pow(x, 2, n)
                if x == n - 1:
                    composite = False
                    break
            if composite:
                return False
        return True

    def add(self, element: str) -> Dict[str, str]:
        """Adds an element to the accumulator."""
        if element in self.members:
            prime = self.prime_map[element]
            return {"prime_representative": hex(prime)[2:], "new_accumulator": hex(self.V)[2:]}

        prime = self.element_to_prime(element)
        self.members.add(element)
        self.prime_map[element] = prime
        self.V = pow(self.V, prime, self.N)

        return {
            "prime_representative": hex(prime)[2:],
            "new_accumulator": hex(self.V)[2:]
        }

    def add_batch(self, elements: List[str]) -> Dict[str, Any]:
        """Adds a batch of elements to the accumulator."""
        count = 0
        for elem in elements:
            if elem not in self.members:
                prime = self.element_to_prime(elem)
                self.members.add(elem)
                self.prime_map[elem] = prime
                self.V = pow(self.V, prime, self.N)
                count += 1
        return {
            "new_accumulator": hex(self.V)[2:],
            "added_count": count
        }

    def delete(self, element: str) -> Dict[str, Any]:
        """Removes an element from the accumulator."""
        if element not in self.members:
            return {"new_accumulator": hex(self.V)[2:], "success": False}

        self.members.remove(element)
        del self.prime_map[element]

        new_v = self.g
        for prime in self.prime_map.values():
            new_v = pow(new_v, prime, self.N)
        self.V = new_v

        return {"new_accumulator": hex(self.V)[2:], "success": True}

    def create_witness(self, element: str) -> Dict[str, str]:
        """Generates a constant-size O(1) membership witness for an element."""
        if element not in self.members:
            raise ValueError(f"Cannot create witness: element '{element}' is not in accumulator.")

        prime = self.prime_map[element]
        w = self.g
        for elem, p in self.prime_map.items():
            if elem != element:
                w = pow(w, p, self.N)

        return {
            "element": element,
            "prime_representative": hex(prime)[2:],
            "witness": hex(w)[2:],
            "accumulator_id": self.id
        }

    def create_non_membership_witness(self, element: str) -> Dict[str, str]:
        """
        Generates an O(1) Non-Membership Witness for an element NOT in the accumulator.
        Computes Bezout identity: a*x + b*P = 1 where x is element prime and P is product of member primes.
        Witness consists of d = (g^a mod N) and integer coefficient b.
        """
        if element in self.members:
            raise ValueError(f"Cannot create non-membership witness: element '{element}' is in accumulator.")

        x = self.element_to_prime(element)
        P = 1
        for p in self.prime_map.values():
            P *= p

        gcd_val, a, b = extended_gcd(x, P)
        if gcd_val != 1:
            raise ValueError("Accumulator non-membership failed: element prime is not coprime to accumulator set.")

        if a < 0:
            inv_g = pow(self.g, -1, self.N)
            d = pow(inv_g, -a, self.N)
        else:
            d = pow(self.g, a, self.N)

        return {
            "element": element,
            "prime_representative": hex(x)[2:],
            "d": hex(d)[2:],
            "b": str(b),
            "accumulator_id": self.id
        }

    @classmethod
    def verify_witness(
        cls,
        witness: Dict[str, str],
        current_accumulator_hex: str,
        modulus_hex: str = DEFAULT_MODULUS_HEX
    ) -> bool:
        """Verifies an O(1) membership witness against the current accumulator value."""
        try:
            n = int(modulus_hex, 16)
            w = int(witness["witness"], 16)
            prime = int(witness["prime_representative"], 16)
            v = int(current_accumulator_hex, 16)

            expected_prime = cls.element_to_prime(witness["element"])
            if expected_prime != prime:
                return False

            computed_v = pow(w, prime, n)
            return computed_v == v
        except Exception:
            return False

    @classmethod
    def verify_non_membership_witness(
        cls,
        witness: Dict[str, str],
        current_accumulator_hex: str,
        generator_hex: str = DEFAULT_GENERATOR_HEX,
        modulus_hex: str = DEFAULT_MODULUS_HEX
    ) -> bool:
        """
        Verifies an O(1) Non-Membership Witness.
        Verification Equation: (d^x) * (V^b) === g (mod N)
        """
        try:
            n = int(modulus_hex, 16)
            g = int(generator_hex, 16)
            d = int(witness["d"], 16)
            x = int(witness["prime_representative"], 16)
            b = int(witness["b"])
            v = int(current_accumulator_hex, 16)

            expected_prime = cls.element_to_prime(witness["element"])
            if expected_prime != x:
                return False

            dx = pow(d, x, n)
            if b < 0:
                inv_v = pow(v, -1, n)
                vb = pow(inv_v, -b, n)
            else:
                vb = pow(v, b, n)

            lhs = (dx * vb) % n
            return lhs == (g % n)
        except Exception:
            return False

    def export_state(self) -> Dict[str, Any]:
        """Exports the accumulator state."""
        return {
            "id": self.id,
            "modulus": hex(self.N)[2:],
            "generator": hex(self.g)[2:],
            "accumulator": hex(self.V)[2:],
            "member_count": len(self.members)
        }
