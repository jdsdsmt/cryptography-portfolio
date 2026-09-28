"""
Number theory helpers.

This module is not a cipher. It has the number theory functions needed for
cryptography: gcd, extended_gcd, the totient phi, prime factoring, and the
primitive root functions.

gcd tells you if an Affine multiplier is usable. extended_gcd then finds
the modular inverse, which is the main thing you need when decrypting.
"""

from collections.abc import Sequence

__all__ = [
    "all_primitive_roots",
    "extended_gcd",
    "find_mod_inverse",
    "gcd",
    "has_primitive_root",
    "phi",
    "prime_factors",
    "primitive_root",
    "smallest_primitive_root",
    "solve_crt",
]


def gcd(a: int, b: int) -> int:
    """
    Return the greatest common divisor of ``a`` and ``b``.

    Uses the Euclidean algorithm: swap ``(a, b)`` for ``(b, a mod b)`` while
    ``b`` is not zero. The last nonzero divisor is the gcd.

    Parameters
    a, b:
        The numbers to combine. Negative inputs use their absolute values.

    Returns
    int
        The largest integer that divides both ``a`` and ``b``.
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Return ``(g, x, y)`` such that ``ax + by = g = gcd(a, b)``.

    This is the extended Euclidean algorithm. It does the same remainder steps
    as gcd, but keeps track of the coefficients too.

    Parameters
    a, b:
        The numbers to combine.

    Returns
    tuple of int
        ``(g, x, y)``: the gcd plus one Bezout pair. When ``gcd(a, b) == 1``,
        ``x`` is the modular inverse of ``a`` mod ``b``.
    """
    # (old_remainder, new_remainder)
    old_r, r = a, b
    # (old_x, old_y) and (new_x, new_y): coefficients for a and b respectively.
    old_s, s = 1, 0
    old_t, t = 0, 1
    # While we still have a remainder, we need to keep going
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    # At this point, we have the solution
    return old_r, old_s, old_t


def find_mod_inverse(a: int, n: int) -> int:
    """
    Return the modular inverse of ``a`` mod ``n``, i.e. the ``x`` where
    ``(a * x) mod n == 1``.

    This just uses extended_gcd to solve ``ax = 1 (mod n)``. The inverse exists
    only when ``a`` is coprime with ``n`` (``gcd(a, n) == 1``), which is also the
    only case the inverse is even defined.

    Parameters
    a:
        The number you want the inverse of. It is reduced mod ``n`` first, so
        you can pass negatives or numbers bigger than ``n``.
    n:
        The modulus, which must be at least 2.

    Returns
    int
        The inverse ``x`` in ``0 <= x < n``.
    Raises
        ValueError
            If ``a`` has no modular inverse (``gcd(a, n) != 1``).
        ValueError
            If ``n < 2``, since no modular system exists below a modulus of 2.
    """
    if n < 2:
        raise ValueError(f"Modulus must be at least 2! Got {n}")
    # Solve the extended gcd to find the pairs
    # We only care about the inverse and gcd
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"{a % n} has no modular inverse mod {n} (gcd is {g}, not 1)")
    return x % n


def solve_crt(residues: Sequence[int], moduli: Sequence[int]) -> tuple[int, int]:
    """
    Return ``(x, m)`` solving the system of congruences in ``residues`` and
    ``moduli`` (the Chinese Remainder Theorem).

    ``x`` satisfies every ``x congruent residues[i] (mod moduli[i])``, and the
    pair is unique mod ``m``, the product of the moduli. The moduli have to be
    pairwise coprime (no two share a factor) for this to work.

    Parameters
    residues:
        The remainders, one per congruence, in order.
    moduli:
        The moduli, one per congruence, in order. Must be pairwise coprime and
        at least two in number. A single modulus is accepted and returned
        unchanged.

    Returns
    tuple of int
        ``(x, m)`` where ``x`` is the unique solution in
        ``0 <= x < m`` and ``m`` is the product of the moduli.

    Raises
        ValueError
            If ``moduli`` is empty, or any modulus is below 2, or any pair of
            moduli shares a factor.
    """
    if not moduli:
        raise ValueError("at least one modulus is required")
    if any(n < 2 for n in moduli):
        raise ValueError("every modulus must be at least 2")
    if len(moduli) != len(residues):
        raise ValueError("residues and moduli must have the same length")
    if len(moduli) == 1:
        # A single congruence is its own answer, reduced form.
        return residues[0] % moduli[0], moduli[0]

    # Pairwise coprime the theorem's precondition.
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(
                    f"moduli must be pairwise coprime (moduli[{i}]={moduli[i]} "
                    f"and moduli[{j}]={moduli[j]} share a factor)"
                )

    m = 1
    for n in moduli:
        m *= n

    # Accumulate one CRT term per congruence, then reduce mod the product.
    x = 0
    for r, n in zip(residues, moduli):
        m_i = m // n  # product of all moduli except this one
        inverse = find_mod_inverse(m_i, n)  # m_i inverser mod n, needed to cancel m_i
        x += r * m_i * inverse  # term that carries residue r mod n
    return x % m, m


def prime_factors(n: int) -> list[int]:
    """
    Return the list of prime factors of ``n`` that multiply to give ``n``.

    Just divides ``n`` by the smallest possible factor each time and moves up
    until no more divide evenly. Works from small primes up, so anything it
    finds next is guaranteed prime. Comes back in ascending order.

    Parameters
    n:
        The number to factor. Must be at least 2.

    Returns
    list of int
        The prime factors in ascending order. A prime input just comes back as
        a one-element list of itself.

    Raises
    ValueError
        If ``n < 2``, since factoring starts at 2.
    """
    # Ensure domain
    if n < 2:
        raise ValueError(f"Cannot factor {n}! Need at least 2")
    factors: list[int] = []
    divisor = 2

    # The main division loop
    while divisor * divisor <= n:
        # pull out all the factors of this prime
        while n % divisor == 0:
            factors.append(divisor)
            n //= divisor
        divisor += 1
    # If we didn't start with a prime, add n to the list
    if n > 1:
        factors.append(n)
    return factors


def phi(n: int) -> int:
    """
    Return Euler's totient of ``n``: how many numbers from 1 to n are coprime
    with n (share no common factor except 1).

    Uses Euler's product formula: multiply n by (1 - 1/p) for each distinct
    prime factor p. Each prime is only counted once no matter how many times it
    divides n.

    Parameters
    n:
        The modulus. Must be at least 1.

    Returns
    int
        ``1`` when ``n`` is 1, otherwise the count of residues coprime with
        ``n``.

    Raises
        ValueError
            If ``n < 1``, since the totient is only defined for positive
            integers.
    """
    if n < 1:
        raise ValueError(f"totient undefined for {n}! Need at least 1")
    if n == 1:
        return 1
    # Apply (1 - 1/p) once per distinct prime factor of n.
    result = n
    for p in set(prime_factors(n)):
        result = result // p * (p - 1)
    return result


def has_primitive_root(n: int) -> bool:
    """
    Return whether ``n`` has a primitive root, which happens when the
    multiplicative group mod ``n`` is cyclic (can be made from one generator).

    Cyclic only for ``n = 1, 2, 4, p**k`` and ``2 * p**k`` where ``p`` is an
    odd prime. Higher powers of 2 (like 8, 16) are not cyclic, so no.

    Parameters
    n:
        The modulus. Must be at least 1.

    Returns
    bool
        ``True`` when a primitive root exists for ``n``, ``False`` otherwise.

    Raises
        ValueError
            If ``n < 1``, since no multiplicative structure exists below it.
    """
    if n < 1:
        raise ValueError(f"No primitive root structure for {n}! Need at least 1")
    if n in (1, 2):
        # Trivial groups: the single element generates.
        return True
    if n == 4:
        return True
    if n % 2 == 0:
        # Even modulus cyclic only when it is 2 * (odd prime power).
        if n % 4 == 0:
            return False
        return _is_prime_power(n // 2)
    return _is_prime_power(n)


def _is_prime_power(n: int) -> bool:
    """Whether ``n >= 2`` is a power of a single prime, ``p**k``.

    Returns False for powers of 2 because those are filtered out by
    ``has_primitive_root`` before this is reached (2 is the only even one that
    counts, and that's handled there).
    """
    factors = set(prime_factors(n))
    if len(factors) != 1:
        return False
    (p,) = factors
    return p != 2


def _has_order(a: int, order: int, n: int) -> bool:
    """Whether ``a`` has multiplicative order exactly ``order`` modulo ``n``.

    The order always divides the group's size, so ``a`` generates only when
    ``a**(size / q)`` is not 1 mod ``n`` for each prime factor ``q`` of the
    size. If any of those powers is 1, the true order is smaller.
    """
    reduced = a % n
    if gcd(reduced, n) != 1:
        return False
    # The order test scans the prime factors of the group's order. The trivial
    # group (order 1, i.e. n in 1 and 2) has none, so its single coprime
    # residue generates and the check is simply True.
    if order == 1:
        return True
    for q in prime_factors(order):
        if pow(reduced, order // q, n) == 1:
            return False
    return True


def primitive_root(a: int, p: int) -> bool:
    """
    Return whether ``a`` is a primitive root modulo ``p``, i.e. whether it
    generates the whole multiplicative group mod ``p``.

    A primitive root has order ``p - 1`` (the biggest order anything can have).
    Fermat's little theorem guarantees ``a**(p-1)`` is 1 mod ``p``, but we also
    need no smaller power to be 1. We only check ``a**((p-1)/q)`` for the prime
    factors ``q`` of ``p - 1``; if none of those is 1, then the order is full.

    Parameters
    a:
        The candidate generator. Any integer; it is reduced modulo ``p`` first.
    p:
        The modulus, which must be at least 2.

    Returns
    bool
        ``True`` when ``a`` has order ``p - 1`` mod ``p`` and so generates the
        group, ``False`` otherwise.

    Raises
        ValueError
            If ``p < 2``, since there is no multiplicative group below a
            modulus of 2.
    """
    if p < 2:
        raise ValueError(f"Modulus must be at least 2! Got {p}")
    # A primitive root mod p has order p - 1, the full multiplicative group.
    return _has_order(a % p, p - 1, p)


def smallest_primitive_root(n: int) -> int:
    """
    Return the smallest primitive root modulo ``n``, or 0 when none exists.

    Primitive roots come in families: if ``g`` is one, every other is a power
    of it (with an exponent coprime with the group order ``phi(n)``). The
    family is empty when ``has_primitive_root`` is False, so we scan upward from
    1 and return the first thing that has full order.

    Parameters
    n:
        The modulus. Must be at least 1.

    Returns
    int
        The smallest generator of the multiplicative group mod ``n``, or ``0``
        when that group is not cyclic.

    Raises
        ValueError
            If ``n < 1``, since there is no structure below it.
    """
    if n < 1:
        raise ValueError(f"No primitive root structure for {n}! Need at least 1")
    if not has_primitive_root(n):
        return 0
    order = phi(n)
    if order == 1:
        # Trivial group (n in 1 and 2): the single residue is its generator.
        return 1 if n != 1 else 0
    for a in range(1, n):
        if _has_order(a, order, n):
            return a
    return 0


def all_primitive_roots(n: int) -> list[int]:
    """
    Return every primitive root modulo ``n``, sorted ascending.

    Lists all generators of the multiplicative group mod ``n``. There are
    exactly ``phi(phi(n))`` of them when a primitive root exists. The list is
    just every number from 1 to n-1 that has full order ``phi(n)``.

    Parameters
    n:
        The modulus. Must be at least 1.

    Returns
    list of int
        Every generator, in ascending order; empty when ``n`` has no primitive
        root.

    Raises
        ValueError
            If ``n < 1``, since there is no structure below it.
    """
    if n < 1:
        raise ValueError(f"No primitive root structure for {n}! Need at least 1")
    if not has_primitive_root(n):
        return []
    order = phi(n)
    if order == 1:
        # Trivial group (n in 1 and 2): the single residue is its generator.
        return [1] if n != 1 else [0]
    return [a for a in range(1, n) if _has_order(a, order, n)]


# Run the module if not imported
if __name__ == "__main__":
    print(gcd(12345678987654321, 100))
    print(gcd(4883, 4369))
    print(prime_factors(4883))
    print(prime_factors(4369))
    print(primitive_root(2, 5))
    print(primitive_root(1, 5))
    print(solve_crt([2, 3, 2], [3, 5, 7]))
