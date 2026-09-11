"""
Cryptomath for number theory.

This module is not a cipher. It is the custom implementations of functions
needed for cyptography. These include gcd and extended_gcd.

gcd decides whether a cipher key is usable in ciphers like an Affine multiplier.
extended_gcd then finds the inverse, which is very useful when decrypting.

Theory
The greatest common divisor of two integers ``a`` and ``b`` is the largest
integer that divides both.

The Euclidean algorithm computes it by knowing that ``a`` and ``b``
share exactly the same divisors as ``b`` and ``a mod b``. Dividing ``a`` by
``b`` leaves a remainder that is a combination of the two, so nothing about the
common divisors is lost. Each step shrinks the problem until the remainder is
zero making the last nonzero remainder the gcd.

Bezout's identity is the other fact here. For any ``a`` and ``b`` there exist
integers ``x`` and ``y`` such that ax + by = gcd(a, b)
extended_gcd returns ``gcd(a, b)`` together with such ``x`` and ``y``.
The ``x`` it produces is the coefficient that turns a linear congruence
``ax = c (mod b)`` into a solvable statement, and when ``gcd(a, b) = 1`` it is
the modular inverse of ``a`` mod ``b``.
"""

__all__ = ["extended_gcd", "find_mod_inverse", "gcd", "prime_factors"]


def gcd(a: int, b: int) -> int:
    """
    Return the greatest common divisor of ``a`` and ``b``.
    Implements the Euclidean algorithm.  replace ``(a, b)`` with
    ``(b, a mod b)`` while ``b`` is nonzero; the last nonzero divisor is the gcd.

    Parameters
    a, b:
        Integers to combine. Negative inputs are handled using their absolute
        values

    Returns
    int
        The largest integer dividing both ``a`` and ``b``.
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Return ``(g, x, y)`` such that ``ax + by = g = gcd(a, b)``.

    This is the extended Euclidean algorithm. It uses Bezout coefficients
    through the same remainder steps as gcd at every step the current
    pair ``(a, b)`` stays a combination of the original ``a`` and ``b``, so the
    coefficients accumulated along the way describe the final remainder exactly.

    Parameters
    a, b:
        Integers to combine.

    Returns
    tuple of int
        ``(g, x, y)`` — the gcd plus one Bezout pair. When ``gcd(a, b) == 1``,
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
    Return the modular inverse of ``a`` mod ``n``.

    This is the function extended_gcd specialized for solving ``ax = 1 (mod n)``.
    Where extended_gcd must be faithful to every Bezout triple, here we may
    take shortcuts, because we only care about ``a``'s own inverse.

    Theory
    The inverse exists exactly when ``a`` is coprime with ``n``, i.e.
    ``gcd(a, n) == 1``. That is because ``ax = 1 (mod n)`` is solvable only
    when the linear congruence has a solution at all, and by the theory of
    linear Diophantine equations the congruence ``ax = 1`` is solvable
    when ``gcd(a, n)`` divides 1. So the gcd test is both the
    existence check and, when it passes, guarantees the inverse is unique
    modulo ``n``.

    Parameters
    a:
        The integer whose inverse is sought. It is reduced modulo ``n`` first,
        so callers may pass negatives or values larger than ``n``.
    n:
        The modulus, which must be at least 2.

    Returns
    int
        The inverse ``x`` in ``0 <= x < n`` such that ``(ax) mod n == 1``.
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


def prime_factors(n: int) -> list[int]:
    """
    Return the list of prime factors of ``n`` whose product is ``n``.

    Every integer ``n >= 2`` is a product of primes, and the Fundamental
    Theorem of Arithmetic says that product is unique up to the order of the
    factors. This function recovers it by division. It peels off the
    smallest possible factor at each step, dividing ``n`` by it until the
    divisor no longer fits, then moves the divisor up. Because it works from
    the smallest primes outward, whatever factor it finds next is guaranteed
    prime because any smaller divisor would already have been divided out, so there
    is nothing left to divide it. The result comes back in ascending order.

    Parameters
    n:
        The composite number to factor. Must be at least 2.

    Returns
    list of int
        The primes, in ascending order, that multiply together to give ``n``.
        A prime input comes back as a one-element list of itself.

    Raises
    ValueError
        If ``n < 2``, since the concept of a prime factorization starts at 2.
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


# Run the module if not imported
if __name__ == "__main__":
    print(gcd(12345678987654321, 100))
    print(gcd(4883, 4369))
    print(prime_factors(4883))
    print(prime_factors(4369))
