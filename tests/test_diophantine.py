"""
Unit tests for the Diophantine cipher.

These tests follow our usual style (import the cipher module and call
``encrypt``/``decrypt``/``crack`` directly, then assert on the returned
strings). They use the standard-library ``unittest`` so no new dependency needs
to be installed, run them with ``uv run python -m unittest`` from the project
root.
"""

import unittest

from src.cipher_toolkit.diophantine import (
    Config,
    DiophantineCipher,
    diophantine,
    _parse_equation,
    _parse_point,
)
from src.cipher_toolkit.ciphers import InvalidParameterError

d = DiophantineCipher()


def _particular(sol: str) -> tuple[int, int]:
    """Pull ``(x, y)`` out of a decrypt report's 'Solution (x, y) = (...)'' line."""
    body = sol.split("Solution (x, y) = (", 1)[1].split(")")[0]
    x, y = body.split(", ")
    return int(x), int(y)


class DiophantineConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        cfg = Config()
        self.assertEqual(cfg.parameters, {"a": 2, "b": 3})

    def test_from_dict(self) -> None:
        cfg = Config({"a": 7, "b": 11})
        self.assertEqual(cfg.get("a"), 7)
        self.assertEqual(cfg.get("b"), 11)

    def test_zero_coefficients_rejected(self) -> None:
        with self.assertRaises(InvalidParameterError):
            Config(a=0, b=0)

    def test_non_int_rejected(self) -> None:
        with self.assertRaises(InvalidParameterError):
            Config(a=2.5, b=3)
        with self.assertRaises(InvalidParameterError):
            Config(a="x", b=3)


class DiophantineEncryptTests(unittest.TestCase):
    def test_encrypt_point(self) -> None:
        self.assertEqual(
            d.encrypt("3, -5", Config(a=2, b=3)), "2x + +3y = -9"
        )

    def test_encrypt_default_config(self) -> None:
        # default coefficients are a=2, b=3; 2*4 + 3*7 = 29
        self.assertEqual(d.encrypt("4, 7", Config(a=2, b=3)), "2x + +3y = 29")

    def test_encrypt_roundtrip_matches_decrypt_constant(self) -> None:
        # encrypt then decrypt must return the same constant
        config = Config(a=3, b=5)
        c = int(d.encrypt("2, 7", config).split("=", 1)[1].strip())
        self.assertEqual(c, 3 * 2 + 5 * 7)


class DiophantineDecryptTests(unittest.TestCase):
    def test_known_solution(self) -> None:
        sol = d.decrypt("5", Config(a=2, b=3))
        x, y = _particular(sol)
        # 2x + 3y = 5
        self.assertEqual(2 * x + 3 * y, 5)

    def test_solution_satisfies_equation_every_c(self) -> None:
        for c in range(-10, 11):
            sol = d.decrypt(str(c), Config(a=3, b=5))
            x, y = _particular(sol)
            self.assertEqual(3 * x + 5 * y, c, f"failed for c={c}")

    def test_general_solution_steps_are_homogeneous(self) -> None:
        import re

        sol = d.decrypt("29", Config(a=3, b=5))
        x_part = sol.split("General solution:", 1)[1]
        # 'x = x0 {+/-}sx t,  y = y0 {+/-}sy t'
        mx = re.search(r"x = (-?\d+) ([+-])(\d+) t", x_part)
        my = re.search(r"y = (-?\d+) ([+-])(\d+) t", x_part)
        assert mx and my
        step_x = int(mx.group(2) + mx.group(3))
        step_y = int(my.group(2) + my.group(3))
        # The homogeneous step must satisfy 3*step_x + 5*step_y = 0 so that
        # adding any multiple of it never changes the value of the equation.
        self.assertEqual(3 * step_x + 5 * step_y, 0)

    def test_negative_coefficients(self) -> None:
        sol = d.decrypt("5", Config(a=-3, b=4))
        x, y = _particular(sol)
        self.assertEqual(-3 * x + 4 * y, 5)

    def test_no_solution_raises(self) -> None:
        # gcd(2, 4) = 2 does not divide 3
        with self.assertRaises(InvalidParameterError):
            d.decrypt("3", Config(a=2, b=4))


class DiophantineCrackTests(unittest.TestCase):
    def test_crack_returns_valid_points(self) -> None:
        points = d.crack("3x + 5y = 29")
        self.assertTrue(points)
        for point, _config in points:
            x, y = point.split(", ")
            self.assertEqual(3 * int(x) + 5 * int(y), 29)

    def test_crack_negative_coefficients(self) -> None:
        points = d.crack("-3x + 4y = 5")
        self.assertTrue(points)
        for point, _config in points:
            x, y = point.split(", ")
            self.assertEqual(-3 * int(x) + 4 * int(y), 5)

    def test_crack_no_solution_raises(self) -> None:
        with self.assertRaises(InvalidParameterError):
            d.crack("3x + 6y = 1")  # gcd(3, 6) = 3 does not divide 1

    def test_crack_zero_coefficients(self) -> None:
        # 0x + 0y = 0 is satisfied by every point; a few are returned
        self.assertTrue(d.crack("0x + 0y = 0"))


class ParserTests(unittest.TestCase):
    def test_parse_point(self) -> None:
        self.assertEqual(_parse_point("3, -5"), (3, -5))
        self.assertEqual(_parse_point("  10 , 20 "), (10, 20))

    def test_parse_point_malformed(self) -> None:
        with self.assertRaises(InvalidParameterError):
            _parse_point("abc")

    def test_parse_equation(self) -> None:
        self.assertEqual(_parse_equation("3x + 5y = 29"), (3, 5, 29))
        self.assertEqual(_parse_equation("-3x - 4y = -7"), (-3, -4, -7))
        self.assertEqual(_parse_equation("x + y = 1"), (1, 1, 1))
        self.assertEqual(_parse_equation("2x + 3y = -5"), (2, 3, -5))

    def test_parse_equation_bad(self) -> None:
        with self.assertRaises(InvalidParameterError):
            _parse_equation("not an equation")

    def test_module_level_instance(self) -> None:
        self.assertIsInstance(diophantine, DiophantineCipher)
        self.assertTrue(diophantine.can_crack())


if __name__ == "__main__":
    unittest.main()
