import unittest
from src.total import total_cents


class SignedTotalTests(unittest.TestCase):
    def test_mixed_signed_amounts_are_net_total(self):
        self.assertEqual(total_cents([100, -25]), 75)
