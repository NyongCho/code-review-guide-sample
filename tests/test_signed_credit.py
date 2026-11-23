import unittest
from src.total import total_cents


class SignedCreditTests(unittest.TestCase):
    def test_mixed_order_includes_credit(self):
        self.assertEqual(total_cents([100, -25]), 75)
