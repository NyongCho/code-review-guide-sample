import unittest
from src.total import total_cents


class RepeatedTotalTests(unittest.TestCase):
    def test_repeated_amounts_are_included(self):
        self.assertEqual(total_cents([100, 100]), 200)
