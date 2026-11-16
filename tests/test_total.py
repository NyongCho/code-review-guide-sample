import unittest
from src.total import total_cents


class TotalTests(unittest.TestCase):
    def test_distinct_items(self):
        self.assertEqual(total_cents([100, 200]), 300)

    def test_empty_order(self):
        self.assertEqual(total_cents([]), 0)
