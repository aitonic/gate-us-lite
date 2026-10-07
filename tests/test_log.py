import unittest

from gate_us_lite.log import tally


class TestTally(unittest.TestCase):
    def test_most_frequent_reasons_come_first_and_are_capped(self):
        reasons = ["a"] * 3 + ["b"] * 2 + list("cdefg")
        self.assertEqual(tally(reasons), "3x a; 2x b; 1x c; 1x d; 1x e")
        self.assertEqual(tally(reasons + ["g"] * 4), "5x g; 3x a; 2x b; 1x c; 1x d")
        self.assertEqual(tally(reasons, top=1), "3x a")

    def test_no_reasons_give_an_empty_string(self):
        self.assertEqual(tally([]), "")


if __name__ == "__main__":
    unittest.main()
