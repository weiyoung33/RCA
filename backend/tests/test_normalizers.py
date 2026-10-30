import unittest

from app.normalizers import normalize_proposer, sha256_text


class NormalizerTests(unittest.TestCase):
    def test_current_proposer_json_is_normalized(self):
        result = normalize_proposer(
            '{"proposed_root_cause":"Worker crashed",'
            '"proposed_actionable_fix":"Review memory",'
            '"historical_confidence_score":92,'
            '"is_historical_match":true}',
            "## Proposed Actionable Fix\nSee ai_proposed_root_cause for fix details.",
        )
        self.assertEqual(result["root_cause"], "Worker crashed")
        self.assertEqual(result["actionable_fix"], "Review memory")
        self.assertEqual(result["historical_confidence_score"], 92)
        self.assertTrue(result["is_historical_match"])

    def test_legacy_text_is_preserved(self):
        result = normalize_proposer("A textual cause", "A textual fix")
        self.assertEqual(result["root_cause"], "A textual cause")
        self.assertEqual(result["actionable_fix"], "A textual fix")

    def test_hash_is_stable(self):
        self.assertEqual(sha256_text("abc"), sha256_text("abc"))
        self.assertNotEqual(sha256_text("abc"), sha256_text("abcd"))


if __name__ == "__main__":
    unittest.main()
