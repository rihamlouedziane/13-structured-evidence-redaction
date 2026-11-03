import unittest
from test_helpers import run_app_with_payload


class RedactionPolicyTests(unittest.TestCase):

    def assertInvalidPolicy(self, policy):
        result = run_app_with_payload({
            "redaction_policy": policy,
            "records": []
        })

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "error: invalid redaction_policy\n"
        )

    def testInvalidPolicy_whenPolicyIsNotObject_returnsError(self):
        for policy in [None, [], "keys", 123]:
            with self.subTest(policy=policy):
                self.assertInvalidPolicy(policy)

    def testInvalidPolicy_whenKeysFieldIsMissing_returnsError(self):
        self.assertInvalidPolicy({})

    def testInvalidPolicy_whenExtraFieldExists_returnsError(self):
        self.assertInvalidPolicy({
            "keys": ["token"],
            "extra": "value"
        })

    def testInvalidPolicy_whenKeysIsNotArray_returnsError(self):
        for keys in ["token", None, 123, {}]:
            with self.subTest(keys=keys):
                self.assertInvalidPolicy({"keys": keys})

    def testInvalidPolicy_whenKeyIsNotString_returnsError(self):
        self.assertInvalidPolicy({"keys": ["token", 123]})

    def testInvalidPolicy_whenKeyIsEmpty_returnsError(self):
        self.assertInvalidPolicy({"keys": ["token", ""]})

    def testInvalidPolicy_whenKeysContainDuplicates_returnsError(self):
        self.assertInvalidPolicy({
            "keys": ["token", "password", "token"]
        })

    def testInvalidPolicy_isValidatedBeforeRecords(self):
        result = run_app_with_payload({
            "redaction_policy": {
                "keys": ["token", "token"]
            },
            "records": "invalid records"
        })

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "error: invalid redaction_policy\n"
        )

    def testValidPolicy_whenKeysIsEmptyArray_returnsSuccess(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": []},
            "records": []
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

    def testValidPolicy_whenKeyContainsOnlySpaces_returnsSuccess(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["   "]},
            "records": []
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

    def testError_whenRecordsAreInvalid_doesNotExposeSensitiveValues(self):
        secret = "DEMO-SECRET-RIHAM"

        result = run_app_with_payload({
            "redaction_policy": {"keys": ["token"]},
            "records": [
                {
                    "record_id": "R01",
                    "evidence": {
                        "token": secret
                    }
                },
                {
                    "record_id": "R01",
                    "evidence": {}
                }
            ]
        })

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(secret, result.stderr)
        self.assertNotIn(secret, result.stdout)

if __name__ == "__main__":
    unittest.main()