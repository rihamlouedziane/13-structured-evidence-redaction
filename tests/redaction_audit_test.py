
import unittest
import json
from test_helpers import run_app_with_payload


class RedactionAuditTests(unittest.TestCase):

    def testAudit_whenValuesAreRedacted_returnsCountAndPaths(self):
        result = run_app_with_payload({
            "redaction_policy": {
                "keys": ["token", "password"]
            },
            "records": [
                {
                    "record_id": "R02",
                    "evidence": {
                        "token": "DEMO-TOKEN"
                    }
                },
                {
                    "record_id": "R01",
                    "evidence": {
                        "password": "DEMO-PASSWORD"
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)

        self.assertEqual(
            output["redaction"],
            {
                "count": 2,
                "paths": [
                    "/records/0/evidence/password",
                    "/records/1/evidence/token"
                ]
            }
        )


if __name__ == "__main__":
    unittest.main()
