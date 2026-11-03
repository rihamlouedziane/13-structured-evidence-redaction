from app import redact_value
import unittest
import json
import textwrap
from test_helpers import run_app, run_app_with_payload


class RedactionMaskingTests(unittest.TestCase):

    def testLegacy_whenNoPolicy_preservesOriginalBehavior(self):
        result = run_app("--input", "inputs/legacy.json")

        expected_output = textwrap.dedent("""\
            {
             "records": [
              {
               "evidence": {
                "a": [
                 0,
                 null,
                 {
                  "text": "caf\\u00e9"
                 }
                ],
                "z": false
               },
               "record_id": " L02 "
              },
              {
               "evidence": {
                "empty": {},
                "value": "  keep spaces  "
               },
               "record_id": "L01"
              }
             ],
             "summary": {
              "records": 2
             }
            }
            """)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, expected_output)

    def testRedaction_whenKeyMatches_replacesItsValue(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["token"]},
            "records": [
                {
                    "record_id": "R01",
                    "evidence": {
                        "token": "DEMO-SECRET",
                        "name": "Riham"
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)

        self.assertEqual(
            output["records"][0]["evidence"]["token"],
            "[REDACTED]"
        )
        self.assertEqual(
            output["records"][0]["evidence"]["name"],
            "Riham"
        )

    def testRedaction_whenKeyIsNested_masksItsValue(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["password"]},
            "records": [
                {
                    "record_id": "R02",
                    "evidence": {
                        "user": {
                            "name": "Salma",
                            "credentials": {
                                "password": "DEMO-PASSWORD"
                            }
                        }
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)
        evidence = output["records"][0]["evidence"]

        self.assertEqual(
            evidence["user"]["credentials"]["password"],
            "[REDACTED]"
        )
        self.assertEqual(
            evidence["user"]["name"],
            "Salma"
        )

    def testRedaction_whenKeyIsInsideArray_masksItsValue(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["password"]},
            "records": [
                {
                    "record_id": "R03",
                    "evidence": {
                        "users": [
                            {
                                "name": "Yassine",
                                "password": "DEMO-YASSINE"
                            },
                            {
                                "name": "Amine",
                                "password": "DEMO-AMINE"
                            }
                        ]
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)
        users = output["records"][0]["evidence"]["users"]

        self.assertEqual(users[0]["password"], "[REDACTED]")
        self.assertEqual(users[1]["password"], "[REDACTED]")

        self.assertEqual(users[0]["name"], "Yassine")
        self.assertEqual(users[1]["name"], "Amine")

    
    def testRedaction_whenValueIsFalsy_masksItRegardlessOfValue(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["password"]},
            "records": [
                {
                    "record_id": "R04",
                    "evidence": {
                        "passwords": [
                            {"password": None},
                            {"password": False},
                            {"password": 0},
                            {"password": ""}
                        ]
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)
        passwords = output["records"][0]["evidence"]["passwords"]

        for item in passwords:
            self.assertEqual(item["password"], "[REDACTED]")

        
    def testRedaction_whenKeyCaseDiffers_masksOnlyExactMatch(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["password"]},
            "records": [
                {
                    "record_id": "R05",
                    "evidence": {
                        "password": "DEMO-SECRET-1",
                        "Password": "DEMO-SECRET-2",
                        "PASSWORD": "DEMO-SECRET-3"
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)
        evidence = output["records"][0]["evidence"]

        self.assertEqual(evidence["password"], "[REDACTED]")
        self.assertEqual(evidence["Password"], "DEMO-SECRET-2")
        self.assertEqual(evidence["PASSWORD"], "DEMO-SECRET-3")

    
    def testRedaction_whenMatchedValueIsObject_replacesEntireObject(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["credentials"]},
            "records": [
                {
                    "record_id": "R06",
                    "evidence": {
                        "user": {
                            "name": "Riham",
                            "credentials": {
                                "password": "DEMO-PASSWORD",
                                "token": "DEMO-TOKEN"
                            }
                        }
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)
        evidence = output["records"][0]["evidence"]

        self.assertEqual(
            evidence["user"]["credentials"],
            "[REDACTED]"
        )

        self.assertEqual(evidence["user"]["name"], "Riham")


    def testRedaction_whenMatchedValueIsArray_replacesEntireArray(self):
        result = run_app_with_payload({
            "redaction_policy": {"keys": ["sessions"]},
            "records": [
                {
                    "record_id": "R07",
                    "evidence": {
                        "user": {
                            "name": "Yassine",
                            "sessions": [
                                "DEMO-SESSION-1",
                                "DEMO-SESSION-2"
                            ]
                        }
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        output = json.loads(result.stdout)
        evidence = output["records"][0]["evidence"]

        self.assertEqual(
            evidence["user"]["sessions"],
            "[REDACTED]"
        )

        self.assertEqual(evidence["user"]["name"], "Yassine")



    def testRedaction_whenSecretIsMasked_doesNotAppearInOutput(self):
        secret = "DEMO-SECRET-RIHAM"

        result = run_app_with_payload({
            "redaction_policy": {"keys": ["token"]},
            "records": [
                {
                    "record_id": "R08",
                    "evidence": {
                        "token": secret,
                        "name": "Riham"
                    }
                }
            ]
        })

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)


    def testRedaction_whenCalledRepeatedly_preservesOriginalData(self):
        evidence = {
            "name": "Riham",
            "token": "DEMO-TOKEN",
            "user": {
                "password": "DEMO-PASSWORD"
            }
        }

        original_evidence = json.loads(json.dumps(evidence))

        first_result = redact_value(
            evidence,
            ["token", "password"],
            "/records/0/evidence",
            []
        )

        second_result = redact_value(
            evidence,
            ["token", "password"],
            "/records/0/evidence",
            []
        )

        self.assertEqual(evidence, original_evidence)
        self.assertEqual(first_result, second_result)

if __name__ == "__main__":
    unittest.main()
