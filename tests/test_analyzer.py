import unittest

from src.deploysafe.analyzer import analyze_plan


class TestDeploySafe(unittest.TestCase):

    def test_detects_resource_deletion(self):
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.important_data",
                    "change": {
                        "actions": ["delete"],
                        "before": {"bucket": "important-data"},
                        "after": None
                    }
                }
            ]
        }

        findings = analyze_plan(plan)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "RESOURCE_DELETION")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_detects_public_s3_acl(self):
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket_acl.public_bucket",
                    "change": {
                        "actions": ["update"],
                        "before": {"acl": "private"},
                        "after": {"acl": "public-read"}
                    }
                }
            ]
        }

        findings = analyze_plan(plan)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "PUBLIC_S3_ACL")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_detects_encryption_removal(self):
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.data",
                    "change": {
                        "actions": ["update"],
                        "before": {
                            "server_side_encryption_configuration": [
                                {"rule": "AES256"}
                            ]
                        },
                        "after": {}
                    }
                }
            ]
        }

        findings = analyze_plan(plan)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "ENCRYPTION_REMOVED")

    def test_safe_plan_has_no_findings(self):
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.safe",
                    "change": {
                        "actions": ["no-op"],
                        "before": {"acl": "private"},
                        "after": {"acl": "private"}
                    }
                }
            ]
        }

        findings = analyze_plan(plan)

        self.assertEqual(findings, [])

    def test_empty_plan_has_no_findings(self):
        self.assertEqual(analyze_plan({}), [])


if __name__ == "__main__":
    unittest.main()
