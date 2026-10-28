import tempfile
import unittest
from pathlib import Path

from src.deploysafe.report import generate_report


class TestDeploySafeReport(unittest.TestCase):

    def test_critical_finding_blocks_report(self):
        findings = [
            {
                "severity": "CRITICAL",
                "resource": "aws_s3_bucket_acl.public_bucket",
                "rule": "PUBLIC_S3_ACL",
                "message": "S3 ACL allows public read access."
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.md"
            result = generate_report(findings, str(output))
            report = result.read_text()

        self.assertIn("BLOCKED", report)
        self.assertIn("PUBLIC_S3_ACL", report)
        self.assertIn("Critical: **1**", report)

    def test_safe_plan_passes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.md"
            result = generate_report([], str(output))
            report = result.read_text()

        self.assertIn("PASSED", report)
        self.assertIn("Total findings: **0**", report)
        self.assertIn("No findings detected", report)

    def test_multiple_findings_are_counted(self):
        findings = [
            {
                "severity": "HIGH",
                "resource": "aws_s3_bucket.example",
                "rule": "RESOURCE_DELETION",
                "message": "Resource will be deleted."
            },
            {
                "severity": "MEDIUM",
                "resource": "aws_instance.example",
                "rule": "CUSTOM_CHECK",
                "message": "Review this resource."
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.md"
            result = generate_report(findings, str(output))
            report = result.read_text()

        self.assertIn("Total findings: **2**", report)
        self.assertIn("High: **1**", report)
        self.assertIn("Medium: **1**", report)


if __name__ == "__main__":
    unittest.main()
