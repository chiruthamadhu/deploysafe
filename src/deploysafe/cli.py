import argparse
import json
import sys
from pathlib import Path

from src.deploysafe.analyzer import analyze_plan
from src.deploysafe.report import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="DeploySafe - Terraform Change Risk Analyzer"
    )
    parser.add_argument(
        "plan",
        help="Path to Terraform plan JSON file"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated reports (default: reports)"
    )

    args = parser.parse_args()
    plan_path = Path(args.plan)
    output_dir = Path(args.output_dir)

    try:
        with plan_path.open(encoding="utf-8") as file:
            plan = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Error reading plan: {error}", file=sys.stderr)
        return 2

    if not isinstance(plan, dict):
        print("Invalid plan: expected a JSON object.", file=sys.stderr)
        return 2

    findings = analyze_plan(plan)
    output_dir.mkdir(parents=True, exist_ok=True)

    findings_path = output_dir / "findings.json"
    findings_path.write_text(
        json.dumps(
            {"finding_count": len(findings), "findings": findings},
            indent=2
        ) + "\n",
        encoding="utf-8"
    )

    report_path = generate_report(
        findings,
        str(output_dir / "deploysafe-report.md")
    )

    print(f"Findings: {len(findings)}")
    print(f"JSON report: {findings_path}")
    print(f"Markdown report: {report_path}")

    if findings:
        print("Result: REVIEW REQUIRED - risks detected")
        return 1

    print("Result: PASSED - no findings detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
