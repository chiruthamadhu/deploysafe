import json
import sys


def analyze_plan(plan):
    findings = []

    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "unknown")
        change = resource.get("change", {})
        actions = change.get("actions", [])
        after = change.get("after") or {}
        before = change.get("before") or {}

        if "delete" in actions:
            findings.append({
                "severity": "HIGH",
                "resource": address,
                "rule": "RESOURCE_DELETION",
                "message": f"Resource has destructive action: {', '.join(actions)}"
            })

        if after.get("acl") == "public-read":
            findings.append({
                "severity": "CRITICAL",
                "resource": address,
                "rule": "PUBLIC_S3_ACL",
                "message": "S3 ACL allows public read access."
            })

        if (
            "server_side_encryption_configuration" in before
            and not after.get("server_side_encryption_configuration")
            and "delete" not in actions
        ):
            findings.append({
                "severity": "HIGH",
                "resource": address,
                "rule": "ENCRYPTION_REMOVED",
                "message": "Existing server-side encryption configuration may be removed."
            })

    return findings


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <terraform-plan.json>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], encoding="utf-8") as file:
            plan = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read plan JSON: {error}", file=sys.stderr)
        sys.exit(2)

    findings = analyze_plan(plan)

    print(json.dumps({
        "finding_count": len(findings),
        "findings": findings
    }, indent=2))

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
