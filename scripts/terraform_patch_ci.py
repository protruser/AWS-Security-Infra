"""CI bridge: read local sensitive plan/state, emit only bounded non-secret metadata."""
import json
import os
import re
import sys
from datetime import datetime, timezone


def plan_summary(source, output):
    with open(source, encoding="utf-8") as stream:
        plan = json.load(stream)
    changes = {"create": [], "update": [], "delete": [], "replace": [], "read": [], "no-op": []}
    labels = {key: [] for key in changes}
    for item in plan.get("resource_changes", []):
        # Resource addresses may contain user-chosen keys. Record resource types
        # only; raw plan JSON and resource values never leave the runner.
        resource_type = item.get("type", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{1,100}", resource_type):
            raise ValueError("unsupported resource type")
        actions = item.get("change", {}).get("actions", [])
        kind = "replace" if set(actions) == {"create", "delete"} else actions[0] if len(actions) == 1 else None
        if kind not in changes:
            raise ValueError("unsupported plan action")
        changes[kind].append(resource_type)
        resource_name = item.get("name", "")
        if resource_name and not re.fullmatch(r"[A-Za-z0-9_]{1,100}", resource_name):
            raise ValueError("unsupported resource name")
        labels[kind].append(f"{resource_type}.{resource_name}" if resource_name else resource_type)
    # Full plan JSON contains secrets and is never an artifact.
    with open(output, "w", encoding="utf-8") as stream:
        json.dump({"counts": {key: len(value) for key, value in changes.items()},
                   "resources": changes, "labels": labels}, stream)


def _checkov_failures(path):
    """(check_id, file_path, resource) set from `checkov -o json` output."""
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    reports = data if isinstance(data, list) else [data]
    failures = set()
    for report in reports:
        # 지적 사항이 하나도 없으면 checkov 는 summary 만 있는 dict 를 낸다.
        for item in report.get("results", {}).get("failed_checks", []):
            failures.add((item["check_id"], item["file_path"], item["resource"]))
    return failures


def checkov_new(base_json, head_json):
    """패치가 새로 만든 Checkov 지적만 실패로 본다. 기존 코드의 지적은 base 에도 있으므로 제외된다.
    출력은 코드에서 나온 check ID/파일/리소스 이름뿐이라 공개 로그에 남겨도 된다."""
    base, head = _checkov_failures(base_json), _checkov_failures(head_json)
    new = sorted(head - base)
    print(f"checkov: base {len(base)} failed, head {len(head)} failed, new {len(new)}")
    for check_id, file_path, resource in new:
        print(f"  NEW {check_id} {file_path} {resource}")
    if new:
        raise SystemExit(1)


def manifest(output):
    def result(name):
        value = os.getenv(f"CHECK_{name.upper()}", "")
        dependency = {"validate": "INIT_STATIC", "tflint": "SETUP_TFLINT",
                      "checkov": "SETUP_CHECKOV", "plan": "AWS"}.get(name)
        prerequisite = os.getenv(f"CHECK_{dependency}", "success") if dependency else "success"
        if prerequisite == "failure":
            status = "ERROR"
        elif prerequisite in ("skipped", "cancelled"):
            status = "NOT_RUN"
        elif value == "success":
            status = "PASS"
        elif value == "failure":
            status = "FAIL"
        elif value in ("skipped", "cancelled", ""):
            status = "NOT_RUN"
        else:
            status = "ERROR"
        return {"status": status, "url": os.environ["RUN_URL"],
                "at": datetime.now(timezone.utc).isoformat()}
    results = {name: result(name) for name in ("fmt", "validate", "plan", "tflint", "checkov")}
    summary = json.load(open("/tmp/patch-plan-summary.json", encoding="utf-8")) if os.path.exists("/tmp/patch-plan-summary.json") else None
    state = json.load(open("/tmp/patch-state.json", encoding="utf-8")) if os.path.exists("/tmp/patch-state.json") else None
    value = {"patch_id": os.environ["PATCH_ID"], "head_sha": os.environ["HEAD_SHA"],
             "base_sha": os.environ["BASE_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
             "results": results, "plan_summary": summary, "state": state,
             "plan_sha256": os.getenv("PLAN_SHA256") or None,
             "plan_key": os.getenv("PLAN_KEY") or None,
             "plan_version_id": os.getenv("PLAN_VERSION_ID") or None}
    with open(output, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False)


if __name__ == "__main__":
    if sys.argv[1] == "plan-summary":
        plan_summary(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "manifest":
        manifest(sys.argv[2])
    elif sys.argv[1] == "checkov-new":
        checkov_new(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("unknown command")
