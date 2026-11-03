"""Existing fictional LarchTrace evidence renderer; policy support is not built yet."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import typing


def render_value(value: typing.Any) -> typing.Any:
    """Copy nested JSON, sorting object keys and preserving array order and types."""
    if isinstance(value, dict):
        return {key: render_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [render_value(item) for item in value]
    return value

def redact_value(value: typing.Any , keys: list[str] , path: str, redacted_paths: list[str]) -> typing.Any:
    """Recursively redact matching keys and collect their JSON Pointer paths."""
    if isinstance(value, dict):
        result = {}

        for key in sorted(value):
            escaped_key = key.replace("~", "~0").replace("/", "~1")
            child_path = f"{path}/{escaped_key}"

            if key in keys:
                result[key] = "[REDACTED]"
                redacted_paths.append(child_path)
            else:
                result[key] = redact_value(
                    value[key], keys, child_path, redacted_paths
                )

        return result

    if isinstance(value, list):
        return [
            redact_value(item, keys, f"{path}/{index}", redacted_paths)
            for index, item in enumerate(value)
        ]

    return value


def validate_records(records: typing.Any) -> list[dict[str, typing.Any]]:
    """Validate identity and evidence presence without echoing supplied values."""
    if isinstance(records, list) is False:
        raise ValueError("records must be an array")
    seen: set[str] = set()
    for index, record in enumerate(records):
        if isinstance(record, dict) is False:
            raise ValueError(f"record {index}: expected object")
        identity = record.get("record_id")
        if isinstance(identity, str) is False or identity.strip() == "":
            raise ValueError(f"record {index}: expected nonblank record_id")
        if identity in seen:
            raise ValueError(f"record {index}: duplicate record_id")
        seen.add(identity)
        if "evidence" not in record:
            raise ValueError(f"record {index}: missing evidence")
    return records


def validate_redaction_policy(policy: typing.Any) -> list[str]:
    if not isinstance(policy, dict):
        raise ValueError("invalid redaction_policy")

    if set(policy.keys()) != {"keys"}:
        raise ValueError("invalid redaction_policy")

    keys = policy["keys"]

    if not isinstance(keys, list):
        raise ValueError("invalid redaction_policy")

    if any(not isinstance(key, str) or key == "" for key in keys):
        raise ValueError("invalid redaction_policy")

    if len(keys) != len(set(keys)):
        raise ValueError("invalid redaction_policy")

    return keys



def render_evidence(payload: dict[str, typing.Any], arguments: argparse.Namespace) -> dict[str, typing.Any]:
    """Render records; unknown envelope and record fields are ignored."""

    keys = None

    if "redaction_policy" in payload:
        keys = validate_redaction_policy(payload["redaction_policy"])

    records = validate_records(payload.get("records"))
    ordered = sorted(records, key=lambda record: record["record_id"])

    items: list[dict[str, typing.Any]] = []
    redacted_paths: list[str] = []

    for index, record in enumerate(ordered):
        if keys is None:
            evidence = render_value(record["evidence"])
        else:
            evidence = redact_value(
                record["evidence"],
                keys,
                f"/records/{index}/evidence",
                redacted_paths
            )

        items.append({
            "record_id": record["record_id"],
            "evidence": evidence,
        })

    result = {
        "records": items,
        "summary": {"records": len(items)}
    }

    if keys is not None:
        result["redaction"] = {
            "count": len(redacted_paths),
            "paths": sorted(redacted_paths)
        }

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a fictional structured scanner evidence batch.")
    parser.add_argument("--input", default="inputs/primary.json", help="UTF-8 fixture JSON")
    arguments = parser.parse_args()
    try:
        payload = json.loads(pathlib.Path(arguments.input).read_text(encoding="utf-8"))
        if isinstance(payload, dict) is False:
            raise ValueError("input must be a JSON object")
        result = render_evidence(payload, arguments)
        print(json.dumps(result, indent=1, sort_keys=True, ensure_ascii=True))
    except NotImplementedError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
