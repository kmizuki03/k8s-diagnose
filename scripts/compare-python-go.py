#!/usr/bin/env python3
"""Compare Python and Go reports by stable diagnostic semantics.

Free-form wording and runtime-specific IDs are intentionally excluded. The
comparison covers CI-relevant severity/code/resource tuples, Health/Coverage,
and Root Cause classification/cause tuples.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Python/Go診断結果の意味差分")
    parser.add_argument(
        "--python",
        default=os.environ.get("K8S_DIAGNOSE_PYTHON"),
        help="比較するPython版のパス (またはK8S_DIAGNOSE_PYTHON)",
    )
    parser.add_argument("--go", default=str(root / "k8s-diagnose"))
    parser.add_argument("--mode", choices=("all", "triage"), default="triage")
    parser.add_argument("--namespace")
    parser.add_argument("--context")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--include-candidates", action="store_true")
    parser.add_argument(
        "--strict-coverage",
        action="store_true",
        help="診断項目数が異なる場合もCoverage百分率の完全一致を要求する",
    )
    # An extra invocation checks that the CLI exit code actually follows the
    # policy embedded in the report. It can be skipped for very large clusters.
    parser.add_argument("--skip-exit-code", action="store_true")
    args = parser.parse_args()
    if not args.python:
        parser.error("--python または K8S_DIAGNOSE_PYTHON を指定してください")
    return args


def command(
    path: str,
    runtime: str,
    args: argparse.Namespace,
    *,
    exit_zero: bool = True,
) -> list[str]:
    prefix = [sys.executable, path] if runtime == "Python" else [path]
    result = [*prefix, "--triage" if args.mode == "triage" else "-a", "--output", "json"]
    if exit_zero:
        result.append("--exit-zero")
    for option, value in (("--namespace", args.namespace), ("--context", args.context), ("--kubeconfig", args.kubeconfig)):
        if value:
            result.extend((option, value))
    return result


def run(path: str, runtime: str, args: argparse.Namespace) -> dict[str, Any]:
    cmd = command(path, runtime, args)
    completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if completed.returncode != 0:
        detail = " ".join(completed.stderr.split())[:500]
        raise RuntimeError(f"{runtime}版がexit {completed.returncode}: {detail}")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{runtime}版のJSONが不正: {exc}") from exc
    if document.get("schema") != "k8s-diagnose/report/v1":
        raise RuntimeError(f"{runtime}版のschemaが不正: {document.get('schema')}")
    return document


def policy_exit_code(path: str, runtime: str, args: argparse.Namespace) -> int:
    completed = subprocess.run(
        command(path, runtime, args, exit_zero=False),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode not in (0, 1):
        detail = " ".join(completed.stderr.split())[:500]
        raise RuntimeError(f"{runtime}版のCI実行がexit {completed.returncode}: {detail}")
    return completed.returncode


def finding_key(value: dict[str, Any]) -> tuple[str, str, str]:
    return str(value.get("severity") or ""), str(value.get("code") or ""), str(value.get("resource") or "")


def finding_counts(document: dict[str, Any], include_candidates: bool) -> Counter[tuple[str, str, str]]:
    return Counter(
        finding_key(value)
        for value in document.get("findings", [])
        if isinstance(value, dict) and (include_candidates or value.get("severity") != "candidate")
    )


def finding_confidences(
    document: dict[str, Any], include_candidates: bool
) -> Counter[tuple[str, str, str, str]]:
    return Counter(
        (*finding_key(value), str(value.get("confidence")))
        for value in document.get("findings", [])
        if isinstance(value, dict)
        and (include_candidates or value.get("severity") != "candidate")
    )


def root_counts(document: dict[str, Any]) -> Counter[tuple[str, ...]]:
    result: Counter[tuple[str, ...]] = Counter()
    for root in document.get("root_causes", []):
        if not isinstance(root, dict):
            continue
        cause = root.get("cause") if isinstance(root.get("cause"), dict) else {}
        impacts = sorted(
            str(impact.get("resource") or "")
            for group in ("direct_impacts", "propagated_impacts")
            for impact in root.get(group, [])
            if isinstance(impact, dict) and impact.get("resource")
        )
        result[
            (
                str(root.get("classification") or ""),
                str(root.get("confidence") or ""),
                str(cause.get("code") or ""),
                str(cause.get("resource") or ""),
                ",".join(impacts),
            )
        ] += 1
    return result


def ci_summary(document: dict[str, Any]) -> tuple[bool, tuple[tuple[str, int], ...]]:
    policy = document.get("policy") if isinstance(document.get("policy"), dict) else {}
    summary = document.get("summary") if isinstance(document.get("summary"), dict) else {}
    active = summary.get("active_findings") if isinstance(summary.get("active_findings"), dict) else {}
    counts = tuple((severity, int(active.get(severity, 0))) for severity in ("issue", "warning", "unavailable"))
    return bool(policy.get("would_fail")), counts


def coverage_summary(document: dict[str, Any]) -> tuple[int, int, int, int]:
    summary = document.get("summary") if isinstance(document.get("summary"), dict) else {}
    checks = summary.get("checks") if isinstance(summary.get("checks"), dict) else {}
    return (
        int(summary.get("coverage", 100)),
        int(checks.get("ok", 0)),
        int(checks.get("unavailable", 0)),
        int(checks.get("total", 0)),
    )


def print_counter(title: str, values: Counter[tuple[str, ...]]) -> None:
    if not values:
        return
    print(title)
    for value, count in sorted(values.items()):
        print(f"  {count} x {' | '.join(value)}")


def main() -> int:
    args = parse_args()
    try:
        python = run(args.python, "Python", args)
        go = run(args.go, "Go", args)
    except (OSError, RuntimeError) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1

    failed = False
    left_health = python.get("summary", {}).get("health")
    right_health = go.get("summary", {}).get("health")
    health_matches = left_health == right_health
    print(f"[{'OK' if health_matches else 'NG'}] health: Python={left_health} Go={right_health}")
    failed = failed or not health_matches

    python_coverage = coverage_summary(python)
    go_coverage = coverage_summary(go)
    percentages_match = python_coverage[0] == go_coverage[0]
    # Go版はPython版を超える独立ルールを持つため、分母が違えば同じ取得
    # 失敗数でも百分率は変わる。既定では診断不能件数と所見の一致を
    # 意味上のパリティとし、完全一致は --strict-coverage で要求する。
    coverage_matches = percentages_match or (
        not args.strict_coverage and python_coverage[2] == go_coverage[2]
    )
    suffix = ""
    if coverage_matches and not percentages_match:
        suffix = " (診断項目数が異なるため、取得失敗数の一致で判定)"
    print(
        f"[{'OK' if coverage_matches else 'NG'}] coverage: "
        f"Python={python_coverage[0]}% ({python_coverage[1]}/{python_coverage[3]}, 失敗{python_coverage[2]}) "
        f"Go={go_coverage[0]}% ({go_coverage[1]}/{go_coverage[3]}, 失敗{go_coverage[2]}){suffix}"
    )
    failed = failed or not coverage_matches

    python_ci, go_ci = ci_summary(python), ci_summary(go)
    marker = "OK" if python_ci == go_ci else "NG"
    print(f"[{marker}] CI policy/active findings: Python={python_ci} Go={go_ci}")
    failed = failed or python_ci != go_ci

    python_findings = finding_counts(python, args.include_candidates)
    go_findings = finding_counts(go, args.include_candidates)
    print_counter("Pythonのみの所見:", python_findings - go_findings)
    print_counter("Goのみの所見:", go_findings - python_findings)
    if python_findings != go_findings:
        failed = True
    else:
        print(f"[OK] CI関連所見: {sum(python_findings.values())}件が一致")

    python_confidence = finding_confidences(python, args.include_candidates)
    go_confidence = finding_confidences(go, args.include_candidates)
    if python_confidence != go_confidence:
        print_counter("Pythonのみの所見/確信度:", python_confidence - go_confidence)
        print_counter("Goのみの所見/確信度:", go_confidence - python_confidence)
        failed = True
    else:
        print("[OK] 所見の確信度が一致")

    python_roots, go_roots = root_counts(python), root_counts(go)
    print_counter("PythonのみのRoot Cause:", python_roots - go_roots)
    print_counter("GoのみのRoot Cause:", go_roots - python_roots)
    if python_roots != go_roots:
        failed = True
    else:
        print(f"[OK] Root Cause: {sum(python_roots.values())}件が一致")

    if not args.skip_exit_code:
        try:
            python_exit = policy_exit_code(args.python, "Python", args)
            go_exit = policy_exit_code(args.go, "Go", args)
        except (OSError, RuntimeError) as exc:
            print(f"エラー: {exc}", file=sys.stderr)
            return 1
        expected = 1 if python_ci[0] else 0
        exit_matches = python_exit == go_exit == expected
        marker = "OK" if exit_matches else "NG"
        print(f"[{marker}] CI exit code: Python={python_exit} Go={go_exit} expected={expected}")
        failed = failed or not exit_matches

    if failed:
        print("判定: 差分あり", file=sys.stderr)
        return 1
    print("判定: 意味上のパリティ一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
