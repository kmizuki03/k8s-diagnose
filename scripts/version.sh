#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

version=${K8S_DIAGNOSE_VERSION:-}
if [[ -z $version ]] && command -v git >/dev/null 2>&1; then
  version=$(git -C "$project_dir" describe --tags --always --dirty 2>/dev/null || true)
fi
if [[ -z $version ]]; then
  version=3.0.0-dev
fi
if [[ ! $version =~ ^[0-9A-Za-z][0-9A-Za-z._+/-]*$ ]]; then
  printf '%s\n' "バージョン文字列が不正です: $version" >&2
  exit 1
fi
printf '%s\n' "$version"
