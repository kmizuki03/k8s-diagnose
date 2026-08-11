#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
ci_binary=$(mktemp "${TMPDIR:-/tmp}/k8s-diagnose-go-ci.XXXXXX")
cleanup() {
  rm -f -- "$ci_binary"
}
trap cleanup EXIT INT TERM

cd "$project_dir"
go mod verify
gofmt_diff=$(gofmt -d .)
if [[ -n "$gofmt_diff" ]]; then
  printf '%s\n' "$gofmt_diff"
  exit 1
fi
go test -mod=readonly ./...
go test -mod=readonly -race ./...
go vet -mod=readonly ./...
if command -v staticcheck >/dev/null 2>&1; then
  staticcheck ./...
  # A second production-only pass catches declarations that are referenced
  # exclusively by tests and would otherwise ship as dead code.
  staticcheck -tests=false ./...
elif [[ ${K8S_DIAGNOSE_REQUIRE_SECURITY_TOOLS:-0} == 1 ]]; then
  printf '%s\n' 'staticcheck がありません' >&2
  exit 1
fi
go run -mod=readonly ./cmd/rbac --namespace default --output-dir rbac --check
version=$("$script_dir/version.sh")
version_symbol=github.com/kmizuki03/k8s-diagnose/internal/config.Version
go build -mod=readonly -trimpath -ldflags "-X $version_symbol=$version" -o "$ci_binary" .
if [[ $("$ci_binary" --version) != "k8s-diagnose $version (Go)" ]]; then
  printf '%s\n' 'ビルドへバージョンを注入できませんでした' >&2
  exit 1
fi

if command -v govulncheck >/dev/null 2>&1; then
  govulncheck ./...
elif [[ ${K8S_DIAGNOSE_REQUIRE_SECURITY_TOOLS:-0} == 1 ]]; then
  printf '%s\n' 'govulncheck がありません' >&2
  exit 1
fi

if command -v gosec >/dev/null 2>&1; then
  gosec ./...
elif [[ ${K8S_DIAGNOSE_REQUIRE_SECURITY_TOOLS:-0} == 1 ]]; then
  printf '%s\n' 'gosec がありません' >&2
  exit 1
fi
