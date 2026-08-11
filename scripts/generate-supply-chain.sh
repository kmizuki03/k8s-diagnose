#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir=${1:-"$project_dir/dist/supply-chain"}

for tool in git cyclonedx-gomod go-licenses; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "$tool がありません" >&2
    exit 1
  fi
done

if [[ $(git -C "$project_dir" rev-parse --is-inside-work-tree 2>/dev/null || true) != true ]]; then
  printf '%s\n' 'CycloneDX appモードでバージョンを決定するため、Git checkout内で実行してください' >&2
  exit 1
fi

if [[ -e "$output_dir" ]]; then
  printf '%s\n' "出力先が既に存在します: $output_dir" >&2
  exit 1
fi

output_parent=$(dirname -- "$output_dir")
mkdir -p "$output_parent"
staging_dir=$(mktemp -d "${output_dir}.tmp.XXXXXX")
cleanup() {
  if [[ -n ${staging_dir:-} && -d $staging_dir ]]; then
    rm -rf -- "$staging_dir"
  fi
}
trap cleanup EXIT INT TERM

cd "$project_dir"

module_go_version=$(go list -m -f '{{.GoVersion}}')
if [[ -z $module_go_version ]]; then
  printf '%s\n' 'go.modのGoバージョンを取得できませんでした' >&2
  exit 1
fi
supply_toolchain=${K8S_DIAGNOSE_SUPPLY_GOTOOLCHAIN:-"go$module_go_version"}
version=$("$script_dir/version.sh")
version_symbol=github.com/kmizuki03/k8s-diagnose/internal/config.Version

# Build the distributed artifact and generate its SBOM from the application
# source. App mode evaluates build constraints and derives the main component
# version from the Git checkout, unlike the more limited binary inspection mode.
# Pin every analysis step to go.mod's patch release so a newer local GOROOT does
# not change package discovery or the generated artifact.
GOTOOLCHAIN="$supply_toolchain" go build -mod=readonly -trimpath -ldflags "-s -w -X $version_symbol=$version" -o "$staging_dir/k8s-diagnose" .
GOTOOLCHAIN="$supply_toolchain" cyclonedx-gomod app -json -output-version 1.6 -output "$staging_dir/bom.cdx.json" "$project_dir"

module_path=$(GOTOOLCHAIN="$supply_toolchain" go list -m -f '{{.Path}}')
printf '%s\n' 'package,license_url,license' > "$staging_dir/THIRD_PARTY_NOTICES.csv"

# go-licenses package discovery is sensitive to GOROOT versions. Use the same
# pinned toolchain as the build by default; retain the narrower override for
# environments that need a separately installed license-analysis toolchain.
license_toolchain=${K8S_DIAGNOSE_LICENSE_GOTOOLCHAIN:-$supply_toolchain}
GOTOOLCHAIN="$license_toolchain" go-licenses report --ignore "$module_path" . >> "$staging_dir/THIRD_PARTY_NOTICES.csv"
GOTOOLCHAIN="$license_toolchain" go-licenses save --ignore "$module_path" . --save_path="$staging_dir/licenses"

if [[ $(wc -l < "$staging_dir/THIRD_PARTY_NOTICES.csv") -le 1 ]]; then
  printf '%s\n' '依存ライセンス一覧が空です' >&2
  exit 1
fi
if [[ ! -d "$staging_dir/licenses" ]] || ! find "$staging_dir/licenses" -type f -print -quit | grep -q .; then
  printf '%s\n' '依存ライセンス文書が生成されませんでした' >&2
  exit 1
fi

mv -- "$staging_dir" "$output_dir"
staging_dir=
trap - EXIT INT TERM
