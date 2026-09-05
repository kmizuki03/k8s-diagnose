#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
release_root=${1:-"$project_dir/dist/releases"}

version=$("$script_dir/version.sh")
safe_version=${version//\//-}
target_os=${GOOS:-$(go env GOOS)}
target_arch=${GOARCH:-$(go env GOARCH)}

for value_name in safe_version target_os target_arch; do
  value=${!value_name}
  if [[ -z $value || ! $value =~ ^[0-9A-Za-z._+-]+$ ]]; then
    printf '%s\n' "配布物名に使用できない値です: $value_name=$value" >&2
    exit 1
  fi
done

binary_name=k8s-diagnose
if [[ $target_os == windows ]]; then
  binary_name+=.exe
fi

bundle_name="k8s-diagnose_${safe_version}_${target_os}_${target_arch}"
bundle_dir="$release_root/$bundle_name"
archive="$release_root/$bundle_name.tar.gz"
checksum="$archive.sha256"

for path in "$bundle_dir" "$archive" "$checksum"; do
  if [[ -e $path ]]; then
    printf '%s\n' "配布物が既に存在します: $path" >&2
    printf '%s\n' '作り直す場合は make fclean の後に make package を実行してください' >&2
    exit 1
  fi
done

mkdir -p "$release_root"
staging_dir=$(mktemp -d "$release_root/.${bundle_name}.tmp.XXXXXX")
cleanup() {
  if [[ -n ${staging_dir:-} && -d $staging_dir ]]; then
    rm -rf -- "$staging_dir"
  fi
}
trap cleanup EXIT INT TERM

payload="$staging_dir/$bundle_name"
mkdir -p "$payload/rbac"

version_symbol=github.com/kmizuki03/k8s-diagnose/internal/config.Version
(
  cd "$project_dir"
  GOOS="$target_os" GOARCH="$target_arch" go build -mod=readonly -trimpath \
    -ldflags "-s -w -X $version_symbol=$version" \
    -o "$payload/$binary_name" .
)
chmod 0755 "$payload/$binary_name"

cp "$project_dir/README.md" "$payload/"
cp "$project_dir/QUICKSTART.md" "$payload/"
cp "$project_dir/k8s-diagnose.ini" "$payload/"
cp "$project_dir/baseline.example.ini" "$payload/"
cp "$project_dir/log-signatures.example.ini" "$payload/"
cp "$project_dir/rbac/README.md" "$payload/rbac/"
cp "$project_dir"/rbac/*.yaml "$payload/rbac/"

printf '%s\n' "$version" > "$payload/VERSION"
printf '%s\n' \
	'このディレクトリは実運用向けの配布物です。' \
	'Goソース、テスト、CI、レビュー資料、開発スクリプトは含みません。' \
	'利用方法は README.md / QUICKSTART.md を参照してください。' \
  > "$payload/CONTENTS.txt"

COPYFILE_DISABLE=1 tar -C "$staging_dir" -czf "$staging_dir/$bundle_name.tar.gz" "$bundle_name"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$staging_dir/$bundle_name.tar.gz" | sed "s#${staging_dir}/##" > "$staging_dir/$bundle_name.tar.gz.sha256"
else
  shasum -a 256 "$staging_dir/$bundle_name.tar.gz" | sed "s#${staging_dir}/##" > "$staging_dir/$bundle_name.tar.gz.sha256"
fi

mv -- "$payload" "$bundle_dir"
mv -- "$staging_dir/$bundle_name.tar.gz" "$archive"
mv -- "$staging_dir/$bundle_name.tar.gz.sha256" "$checksum"

staging_dir=
trap - EXIT INT TERM

printf '%s\n' "配布ディレクトリ: $bundle_dir"
printf '%s\n' "配布アーカイブ: $archive"
printf '%s\n' "SHA-256: $checksum"
