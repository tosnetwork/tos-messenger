#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 OUTPUT.zip COLLECTOR-MANIFEST.json [...]" >&2
  exit 2
fi

output=$1
shift
case "$output" in
  /*) ;;
  *) output="$(pwd)/$output" ;;
esac
collectors=()
for collector in "$@"; do
  case "$collector" in
    /*) collectors+=("$collector") ;;
    *) collectors+=("$(pwd)/$collector") ;;
  esac
done
if [ -e "$output" ]; then
  echo "refusing to replace existing output: $output" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo"

dirty=$(git status --porcelain --untracked-files=all -- . ':(exclude).claude/**')
if [ -n "$dirty" ]; then
  echo "evidence must be built from a clean checkout" >&2
  echo "$dirty" >&2
  exit 1
fi

evidence_tmp=$(mktemp -d)
trap 'rm -rf -- "$evidence_tmp"' EXIT HUP INT TERM
mkdir -p "$evidence_tmp/input/build" "$evidence_tmp/input/bin/linux-amd64" \
  "$evidence_tmp/input/bin/linux-arm64" "$evidence_tmp/input/collectors" "$evidence_tmp/input/vectors"

make verify 2>&1 | tee "$evidence_tmp/input/verify.log"

commands="tos-messengerd tos-reachability tos-reachability-coordinator tos-reachability-report tos-reachability-tunnel tos-m0-evidence tos-vector-report"
for target in linux-amd64 linux-arm64; do
  arch=${target#linux-}
  log="$evidence_tmp/input/build/$target.log"
  : > "$log"
  for command in $commands; do
    echo "building $command for linux/$arch" | tee -a "$log"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOWORK=off \
      go build -trimpath -o "$evidence_tmp/input/bin/$target/$command" "./cmd/$command" 2>&1 | tee -a "$log"
  done
done

cp internal/vectors/testdata/vectors.json "$evidence_tmp/input/vectors/objects.json"
cp internal/vectors/testdata/adversarial-corpus.json "$evidence_tmp/input/vectors/adversarial.json"
cp pkg/e2ee/testdata/default-suite-vectors.json "$evidence_tmp/input/vectors/e2ee.json"

for collector in "${collectors[@]}"; do
  if [ ! -f "$collector" ] || [ -L "$collector" ]; then
    echo "collector manifest is not a regular file: $collector" >&2
    exit 2
  fi
  name=$(basename -- "$collector")
  if [ -e "$evidence_tmp/input/collectors/$name" ]; then
    echo "duplicate collector manifest name: $name" >&2
    exit 2
  fi
  cp "$collector" "$evidence_tmp/input/collectors/$name"
done

GOWORK=off go build -trimpath -o "$evidence_tmp/tos-m0-evidence" ./cmd/tos-m0-evidence
commit=$(git rev-parse HEAD)
toolchain=$(go version)
"$evidence_tmp/tos-m0-evidence" pack -root "$evidence_tmp/input" -out "$output" \
  -commit "$commit" -toolchain "$toolchain"
"$evidence_tmp/tos-m0-evidence" verify -in "$output"
sha256sum "$output"
