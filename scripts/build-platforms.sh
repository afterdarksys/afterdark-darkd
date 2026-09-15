#!/usr/bin/env bash
set -euo pipefail
: "${GO:=go}" "${BUILD_DIR:=dist}" "${VERSION:=dev}" "${COMMIT:=unknown}"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  target_os=${target%/*}
  target_arch=${target#*/}
  suffix=""
  if [[ "$target_os" == windows ]]; then suffix=.exe; fi
  mkdir -p "$BUILD_DIR/$target_os-$target_arch"
  for command in afterdark-darkd afterdark-darkdadm darkapi; do
    GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 "$GO" build -trimpath \
      -ldflags "-s -w -X main.Version=$VERSION -X main.Commit=$COMMIT" \
      -o "$BUILD_DIR/$target_os-$target_arch/$command$suffix" "./cmd/$command"
  done
  echo "Built $target (portable variant)"
done
