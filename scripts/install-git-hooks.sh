#!/usr/bin/env bash
# Per-clone setup: turns on the repository's git hooks (.githooks/) and, when
# gitleaks isn't already installed, fetches the pinned, checksum-verified
# build they use. Idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=8.30.1

if command -v gitleaks >/dev/null; then
  bin="$(command -v gitleaks)"
else
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)                 PLAT=linux_x64;    SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
    Linux-aarch64|Linux-arm64)    PLAT=linux_arm64;  SHA=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
    Darwin-x86_64)                PLAT=darwin_x64;   SHA=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
    Darwin-arm64)                 PLAT=darwin_arm64; SHA=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
    *) echo "no pinned gitleaks build for $(uname -s) $(uname -m)" >&2; exit 1 ;;
  esac
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/local-ci"
  bin="$cache/gitleaks-$VERSION"
  if [ ! -x "$bin" ]; then
    mkdir -p "$cache"
    f="gitleaks_${VERSION}_${PLAT}.tar.gz"
    curl -fsSLo "$cache/$f" "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/$f"
    if command -v sha256sum >/dev/null; then
      echo "$SHA  $cache/$f" | sha256sum -c - >/dev/null
    else
      echo "$SHA  $cache/$f" | shasum -a 256 -c - >/dev/null
    fi
    tar -xzf "$cache/$f" -C "$cache" gitleaks
    mv "$cache/gitleaks" "$bin"
    rm -f "$cache/$f"
  fi
fi

git -C "$ROOT" config core.hooksPath .githooks
echo "✓ git hooks on (.githooks): secret scan before commit; branch guard + scripts/local-ci.sh quick before push"
echo "  gitleaks at $bin"
