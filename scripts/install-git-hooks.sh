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

# A security policy (GitHub shows it on the Security tab). An existing one is never touched.
if [ ! -f "$ROOT/SECURITY.md" ] && [ ! -f "$ROOT/.github/SECURITY.md" ] && [ ! -f "$ROOT/docs/SECURITY.md" ]; then
  branch="$(git -C "$ROOT" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)"
  cat > "$ROOT/SECURITY.md" <<EOF
# Security policy

## Reporting a vulnerability

This repository is private. **Don't open an issue or pull request for a security problem** —
they are visible to every collaborator. Tell the repository owner directly and privately, with
what an attacker can do, the steps or a proof of concept, and the affected component or host.
Never test against live systems in a way that changes or exposes real data.

You'll get an acknowledgement as soon as the report is read, and a fix or a decision once it
has been triaged. Please keep the details private until a fix is released.

## Supported versions

Only the latest default branch (\`${branch#origin/}\`) gets security fixes; older commits, tags and
forks don't.

## Scope

Everything in this repository and what it deploys. In scope: anything that lets someone read
data, run code, or act with access they shouldn't have. Never commit secrets: credentials live
in environment variables or the platform's secret store, \`.env\` files are git-ignored, and a
gitleaks scan runs on pre-commit where hooks are installed. Dependabot watches the
dependencies; its alerts are triaged as part of this policy.
EOF
  echo "✓ SECURITY.md written (review the Scope section, then commit it)"
fi
