#!/usr/bin/env bash
# Builds target/release/snowpaw.app: the desktop client as a macOS app bundle, with its icon.
#
# The icon ships in two forms:
#   snowpaw.icon  Icon Composer source for macOS 26 and later: Fresh Snow in light mode,
#                 Night Snow in dark mode. Compiling it needs actool from Xcode 27 or
#                 later; older versions drop the dark appearance without an error.
#   snowpaw.icns  Fallback, Fresh Snow only. Used when Xcode 27 isn't installed, and by
#                 macOS 15 and earlier.
#
# Usage: packaging/macos/build-app.sh [--no-build]
#   --no-build   package the existing target/release/snowpaw instead of building it
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
app="$root/target/release/snowpaw.app"

build=1
for arg in "$@"; do
    case "$arg" in
        --no-build) build=0 ;;
        *) echo "usage: $0 [--no-build]" >&2; exit 2 ;;
    esac
done

if [ "$(uname -s)" != Darwin ]; then
    echo "error: this script builds a macOS app bundle and only runs on macOS" >&2
    exit 1
fi

if [ "$build" = 1 ]; then
    # The client and its sandboxed render worker (code highlighting, math, pictures),
    # which must sit next to it in the bundle.
    cargo build --release --locked -p snowpaw-client -p snowpaw-render --manifest-path "$root/Cargo.toml"
fi
bin="$root/target/release/snowpaw"
worker="$root/target/release/snowpaw-render"
for f in "$bin" "$worker"; do
    if [ ! -x "$f" ]; then
        echo "error: $f not found; build it first or drop --no-build" >&2
        exit 1
    fi
done

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)"
if [ -z "$version" ]; then
    echo "error: couldn't read the version from Cargo.toml" >&2
    exit 1
fi

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/snowpaw"
cp "$worker" "$app/Contents/MacOS/snowpaw-render"
cp "$here/snowpaw.icns" "$app/Contents/Resources/snowpaw.icns"
sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"

# The light/dark icon (Assets.car) needs actool from Xcode 27 or later.
actool_major=0
if actool_version="$(xcrun actool --version 2>/dev/null)"; then
    actool_major="$(printf '%s\n' "$actool_version" |
        sed -n '/short-bundle-version/{n;s/.*<string>\([0-9]*\).*/\1/p;}')"
fi
if [ "${actool_major:-0}" -ge 27 ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    if ! xcrun actool "$here/snowpaw.icon" --compile "$tmp" --app-icon snowpaw \
        --output-partial-info-plist "$tmp/partial.plist" \
        --platform macosx --target-device mac --minimum-deployment-target 11.0 \
        --errors --warnings > "$tmp/actool.log" || [ ! -f "$tmp/Assets.car" ]; then
        cat "$tmp/actool.log" >&2
        echo "error: actool couldn't compile snowpaw.icon" >&2
        exit 1
    fi
    cp "$tmp/Assets.car" "$app/Contents/Resources/Assets.car"
    icon="light and dark"
elif [ -f "$here/Assets.car" ]; then
    # Prebuilt from snowpaw.icon with Xcode 27 (see README.md), for machines without it.
    cp "$here/Assets.car" "$app/Contents/Resources/Assets.car"
    icon="light and dark, from the prebuilt Assets.car"
else
    /usr/libexec/PlistBuddy -c "Delete :CFBundleIconName" "$app/Contents/Info.plist"
    icon="light only; install Xcode 27 or later for the dark-mode icon"
fi

# Ad-hoc signatures, so the bundle's seal matches its contents when run locally. The
# worker is signed first: it's a separate executable inside the bundle.
codesign --force --sign - "$app/Contents/MacOS/snowpaw-render" > /dev/null 2>&1
codesign --force --sign - "$app" > /dev/null 2>&1
echo "built $app (icon: $icon)"
