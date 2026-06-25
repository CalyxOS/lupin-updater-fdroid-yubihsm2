#!/usr/bin/env bash
# Wrapper around apksigner that adds extra parameters.
# 
# This is needed because apksigner can't access the cryptoki API otherwise.
# See https://gitlab.com/fdroid/fdroidserver/-/work_items/1313#note_2979031088
#

EXTRA_FLAG="-J-add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED"

# 1. Prefer the system-wide apksigner from PATH (e.g. /usr/bin/apksigner).
if command -v apksigner &>/dev/null; then
    exec apksigner "$EXTRA_FLAG" "$@"
fi

# 2. Fall back to the newest version found under $ANDROID_HOME/build-tools/.
if [[ -n "$ANDROID_HOME" ]]; then
    # Sort version directories so the highest version is picked last, then use tail -1.
    APKSIGNER=$(find "$ANDROID_HOME/build-tools" -name apksigner -type f 2>/dev/null | sort | tail -1)

    if [[ -n "$APKSIGNER" ]]; then
        exec "$APKSIGNER" "$EXTRA_FLAG" "$@"
    fi
fi

echo "apksigner not found. Set ANDROID_HOME or add apksigner to PATH." >&2
exit 1
