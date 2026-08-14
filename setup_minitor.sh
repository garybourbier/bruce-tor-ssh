#!/usr/bin/env bash
# setup_minitor.sh — populate the Minitor submodule for bruce-tor-ssh
#
# Run once from the project root before building with -DMINITOR_READY=1.
#
# Requirements: git, internet access

set -e

MINITOR_DIR="lib/minitor/src"

echo "[1/3] Cloning Minitor (Triple-Layer-Development fork)..."
if [ ! -d "$MINITOR_DIR/minitor/.git" ]; then
    git clone --depth=1 \
        https://github.com/Triple-Layer-Development/minitor \
        "$MINITOR_DIR/minitor"
else
    echo "  -> already cloned, pulling..."
    git -C "$MINITOR_DIR/minitor" pull --ff-only
fi

echo "[2/3] Cloning wolfSSL fork (expanded ed25519 support required by Tor v3)..."
if [ ! -d "$MINITOR_DIR/wolfssl/.git" ]; then
    git clone --depth=1 \
        https://github.com/wolfSSL/wolfssl \
        "$MINITOR_DIR/wolfssl"
    # Apply Minitor's wolfSSL patches if present
    PATCH_DIR="$MINITOR_DIR/minitor/wolfssl_patches"
    if [ -d "$PATCH_DIR" ]; then
        echo "  -> applying wolfSSL patches..."
        git -C "$MINITOR_DIR/wolfssl" apply "$PATCH_DIR"/*.patch
    fi
else
    echo "  -> already cloned"
fi

echo "[3/3] Enabling Minitor in board config..."
INI="boards/lilygo-t-embed-cc1101/lilygo-t-embed-cc1101.ini"
if grep -q "; -DMINITOR_READY=1" "$INI"; then
    sed -i 's/; -DMINITOR_READY=1/-DMINITOR_READY=1/' "$INI"
    echo "  -> -DMINITOR_READY=1 enabled in $INI"
else
    echo "  -> already enabled (or not found, check $INI manually)"
fi

echo ""
echo "Done. Build with:"
echo "  pio run -e lilygo-t-embed-cc1101"
