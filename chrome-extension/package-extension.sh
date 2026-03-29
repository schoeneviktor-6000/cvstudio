#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="$ROOT/dist"
OUT_FILE="$OUT_DIR/cvstudio-tailor-extension.zip"
TMP_DIR="$OUT_DIR/package"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR" "$OUT_DIR"

cp "$ROOT/manifest.json" "$TMP_DIR/"
cp "$ROOT/background.js" "$TMP_DIR/"
cp "$ROOT/scraper.js" "$TMP_DIR/"
cp "$ROOT/sidepanel.html" "$TMP_DIR/"
cp "$ROOT/sidepanel.css" "$TMP_DIR/"
cp "$ROOT/sidepanel.js" "$TMP_DIR/"
cp -R "$ROOT/icons" "$TMP_DIR/icons"

rm -f "$OUT_FILE"
cd "$TMP_DIR"
zip -qr "$OUT_FILE" .

printf '%s\n' "Created $OUT_FILE"
