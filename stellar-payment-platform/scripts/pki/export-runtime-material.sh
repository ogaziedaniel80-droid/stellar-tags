#!/bin/sh
# ---------------------------------------------------------------------------
# scripts/pki/export-runtime-material.sh
#
# Copies the subset of a generated PKI that running services are allowed to
# see out of the CA volume and into the shared runtime volume:
#
#   ca-bundle.crt          trust anchor (root + every live intermediate)
#   manifest.env           generated metadata
#   services/<name>.crt   the service's own certificate
#   services/<name>.key   the service's own private key
#
# Deliberately excluded: root/ca.key and intermediate/ca.key. Keeping the
# issuer keys in their own volume means a compromised backend cannot mint a
# certificate for a peer it does not own.
#
# Usage: export-runtime-material.sh <ca-dir> <runtime-dir>
# ---------------------------------------------------------------------------
set -eu

CA_DIR="${1:-/ca}"
OUT_DIR="${2:-/certs}"
# uid:gid of the `node` user in the backend images, so the API can read the
# key it owns while the file stays mode 600.
OWNER="${PKI_RUNTIME_OWNER:-1000:1000}"

[ -d "$CA_DIR/services" ] || {
  printf 'export: no PKI found at %s; run pki.sh init first\n' "$CA_DIR" >&2
  exit 1
}

mkdir -p "$OUT_DIR/services"

# Drop stale leaves before copying, so a service removed from the PKI does not
# keep a usable certificate sitting in the runtime volume.
rm -f "$OUT_DIR"/services/*.crt "$OUT_DIR"/services/*.key

for cert in "$CA_DIR"/services/*.crt; do
  name=$(basename "$cert" .crt)
  cp "$cert" "$OUT_DIR/services/$name.crt"
  cp "$CA_DIR/services/$name.key" "$OUT_DIR/services/$name.key"
done

cp "$CA_DIR/ca-bundle.crt" "$OUT_DIR/ca-bundle.crt"
cp "$CA_DIR/manifest.env" "$OUT_DIR/manifest.env"

chown -R "$OWNER" "$OUT_DIR"
# Directory 700 + key 600 keeps the material readable only by the service uid.
chmod 700 "$OUT_DIR" "$OUT_DIR/services"
chmod 600 "$OUT_DIR"/services/*.key
chmod 644 "$OUT_DIR/ca-bundle.crt" "$OUT_DIR/manifest.env" "$OUT_DIR"/services/*.crt

printf 'export: published %s leaf certificate(s) to %s\n' \
  "$(ls -1 "$OUT_DIR"/services/*.crt | wc -l | tr -d ' ')" "$OUT_DIR"
