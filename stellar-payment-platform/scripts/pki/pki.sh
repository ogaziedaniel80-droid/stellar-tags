#!/bin/sh
# ---------------------------------------------------------------------------
# scripts/pki/pki.sh - internal PKI for service-to-service mTLS
#
# Establishes and maintains the certificate authority that every internal
# service uses to both serve and authenticate itself. Written in POSIX sh so
# the same script runs on a developer machine and inside the `alpine/openssl`
# image the `pki-init` compose service uses.
#
#   pki.sh init   [--out DIR] [--services a,b] [--days N] [--key-bits N] [--sans name=...]
#        Build the root CA, the intermediate CA and one leaf per service.
#
#   pki.sh rotate [--out DIR] [--days N] [--key-bits N] [--new-intermediate]
#        Re-issue every leaf from the current intermediate, or mint a fresh
#        intermediate when --new-intermediate is passed. The generated trust
#        bundle always contains the root plus every intermediate that is still
#        live, so peers can be switched over in any order without downtime.
#
#   pki.sh prune  [--out DIR]
#        Drop intermediates retired by a previous --new-intermediate rotation.
#        Run this only once every process has picked up the newer bundle;
#        afterwards the bundle trusts the current intermediate alone.
#
#   pki.sh check  [--out DIR] [--warn-days N]
#        Report what expires and when. Exit code 1 when anything is inside the
#        warning window, so it can gate a deploy or run on a schedule.
#
# Layout under --out (default: ./certs):
#   root/ca.key, root/ca.crt             offline-capable root
#   intermediate/ca.key, .../ca.crt     current issuing CA
#   intermediate/retired/<ts>/           superseded issuing CAs
#   services/<name>.key, <name>.crt      leaf: serverAuth + clientAuth
#   ca-bundle.crt                        root + live intermediates (trust anchor)
#   manifest.env                         generated metadata
#
# Private keys are written with mode 600 and the directory is 700: this is
# material that can impersonate any internal service.
# ---------------------------------------------------------------------------
set -eu

OUT_DIR="./certs"
LEAF_DAYS=397
CA_DAYS=3650
INTERMEDIATE_DAYS=1825
WARN_DAYS=30
ROOT_CA_DAYS=3650
# Root and issuing CA key sizes. 4096 is the right default for a long-lived
# internal CA; --key-bits lowers it when generating throwaway material (tests).
CA_KEY_BITS=4096
LEAF_KEY_BITS=2048
SUBJECT_PREFIX="/C=US/O=Stellar Tags/OU=Internal PKI"
COMMAND=""

# service name -> Subject Alternative Names. Override per service with
# --sans "<name>=DNS:a,DNS:b" or extend the defaults with PKI_EXTRA_SANS_*.
# URI SANs double as the service identity read by src/middleware/mtls.js.
# Variable names use `_` where a service name uses `-`, since a shell variable
# cannot contain a hyphen (sans_for_service normalizes before looking one up).
DEFAULT_SANS_api="DNS:api,DNS:backend,DNS:localhost,IP:127.0.0.1,URI:spiffe://stellar-tags/internal/api"
DEFAULT_SANS_edge="DNS:edge,DNS:frontend,DNS:localhost,IP:127.0.0.1,URI:spiffe://stellar-tags/internal/edge"
DEFAULT_SANS_fraud_worker="DNS:fraud-worker,DNS:localhost,IP:127.0.0.1,URI:spiffe://stellar-tags/internal/fraud-worker"
DEFAULT_SANS_api_test="DNS:api-test,DNS:localhost,IP:127.0.0.1,URI:spiffe://stellar-tags/internal/api-test"
DEFAULT_SANS_healthcheck="DNS:localhost,IP:127.0.0.1,URI:spiffe://stellar-tags/internal/healthcheck"

# Services issued a certificate by `init` and re-issued by `rotate`.
DEFAULT_SERVICES="api edge fraud-worker api-test healthcheck"

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'pki: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

require_openssl() {
  command -v openssl >/dev/null 2>&1 || die "openssl is required but was not found on PATH"
}

# Human-readable notAfter straight from the certificate, so no locale- or
# libc-dependent date parsing is needed anywhere in this script.
cert_not_after_human() {
  openssl x509 -in "$1" -noout -enddate | sed 's/notAfter=//'
}

# --- argument parsing --------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    init|rotate|prune|check)
      COMMAND="$1"
      shift
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --services)
      DEFAULT_SERVICES="$2"
      shift 2
      ;;
    --days)
      LEAF_DAYS="$2"
      shift 2
      ;;
    --ca-days)
      CA_DAYS="$2"
      shift 2
      ;;
    --key-bits)
      CA_KEY_BITS="$2"
      shift 2
      ;;
    --warn-days)
      WARN_DAYS="$2"
      shift 2
      ;;
    --new-intermediate)
      NEW_INTERMEDIATE=1
      shift
      ;;
    --sans)
      # Space-separated "<service>=<SAN list>" pairs, e.g.
      # --sans "api=DNS:api,DNS:backend api-test=DNS:api-test"
      PKI_SAN_OVERRIDE="${PKI_SAN_OVERRIDE:-} $2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1 (try --help)"
      ;;
  esac
done

[ -n "$COMMAND" ] || {
  usage
  exit 1
}

require_openssl

for numeric in "$LEAF_DAYS" "$CA_KEY_BITS" "$LEAF_KEY_BITS"; do
  case "$numeric" in
    ''|*[!0-9]*) die "day and key-size options must be positive integers, got \"$numeric\"" ;;
  esac
done

# Service names reach `eval` in sans_for_service and are used as file names, so
# restrict them to a safe character set before anything else happens.
for candidate in $DEFAULT_SERVICES; do
  case "$candidate" in
    ''|*[!A-Za-z0-9._-]*) die "invalid service name \"$candidate\"" ;;
  esac
done

ROOT_DIR="$OUT_DIR/root"
INTERMEDIATE_DIR="$OUT_DIR/intermediate"
RETIRED_DIR="$INTERMEDIATE_DIR/retired"
SERVICES_DIR="$OUT_DIR/services"
BUNDLE="$OUT_DIR/ca-bundle.crt"
MANIFEST="$OUT_DIR/manifest.env"

# Create the tree with restrictive permissions before any key lands in it.
secure_mkdir() {
  mkdir -p "$1"
  chmod 700 "$1"
}

secure_mkdir "$OUT_DIR"
secure_mkdir "$ROOT_DIR"
secure_mkdir "$INTERMEDIATE_DIR"
secure_mkdir "$SERVICES_DIR"

now_iso() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

timestamp_slug() {
  date -u +%Y%m%dT%H%M%SZ
}

sans_for_service() {
  name="$1"
  # Space-separated overrides, each "<name>=<comma separated SAN list>".
  for pair in ${PKI_SAN_OVERRIDE:-}; do
    key=${pair%%=*}
    if [ "$key" = "$name" ]; then
      printf '%s' "${pair#*=}"
      return 0
    fi
  done
  # `-` is not legal in a shell variable name, so normalize before the lookup.
  key=$(printf '%s' "$name" | tr '-' '_')
  eval "printf '%s' \"\${PKI_EXTRA_SANS_$key:-\${DEFAULT_SANS_$key}}\""
}

# --- CA construction ---------------------------------------------------------

init_root_ca() {
  if [ -f "$ROOT_DIR/ca.crt" ]; then
    log "root CA already present at $ROOT_DIR/ca.crt (reusing it)"
    return 0
  fi
  log "generating root CA ($ROOT_CA_DAYS days)"
  openssl genrsa -out "$ROOT_DIR/ca.key" "$CA_KEY_BITS" 2>/dev/null
  chmod 600 "$ROOT_DIR/ca.key"
  openssl req -x509 -new -sha256 -days "$ROOT_CA_DAYS" \
    -key "$ROOT_DIR/ca.key" \
    -out "$ROOT_DIR/ca.crt" \
    -subj "$SUBJECT_PREFIX/CN=Stellar Tags Internal Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
  chmod 644 "$ROOT_DIR/ca.crt"
}

init_intermediate_ca() {
  if [ -f "$INTERMEDIATE_DIR/ca.crt" ]; then
    log "intermediate CA already present at $INTERMEDIATE_DIR/ca.crt (reusing it)"
    return 0
  fi
  issue_intermediate_ca "$INTERMEDIATE_DIR" "$INTERMEDIATE_DAYS" "Stellar Tags Internal Intermediate CA"
}

# Signs a fresh intermediate with the root CA. `dest_dir` is either the live
# intermediate directory or a retired archive directory.
issue_intermediate_ca() {
  dest_dir="$1"
  days="$2"
  label="$3"

  secure_mkdir "$dest_dir"
  openssl genrsa -out "$dest_dir/ca.key" "$CA_KEY_BITS" 2>/dev/null
  chmod 600 "$dest_dir/ca.key"
  openssl req -new -sha256 -key "$dest_dir/ca.key" \
    -out "$dest_dir/ca.csr" \
    -subj "$SUBJECT_PREFIX/CN=$label"

  cat > "$dest_dir/ca.ext" <<'EXT'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
EXT

  openssl x509 -req -sha256 -days "$days" \
    -in "$dest_dir/ca.csr" \
    -CA "$ROOT_DIR/ca.crt" \
    -CAkey "$ROOT_DIR/ca.key" \
    -CAcreateserial \
    -out "$dest_dir/ca.crt" \
    -extfile "$dest_dir/ca.ext"
  chmod 644 "$dest_dir/ca.crt"
  rm -f "$dest_dir/ca.csr"
}

# Archives the current intermediate and issues a new one, so a CA rotation can
# be rolled out alongside the leaves signed by the old CA.
rotate_intermediate_ca() {
  slug=$(timestamp_slug)
  mkdir -p "$RETIRED_DIR"
  log "archiving the current intermediate CA under intermediate/retired/$slug"
  mv "$INTERMEDIATE_DIR/ca.crt" "$RETIRED_DIR/$slug.crt"
  mv "$INTERMEDIATE_DIR/ca.key" "$RETIRED_DIR/$slug.key"
  if [ -f "$INTERMEDIATE_DIR/ca.srl" ]; then
    mv "$INTERMEDIATE_DIR/ca.srl" "$RETIRED_DIR/$slug.srl"
  fi
  chmod 600 "$RETIRED_DIR/$slug.key"

  log "issuing a new intermediate CA ($INTERMEDIATE_DAYS days)"
  issue_intermediate_ca "$INTERMEDIATE_DIR" "$INTERMEDIATE_DAYS" \
    "Stellar Tags Internal Intermediate CA $slug"
}

# --- leaf certificates -------------------------------------------------------

issue_leaf() {
  name="$1"
  sans="$2"

  [ -n "$sans" ] || die "no SANs resolved for service \"$name\"; pass --sans \"$name=DNS:...\""

  openssl genrsa -out "$SERVICES_DIR/$name.key" "$LEAF_KEY_BITS" 2>/dev/null
  chmod 600 "$SERVICES_DIR/$name.key"
  openssl req -new -sha256 -key "$SERVICES_DIR/$name.key" \
    -out "$SERVICES_DIR/$name.csr" \
    -subj "$SUBJECT_PREFIX/CN=$name"

  cat > "$SERVICES_DIR/$name.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
# Both roles in one certificate: an internal service serves TLS to its peers
# and presents the same identity as a client.
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
subjectAltName=PLACEHOLDER
EXT

  # subjectAltName is written into the extension file so DNS/IP/URI entries keep
  # their types instead of being flattened into a shell-escaped string.
  sed "s|subjectAltName=PLACEHOLDER|subjectAltName=$sans|" \
    "$SERVICES_DIR/$name.ext" > "$SERVICES_DIR/$name.ext.tmp"
  mv "$SERVICES_DIR/$name.ext.tmp" "$SERVICES_DIR/$name.ext"

  openssl x509 -req -sha256 -days "$LEAF_DAYS" \
    -in "$SERVICES_DIR/$name.csr" \
    -CA "$INTERMEDIATE_DIR/ca.crt" \
    -CAkey "$INTERMEDIATE_DIR/ca.key" \
    -CAcreateserial \
    -out "$SERVICES_DIR/$name.crt" \
    -extfile "$SERVICES_DIR/$name.ext"
  chmod 644 "$SERVICES_DIR/$name.crt"
  rm -f "$SERVICES_DIR/$name.csr"
  log "issued $name (valid $LEAF_DAYS days) SAN=$sans"
}

issue_leaves() {
  for name in $DEFAULT_SERVICES; do
    issue_leaf "$name" "$(sans_for_service "$name")"
  done
}

# --- trust bundle ------------------------------------------------------------

# The bundle is the single file every service mounts as its CA trust anchor. It
# lists the root and every intermediate still in service, which is what makes a
# two-phase rotation possible: publish the wider bundle, switch the leaves,
# then prune the old intermediate.
build_bundle() {
  cat "$ROOT_DIR/ca.crt" > "$BUNDLE.tmp"
  for crt in "$INTERMEDIATE_DIR"/ca.crt "$RETIRED_DIR"/*.crt; do
    [ -f "$crt" ] || continue
    printf '\n' >> "$BUNDLE.tmp"
    cat "$crt" >> "$BUNDLE.tmp"
  done
  mv "$BUNDLE.tmp" "$BUNDLE"
  chmod 644 "$BUNDLE"
  count=$(grep -c 'BEGIN CERTIFICATE' "$BUNDLE" || true)
  log "trust bundle at $BUNDLE now contains $count certificates"
}

write_manifest() {
  {
    echo "PKI_GENERATED_AT=$(now_iso)"
    echo "PKI_LEAF_DAYS=$LEAF_DAYS"
    echo "PKI_INTERMEDIATE_DAYS=$INTERMEDIATE_DAYS"
    echo "PKI_SERVICES=$DEFAULT_SERVICES"
    echo "PKI_ROOT_CA_EXPIRES=$(cert_not_after_human "$ROOT_DIR/ca.crt")"
    echo "PKI_INTERMEDIATE_CA_EXPIRES=$(cert_not_after_human "$INTERMEDIATE_DIR/ca.crt")"
    for name in $DEFAULT_SERVICES; do
      [ -f "$SERVICES_DIR/$name.crt" ] || continue
      echo "PKI_${name}_EXPIRES=$(cert_not_after_human "$SERVICES_DIR/$name.crt")"
    done
  } > "$MANIFEST"
  chmod 644 "$MANIFEST"
}

# --- verification ------------------------------------------------------------

# The services that were actually issued, taken from the manifest so `check`
# follows a PKI created with a custom --services list instead of the built-in
# default (which would report every unissued name as MISSING).
issued_services() {
  if [ -f "$MANIFEST" ]; then
    recorded=$(sed -n 's/^PKI_SERVICES=//p' "$MANIFEST" | head -n 1)
    if [ -n "$recorded" ]; then
      printf '%s\n' "$recorded"
      return 0
    fi
  fi
  printf '%s\n' "$DEFAULT_SERVICES"
}

verify_chain() {
  name="$1"
  if openssl verify -CAfile "$BUNDLE" -untrusted "$INTERMEDIATE_DIR/ca.crt" \
    "$SERVICES_DIR/$name.crt" >/dev/null 2>&1; then
    return 0
  fi
  die "issued certificate for \"$name\" does not verify against the generated bundle"
}

cmd_init() {
  init_root_ca
  init_intermediate_ca
  issue_leaves
  build_bundle
  write_manifest
  for name in $DEFAULT_SERVICES; do
    verify_chain "$name"
  done
  log ""
  log "internal PKI ready in $OUT_DIR"
  log "server identity: MTLS_CERT_FILE=$SERVICES_DIR/<service>.crt MTLS_KEY_FILE=$SERVICES_DIR/<service>.key"
  log "trust anchor:    MTLS_CA_FILE=$BUNDLE"
}

cmd_rotate() {
  [ -f "$ROOT_DIR/ca.crt" ] || die "no PKI found in $OUT_DIR; run \"pki.sh init\" first"
  [ -f "$INTERMEDIATE_DIR/ca.crt" ] || die "no issuing CA found in $INTERMEDIATE_DIR; run \"pki.sh init\" first"

  if [ -n "${NEW_INTERMEDIATE:-}" ]; then
    rotate_intermediate_ca
  else
    log "re-issuing leaves from the current intermediate CA"
  fi

  issue_leaves
  build_bundle
  write_manifest
  for name in $DEFAULT_SERVICES; do
    verify_chain "$name"
  done
  log ""
  log "rotation complete."
  if [ -n "${NEW_INTERMEDIATE:-}" ]; then
    log "The bundle trusts both the old and the new intermediate CA, so peers can"
    log "be restarted in any order. Once nothing serves the previous CA, run:"
    log "  pki.sh prune --out $OUT_DIR"
  fi
}

cmd_prune() {
  [ -d "$RETIRED_DIR" ] || die "no retired intermediates to prune"
  count=$(ls -1 "$RETIRED_DIR"/*.crt 2>/dev/null | wc -l | tr -d ' ')
  [ "$count" -gt 0 ] || die "no retired intermediates to prune"
  log "removing $count retired intermediate CA(s) from the trust bundle"
  for crt in "$RETIRED_DIR"/*.crt; do
    base=${crt%.crt}
    rm -f "$crt" "$base.key" "$base.srl"
  done
  rmdir "$RETIRED_DIR" 2>/dev/null || true
  build_bundle
  write_manifest
  log "pruned; the bundle now trusts only the current intermediate CA"
}

cmd_check() {
  [ -f "$BUNDLE" ] || die "no trust bundle at $BUNDLE; run \"pki.sh init\" first"

  status=0
  # `-checkend` asks openssl directly, so expiry detection behaves identically
  # on glibc and musl and never depends on parsing a date string.
  report() {
    label="$1"
    file="$2"
    if [ ! -f "$file" ]; then
      log "MISSING  $label ($file)"
      status=1
      return 0
    fi
    if ! openssl x509 -checkend 0 -noout -in "$file" >/dev/null 2>&1; then
      log "EXPIRED  $label expired at $(cert_not_after_human "$file")"
      status=1
    elif ! openssl x509 -checkend "$((WARN_DAYS * 86400))" -noout -in "$file" >/dev/null 2>&1; then
      log "EXPIRING $label expires within ${WARN_DAYS}d ($(cert_not_after_human "$file"))"
      status=1
    else
      log "ok       $label valid until $(cert_not_after_human "$file")"
    fi
  }

  report "root CA" "$ROOT_DIR/ca.crt"
  report "intermediate CA" "$INTERMEDIATE_DIR/ca.crt"
  for name in $(issued_services); do
    report "service:$name" "$SERVICES_DIR/$name.crt"
  done

  if [ "$status" -ne 0 ]; then
    log ""
    log "certificates need attention: rotate with \"pki.sh rotate --out $OUT_DIR\""
  fi
  return $status
}

case "$COMMAND" in
  init) cmd_init ;;
  rotate) cmd_rotate ;;
  prune) cmd_prune ;;
  check) cmd_check ;;
  *) die "unhandled command: $COMMAND" ;;
esac
