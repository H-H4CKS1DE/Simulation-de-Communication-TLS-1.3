#!/usr/bin/env bash
set -euo pipefail

# On Bob: ./openssl_server.sh tls13|tls12
MODE="${1:-tls13}"
case "$MODE" in
  tls13) VERSION="-tls1_3" ;;
  tls12) VERSION="-tls1_2" ;;
  *) echo "Usage: $0 tls13|tls12" >&2; exit 2 ;;
esac
exec openssl s_server -accept 4433 -cert bob.crt -key bob.key "$VERSION" -www -msg -state
