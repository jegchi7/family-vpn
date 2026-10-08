#!/usr/bin/env bash
# Operator-run binary installation and private configuration preparation only.
set -euo pipefail
umask 077

apply=0
case "${1:-}" in
  '') ;;
  --apply) apply=1 ;;
  *) printf '%s\n' 'Usage: bootstrap-foreign.sh [--apply]' >&2; exit 1 ;;
esac
if (( $# > 1 )); then
  printf '%s\n' 'Unexpected arguments' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'Foreign preparation requires Linux' >&2
  exit 1
fi
if (( apply && EUID != 0 )); then
  printf '%s\n' 'Run --apply as root or through sudo' >&2
  exit 1
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
vpnctl="$script_dir/../build/vpnctl"
if [[ ! -f "$vpnctl" || -L "$vpnctl" || ! -x "$vpnctl" ]]; then
  printf '%s\n' 'Extract the matching verified Linux bundle first' >&2
  exit 1
fi

"$vpnctl" core-plan --role foreign
read -r -p 'Foreign public IP with port (IP:443): ' endpoint
read -r -p 'RU public IP: ' ru_source
read -r -p 'REALITY TLS target public IP with port (IP:443): ' reality_target
read -r -p 'REALITY target TLS hostname (SNI): ' server_name
args=(--endpoint "$endpoint" --ru-source "$ru_source" --reality-target "$reality_target" --server-name "$server_name")
# Validate all non-secret operator inputs before downloading or installing.
"$vpnctl" foreign-init "${args[@]}"
if (( ! apply )); then
  printf '%s\n' 'Dry-run complete. No downloads, generated secrets, or files written.'
  exit 0
fi
"$vpnctl" core-install --core xray --apply
"$vpnctl" core-install --core hysteria --apply
"$vpnctl" foreign-init "${args[@]}" --apply
"$vpnctl" foreign-check --native-check
printf '%s\n' 'Preparation complete. No service started; VPN and profile delivery remain unavailable.'
printf '%s\n' 'Continue with the kernel isolation and RU-to-Foreign acceptance steps in docs/vpn-bootstrap-runbook.md.'
