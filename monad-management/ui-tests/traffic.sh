#!/usr/bin/env bash
# Continuous traffic through a configured SOCKS5 route. No wallet operations.
set -u

usage() {
  printf 'Usage: %s SOCKS_HOST:PORT TARGET_URL [DELAY_SECONDS]\n' "$0"
  printf 'Example: %s 127.0.0.1:12345 http://127.0.0.1:54321 0.1\n' "$0"
  printf 'Repeats requests until Ctrl-C. Default delay: 0.1 seconds; use 0 for no delay.\n'
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  usage
  exit 0
fi
if (( $# < 2 || $# > 3 )); then
  usage >&2
  exit 2
fi

socks=$1
target=$2
delay=${3:-0.1}
if [[ ! $delay =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]]; then
  printf 'DELAY_SECONDS must be a nonnegative number.\n' >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  printf 'curl is required.\n' >&2
  exit 1
fi

trap 'printf "\nTraffic stopped.\n"; exit 0' INT TERM
printf 'Continuous SOCKS traffic; press Ctrl-C to stop.\n'
while true; do
  # Explicitly override NO_PROXY so local demo targets go through SOCKS too.
  if ! curl --silent --show-error \
      --socks5-hostname "$socks" \
      --noproxy "" \
      --max-time 15 \
      --output /dev/null \
      --write-out 'HTTP %{http_code} · %{size_download} bytes · %{time_total}s\n' \
      --url "$target"; then
    printf 'Request failed; continuing after the delay.\n' >&2
  fi
  sleep "$delay"
done
