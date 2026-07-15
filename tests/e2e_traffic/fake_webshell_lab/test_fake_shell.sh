#!/usr/bin/env bash
# Smoke-test fake JSP webshell command execution.
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8080/shell.jsp}"
# Normalize: allow passing host root or full shell.jsp URL.
if [[ "$BASE_URL" != *"/shell.jsp"* ]]; then
  BASE_URL="${BASE_URL%/}/shell.jsp"
fi

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

probe() {
  local label="$1"
  local cmd="$2"
  local url="${BASE_URL}?cmd=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$cmd")"
  echo "=== $label ==="
  echo "URL: $url"
  local tmp
  tmp="$(mktemp)"
  local code
  code="$(curl -sS -o "$tmp" -w "%{http_code}" --connect-timeout 5 --max-time 30 "$url" || true)"
  echo "HTTP $code"
  if [[ "$code" != "200" ]]; then
    echo "body:" >&2
    cat "$tmp" >&2 || true
    rm -f "$tmp"
    fail "$label expected HTTP 200, got $code"
  fi
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    fail "$label empty response body"
  fi
  # Strip optional exit marker for display
  sed '/^__EXIT_CODE:/d' "$tmp" | head -n 20
  echo
  rm -f "$tmp"
}

echo "Testing fake shell at $BASE_URL"
probe "whoami" "whoami"
probe "hostname" "hostname"
probe "ip addr" "ip addr"

# POST path (DSP may use POST for larger payloads)
echo "=== POST cmd=whoami ==="
POST_BODY="$(curl -sS -o /tmp/fake_shell_post.out -w "%{http_code}" \
  --connect-timeout 5 --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "cmd=whoami" \
  "$BASE_URL" || true)"
echo "HTTP $POST_BODY"
if [[ "$POST_BODY" != "200" ]]; then
  cat /tmp/fake_shell_post.out >&2 || true
  fail "POST whoami expected HTTP 200"
fi
if [[ ! -s /tmp/fake_shell_post.out ]]; then
  fail "POST whoami empty body"
fi
sed '/^__EXIT_CODE:/d' /tmp/fake_shell_post.out | head -n 5
rm -f /tmp/fake_shell_post.out

echo
echo "PASS: fake shell command execution OK"
exit 0
