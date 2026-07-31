#!/usr/bin/env bash
#
# Tests for scan-internal-identifiers.sh.
#
# A scanner that never fires is indistinguishable from no scanner, so every
# case below plants a value and asserts the scan *fails* — not merely that a
# clean tree passes. The planted values are assembled at run time and written
# into a throwaway repository under $TMPDIR; none of them is ever stored in
# this repository, which would defeat the purpose of the check.
#
# Usage: scan-internal-identifiers.test.sh

set -euo pipefail

SCANNER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scan-internal-identifiers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

# Build a fresh repo whose HEAD commit carries $2 as its message and $1 as the
# added file content, on top of a clean base commit. Echoes the range to scan.
scenario() {
  local content="$1" message="$2"
  local dir="$work/$RANDOM$RANDOM"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" config user.email t@example.invalid
  git -C "$dir" config user.name test
  echo "base" > "$dir/base.txt"
  git -C "$dir" add -A
  git -C "$dir" commit -qm "base commit"
  git -C "$dir" branch -q base
  printf '%s\n' "$content" > "$dir/change.txt"
  git -C "$dir" add -A
  git -C "$dir" commit -qm "$message"
  echo "$dir"
}

check() {
  local name="$1" expected="$2" dir="$3"
  local actual=0
  ( cd "$dir" && bash "$SCANNER" "base...HEAD" ) >/dev/null 2>&1 || actual=$?
  if [ "$actual" -eq "$expected" ]; then
    echo "  ok    $name"
    pass=$((pass + 1))
  else
    echo "  FAIL  $name (expected exit $expected, got $actual)"
    fail=$((fail + 1))
  fi
}

# Assembled at run time so the literals never appear in the repository.
ip_priv="10.$((90 + 9)).0.$((60 + 1))"          # an RFC1918 host address
ip_172="172.$((16 + 4)).5.9"
ip_192="192.168.$((40 + 4)).7"
res_sg="sg-0$(printf '%015x' $((0x123456789abcde)))"
res_eni="eni-0$(printf '%015x' $((0xfedcba987654)))"
# Assembled rather than written out for the same reason as the addresses: a
# literal PEM header here would be a finding in this very file, and the scanner
# correctly flagged it when it was one.
rule="$(printf -- '-%.0s' 1 2 3 4 5)"
pem_header="${rule}BEGIN OPENSSH PRIVATE KEY${rule}"

echo "scan-internal-identifiers.sh"

check "clean change passes" 0 \
  "$(scenario 'nothing interesting here' 'a clean commit message')"

check "private IP in an added line is caught" 1 \
  "$(scenario "host = $ip_priv" 'clean message')"

# The regression case: files clean, address only in the commit message. This is
# the shape of the incident the check exists for.
check "private IP in a COMMIT MESSAGE is caught" 1 \
  "$(scenario 'nothing interesting here' "used $ip_priv as the example value")"

check "172.16/12 range is caught" 1 \
  "$(scenario "peer $ip_172" 'clean message')"

check "192.168/16 range is caught" 1 \
  "$(scenario "gateway $ip_192" 'clean message')"

check "AWS security group id is caught" 1 \
  "$(scenario "group $res_sg" 'clean message')"

check "AWS ENI id in a commit message is caught" 1 \
  "$(scenario 'nothing interesting here' "detached $res_eni")"

check "PEM private key block is caught" 1 \
  "$(scenario "$pem_header" 'clean message')"

# Allow-listing behaviour.
check "documentation CIDR is allowed" 0 \
  "$(scenario 'the group already permits 10.0.0.0/8' 'clean message')"

check "RFC example address is allowed" 0 \
  "$(scenario 'blocked hosts include 192.168.1.1 and 10.0.0.1' 'clean message')"

check "inline escape hatch is honoured" 0 \
  "$(scenario "host = $ip_priv  # internal-scan:allow" 'clean message')"

# The reason allowed values are stripped from the line rather than exempting
# the whole line: otherwise a real address rides along beside a safe one.
check "real address alongside an allowed one is still caught" 1 \
  "$(scenario "permits 10.0.0.0/8 but the host is $ip_priv" 'clean message')"

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
