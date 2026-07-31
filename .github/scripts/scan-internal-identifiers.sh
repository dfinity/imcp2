#!/usr/bin/env bash
#
# Fail if a change introduces an internal network identifier — a private IP
# address, a cloud resource id, or a private key block — in either an added
# line of code or a commit message.
#
# Why commit messages. The incident this check exists to prevent was a commit
# *message* quoting a host's private address (see SECURITY.md's history and the
# repository's pre-publication scrub). The files were clean; the message that
# cleaned them was not. A scanner that only reads the diff sails straight past
# that, so both are scanned here and the workflow must check out with
# `fetch-depth: 0` or the message scan silently sees nothing.
#
# Why only generic patterns. This file is public. Encoding the organisation's
# actual address space, site codes or hostnames here would *be* the disclosure
# the check exists to prevent — a deny-list of secrets is a list of secrets. So
# the patterns below match structural classes that give nothing away. Values
# specific to this organisation belong in a GitHub secret-scanning custom
# pattern, which is not public and additionally blocks at push time rather than
# at pull-request time.
#
# Usage: scan-internal-identifiers.sh <git-range>
#   e.g. scan-internal-identifiers.sh origin/main...HEAD
#
# Exit: 0 clean, 1 findings, 2 usage error.

set -euo pipefail

RANGE="${1:-}"
if [ -z "$RANGE" ]; then
  echo "usage: $0 <git-range>   (e.g. origin/main...HEAD)" >&2
  exit 2
fi

# Structural classes only — see the header note on why nothing here is
# organisation-specific.
#   * RFC1918 IPv4 in all three ranges
#   * AWS-style resource identifiers
#   * PEM private key blocks (secret scanning also covers these; cheap to keep)
PATTERNS='(\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b)'
PATTERNS+='|(\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b)'
PATTERNS+='|(\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b)'
PATTERNS+='|(\b(vpc|subnet|sg|eni|igw|nat|rtb|acl|ami|vol|snap)-[0-9a-f]{8,17}\b)'
PATTERNS+='|(\bi-[0-9a-f]{8,17}\b)'
PATTERNS+='|(-----BEGIN [A-Z ]*PRIVATE KEY-----)'

# Canonical documentation and RFC-example values, removed from a line *before*
# it is scanned rather than exempting the whole line. Whole-line exemption
# would let a real address ride along on a line that also mentions 10.0.0.0/8 —
# and the SSRF tests in src/discover.rs legitimately contain several of these.
#
# The boundaries are load-bearing, not decoration. Without them the removal is
# a plain substring replacement, so an allowed value that is a *prefix* of a
# real one takes a bite out of it — append one digit to any bare address below
# and the strip leaves a lone digit behind, which matches nothing and passes
# silently. Longest alternatives first so the CIDR forms win over the bare
# addresses they contain.
ALLOWED='\b(10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16'
ALLOWED+='|10\.0\.0\.1|172\.16\.0\.1|192\.168\.1\.1|192\.168\.0\.1)\b'

# Per-line escape hatch. Deliberately an inline marker rather than a config
# file: it shows up in the diff, so a reviewer sees the suppression alongside
# the thing being suppressed.
ESCAPE='internal-scan:allow'

strip_allowed() { sed -E "s@${ALLOWED}@@g"; }

# `A...B` means two different things to the two commands below, and passing the
# caller's range to both is wrong for one of them:
#
#   git diff A...B      changes on B since the merge base   <- what we want
#   git rev-list A...B  symmetric difference: commits unique to EITHER side
#
# So rev-list with three dots also walks commits that are only on the base
# branch. A base commit that has nothing to do with this pull request would
# then fail its scan. Two dots gives exactly the commits B has and A does not.
REV_RANGE="${RANGE/.../..}"

findings=0
commits_scanned=0
lines_scanned=0

# --- commit messages in the range -------------------------------------------
while read -r sha; do
  [ -n "$sha" ] || continue
  commits_scanned=$((commits_scanned + 1))
  msg="$(git log -1 --format='%B' "$sha")"
  hit="$(printf '%s\n' "$msg" | grep -vE "$ESCAPE" | strip_allowed | grep -oE "$PATTERNS" || true)"
  if [ -n "$hit" ]; then
    echo "::error::commit $(git rev-parse --short "$sha") message contains an internal identifier: $(printf '%s' "$hit" | tr '\n' ' ')"
    findings=1
  fi
done < <(git rev-list "$REV_RANGE")

# --- added lines in the diff -------------------------------------------------
# Only added lines (`^+`), so pre-existing content does not fail every future
# build; the goal is to stop new introductions. `--no-color` and `-U0` keep the
# output parseable, and the `+++` header is skipped so filenames never match.
current_file=""
while IFS= read -r line; do
  case "$line" in
    '+++ b/'*) current_file="${line#+++ b/}" ; continue ;;
    '+'*) ;;
    *) continue ;;
  esac
  case "$line" in *"$ESCAPE"*) continue ;; esac
  lines_scanned=$((lines_scanned + 1))
  hit="$(printf '%s\n' "${line#+}" | strip_allowed | grep -oE "$PATTERNS" || true)"
  if [ -n "$hit" ]; then
    echo "::error file=${current_file}::added line contains an internal identifier: $(printf '%s' "$hit" | tr '\n' ' ')"
    findings=1
  fi
done < <(git diff --no-color -U0 "$RANGE")

if [ "$findings" -ne 0 ]; then
  cat >&2 <<'EOF'

Blocked: this change introduces an internal network identifier.

Replace it with prose that keeps the reasoning — "the production host's private
address" rather than the address itself. Identifiers that are genuinely safe to
publish (documentation examples, RFC sample values) can be marked by adding
`internal-scan:allow` to the line, which stays visible in review.
EOF
  exit 1
fi

# A scan that walked nothing prints exactly the same reassuring line as a scan
# that walked everything, so refuse to report success on an empty commit walk.
# In practice this means one thing: the workflow lost `fetch-depth: 0` and the
# shallow clone left rev-list with no history. Every pull request has at least
# one commit, so zero is never legitimate.
if [ "$commits_scanned" -eq 0 ]; then
  echo "::error::scanned 0 commits in range '$REV_RANGE' — the checkout is probably shallow (needs fetch-depth: 0). Refusing to report success." >&2
  exit 1
fi

# Deletion-only changes legitimately add no lines, so that count is reported
# rather than enforced.
echo "no internal identifiers introduced in $RANGE" \
     "(scanned $commits_scanned commit message(s), $lines_scanned added line(s))"
