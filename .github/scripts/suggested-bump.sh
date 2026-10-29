#!/usr/bin/env bash
# The version bump a refresh calls for under the Versioning rule in the README, for the description
# of the pull request it opens.
#
#   suggested-bump.sh
#
# Minor when a store's trust anchors changed: a file under roots/ was added, removed or replaced,
# or a root moved between stores because its trust bits changed, which shows only in the
# TLS_ROOTS, EMAIL_ROOTS and ALL_ROOTS lists at the end of src/generated.rs. Patch otherwise, when
# only intermediate CA certificates, dates or other root metadata moved.
set -euo pipefail

store_lists() {
  sed -n '/^pub static TLS_ROOTS/,$p'
}

if [ -n "$(git status --porcelain --untracked-files=all -- roots)" ] ||
  [ "$(git show HEAD:src/generated.rs | store_lists)" != "$(store_lists < src/generated.rs)" ]; then
  echo "Suggested version bump: **minor**, because a store's trust anchors changed."
else
  echo "Suggested version bump: **patch**, because no store's trust anchors changed; only"
  echo "intermediate CA certificates, dates or other root metadata did."
fi
