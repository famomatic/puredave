#!/bin/sh
# Fetches the RFC 9420 interoperability test vectors used by the mls package
# tests into testdata/mls-vectors. The vectors are not vendored.
set -eu
COMMIT=2034fe72e0c805a683ba76165660c834f2a8142a
BASE="https://raw.githubusercontent.com/mlswg/mls-implementations/$COMMIT/test-vectors"
DIR="$(cd "$(dirname "$0")/.." && pwd)/testdata/mls-vectors"
mkdir -p "$DIR"
for f in crypto-basics deserialization key-schedule messages passive-client-handling-commit \
	passive-client-random passive-client-welcome psk_secret transcript-hashes tree-math \
	tree-validation treekem welcome; do
	curl -fsSL -o "$DIR/$f.json" "$BASE/$f.json"
done
echo "test vectors written to $DIR"
