# interop

Cross-checks puredave against Discord's libdave. This is a separate Go module
because it uses cgo; the main puredave module stays dependency-free.

It simulates the DAVE voice gateway (external sender, proposals, commit
selection, welcomes) for groups that mix libdave and puredave members, with
randomized adds, removes and committers. After every epoch all members must
agree on the epoch authenticator and decrypt each other's frames. At the end
a differential test encrypts libdave's codec test frames and random frames for
all six codecs with both implementations under the same key ratchet and
requires byte-identical output and cross-decryption.

Requires libdave with `dave.pc` on the `pkg-config` path (for example via
godave's `scripts/libdave_install.sh`).

```sh
go run . -seed 1 -rounds 40
```

Lines starting with `KNOWN:` are commits that a libdave member rejected with
mlspp's `bad_optional_access` (see "Differences from libdave" in the top-level
README). Such members are evicted, as the voice gateway would do after an
invalid-commit report. Any rejection by a puredave member fails the run.
