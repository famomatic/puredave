# puredave

**A pure Go implementation of Discord's DAVE end-to-end encryption protocol.**

puredave is a complete Go rewrite of [libdave](https://github.com/discord/libdave),
Discord's reference implementation of the
[DAVE protocol](https://github.com/discord/dave-protocol) (audio/video E2EE for
voice channels, calls and Go Live). It has **no dependencies outside the Go
standard library**: no cgo, no C++ toolchain, no vcpkg, no BoringSSL/OpenSSL,
no mlspp. `CGO_ENABLED=0` builds work, and binaries are fully static.

```go
import dave "github.com/famomatic/puredave"
```

## Why

libdave is C++ on top of mlspp (Cisco's C++ MLS library) and BoringSSL/OpenSSL,
built through vcpkg. Using it from Go means cgo, a shared library that has to be
built or downloaded per platform, `pkg-config` metadata and `LD_LIBRARY_PATH`
at run time. puredave replaces all of that with `go get`.

## Features

| | libdave | puredave |
|---|---|---|
| MLS (RFC 9420), ciphersuite `DHKEMP256_AES128GCM_SHA256_P256` | mlspp | `mls` package, written from scratch |
| HPKE (RFC 9180) DHKEM(P-256) / HKDF-SHA256 / AES-128-GCM | mlspp/OpenSSL | built in |
| MLS session: key packages, external sender, proposals (append/revoke), commits, welcomes, recognized users | ✓ | ✓ (`Session`) |
| Sender key ratchets (`MLS-Exporter("Discord Secure Frames v0")` + hash ratchet) | ✓ | ✓ |
| Frame encryption, 64-bit truncated AES-GCM tags, ULEB128 nonce/ranges, `0xFAFA` marker | ✓ | ✓ (`Encryptor`) |
| Codec-aware transforms: Opus, VP8, VP9, H.264, H.265, AV1 | ✓ | ✓ |
| Receive side: passthrough, silence frames, multi-epoch transitions, generation wrap, nonce replay protection | ✓ | ✓ (`Decryptor`) |
| Epoch authenticator, displayable codes, pairwise fingerprints (scrypt) | ✓ | ✓ (scrypt built in) |
| Voice gateway transition state machine (opcodes 4, 11, 13, 21–31) | in each binding | ✓ (`GatewaySession`) |
| Persistent identity keys in platform key stores | ✓ | pluggable (`WithPersistedKeyProvider`) |

## Verification

* **RFC 9420 test vectors** (mlswg/mls-implementations) for ciphersuite 2: tree math,
  crypto basics, key schedule, transcript hashes, PSK secrets, Welcome, tree
  validation, TreeKEM, message encoding, and the passive-client Welcome and
  commit-handling scenarios.
* **Interoperability with libdave v1.3.0** ([`interop/`](interop)): a simulated
  voice gateway runs randomized groups that mix libdave and puredave members
  (up to 14 members, adds and removes, either side committing). All members must agree on every
  epoch authenticator and decrypt each other's frames. A byte-level
  differential test encrypts libdave's codec test frames plus random frames for
  all six codecs with both implementations under the same key ratchet, and
  requires **byte-identical output** and successful cross-decryption.
* Unit tests for the frame layer, sessions, transitions and the gateway state
  machine.

## Usage

### With a voice gateway connection

`GatewaySession` implements the client side of the DAVE protocol. Feed it
gateway events and send what it asks you to send:

```go
type callbacks struct{ conn *VoiceGateway }

func (c callbacks) SendMLSKeyPackage(kp []byte) error        { return c.conn.SendBinary(26, kp) }
func (c callbacks) SendMLSCommitWelcome(cw []byte) error     { return c.conn.SendBinary(28, cw) }
func (c callbacks) SendReadyForTransition(id uint16) error   { return c.conn.SendJSON(23, id) }
func (c callbacks) SendInvalidCommitWelcome(id uint16) error { return c.conn.SendJSON(31, id) }

s := dave.NewGatewaySession(selfUserID, callbacks{conn})
s.SetChannelID(channelID)
s.AssignSsrcToCodec(ssrc, dave.CodecOpus)

// identify (0): send "max_dave_protocol_version": dave.MaxSupportedProtocolVersion()
// select_protocol_ack (4):                s.OnSelectProtocolAck(d.DaveProtocolVersion)
// clients_connect (11) / disconnect (13): s.AddUser(id) / s.RemoveUser(id)
// 21 prepare_transition:                  s.OnPrepareTransition(d.TransitionID, d.ProtocolVersion)
// 22 execute_transition:                  s.OnExecuteTransition(d.TransitionID)
// 24 prepare_epoch:                       s.OnPrepareEpoch(d.Epoch, d.ProtocolVersion)
// 25 external_sender_package (binary):    s.OnExternalSenderPackage(payload)
// 27 proposals (binary):                  s.OnProposals(payload)
// 29 announce_commit_transition (binary): s.OnAnnounceCommitTransition(transitionID, payload)
// 30 welcome (binary):                    s.OnWelcome(transitionID, payload)

// Sending audio (hold frames while s.Ready() is false, i.e. during the
// MLS handshake, instead of sending them unencrypted):
buf := make([]byte, s.MaxEncryptedFrameSize(dave.MediaTypeAudio, len(opus)))
n, err := s.Encrypt(dave.MediaTypeAudio, ssrc, opus, buf)

// Receiving audio:
n, err = s.Decrypt(userID, dave.MediaTypeAudio, frame, out)
```

Binary payloads are the opcode body after the sequence number and opcode
byte (and after the transition ID for 29 and 30), as in libdave.

### Lower-level API

The building blocks mirror libdave one to one:

```go
sess := dave.NewSession()
key := sess.Init(dave.CurrentProtocolVersion, channelID, selfUserID, nil)
sess.SetExternalSender(externalSenderPackage)
kp, _ := sess.MarshalledKeyPackage()
commitWelcome, _ := sess.ProcessProposals(proposals)
roster, err := sess.ProcessCommit(commit)  // dave.ErrIgnored for soft rejections
roster, err = sess.ProcessWelcome(welcome)
ratchet := sess.KeyRatchet(userID)

enc := dave.NewEncryptor()
enc.SetKeyRatchet(ratchet)
dec := dave.NewDecryptor()
dec.TransitionToKeyRatchet(ratchet, dave.DefaultTransitionDuration)
```

The `mls` package is usable on its own as a small RFC 9420 implementation
(groups, external proposals, commits, Welcome processing, exporters).

## Packages

| Path | Contents |
|---|---|
| `github.com/famomatic/puredave` | DAVE: `Session`, `Encryptor`, `Decryptor`, key ratchets, codecs, fingerprints, `GatewaySession` |
| `github.com/famomatic/puredave/mls` | MLS for ciphersuite 2: TLS codec, HPKE, ratchet tree, TreeKEM, key schedule, messages, group state |
| `internal/tls`, `internal/scrypt` | TLS presentation language codec; RFC 7914 scrypt |
| `interop/` | Separate module (cgo) that cross-checks against libdave |

## Differences from libdave

* **Persistent identity keys.** libdave stores them in Keychain, the Windows
  credential store, Android keystore or files. puredave leaves storage to the
  application through `WithPersistedKeyProvider`; by default it uses transient
  keys, as bots usually do.
* **UpdatePath decryption.** When a member is an unmerged leaf under a parent
  node in the copath resolution, mlspp picks that parent and then has no key for
  it. In our randomized runs, libdave members occasionally reject such commits
  with `bad_optional_access` and need to be re-added. puredave picks the first
  covering resolution node it holds a private key for, so it accepts these
  commits. Both choices decrypt the same path secret.
* **GREASE.** mlspp may add GREASE values to leaf nodes. puredave accepts them
  but does not emit them.
* **PrivateMessage.** DAVE sends all handshake messages as PublicMessage, so the
  MLS layer implements only PublicMessage framing.
* **API shape.** The API follows Go conventions: methods return errors and
  values instead of optional outputs, and `PairwiseFingerprint` is synchronous
  (run it in a goroutine; scrypt is deliberately slow).

## Testing

```sh
go test ./...                       # unit tests
./scripts/fetch-test-vectors.sh     # download the RFC 9420 test vectors
go test ./mls/                      # now also runs the vectors

# Interoperability with libdave (requires libdave and dave.pc, e.g. via
# godave's scripts/libdave_install.sh)
cd interop && go run . -seed 1
```

## Status

The protocol and cryptography match libdave as verified above. puredave has
not yet been used in production against Discord's voice servers, so treat it
as new software and report issues.

## License

MIT. puredave is a port of libdave (MIT, © Discord) and follows the behavior
of mlspp (BSD-2-Clause, © Cisco Systems); see [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). DAVE is Discord's protocol; this
project is not affiliated with Discord.
