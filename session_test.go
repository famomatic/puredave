package dave

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/famomatic/puredave/internal/tls"
	"github.com/famomatic/puredave/mls"
)

// testGateway simulates the DAVE voice gateway acting as MLS delivery
// service and external sender.
type testGateway struct {
	t       *testing.T
	key     *mls.SignaturePrivateKey
	ext     []byte
	groupID uint64
	epoch   uint64
	leaves  []string
	members map[string]*Session
}

func newTestGateway(t *testing.T) *testGateway {
	key, err := mls.GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	es := &mls.ExternalSender{SignatureKey: key.PublicKey(), Credential: mls.NewBasicCredential([]byte("gateway"))}
	ext, err := es.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &testGateway{t: t, key: key, ext: ext, groupID: 987654321, members: map[string]*Session{}}
}

func (g *testGateway) newSession(uid string, recognized ...string) *Session {
	s := NewSession(WithFailureCallback(func(src, reason string) { g.t.Logf("[%s] %s: %s", uid, src, reason) }))
	for _, r := range recognized {
		s.AddRecognizedUser(r)
	}
	s.Init(CurrentProtocolVersion, g.groupID, uid, nil)
	if err := s.SetExternalSender(g.ext); err != nil {
		g.t.Fatal(err)
	}
	return s
}

func (g *testGateway) proposals(ps ...*mls.Proposal) []byte {
	w := tls.NewWriter()
	w.U8(0)
	w.Vector(func(w *tls.Writer) {
		for _, p := range ps {
			m, err := mls.NewExternalProposal(bigEndianBytes(g.groupID), g.epoch, 0, p, g.key)
			if err != nil {
				g.t.Fatal(err)
			}
			b, _ := m.MarshalBinary()
			w.Raw(b)
		}
	})
	return w.Bytes()
}

func (g *testGateway) addProposal(s *Session) *mls.Proposal {
	b, err := s.MarshalledKeyPackage()
	if err != nil {
		g.t.Fatal(err)
	}
	kp, err := mls.UnmarshalKeyPackage(b)
	if err != nil {
		g.t.Fatal(err)
	}
	return &mls.Proposal{Type: mls.ProposalTypeAdd, KeyPackage: kp}
}

func split(t *testing.T, cw []byte) ([]byte, []byte) {
	_, n, err := mls.DecodeMLSMessage(cw)
	if err != nil {
		t.Fatal(err)
	}
	return cw[:n], cw[n:]
}

// round delivers proposals to all members, lets `winner` commit and
// announces the commit; it returns the welcome.
func (g *testGateway) round(body []byte, winner string) []byte {
	var commit, welcome []byte
	for _, uid := range g.uids() {
		cw, err := g.members[uid].ProcessProposals(body)
		if err != nil || cw == nil {
			g.t.Fatalf("%s: ProcessProposals: %v", uid, err)
		}
		if uid == winner {
			commit, welcome = split(g.t, cw)
		}
	}
	for _, uid := range g.uids() {
		if _, err := g.members[uid].ProcessCommit(commit); err != nil {
			g.t.Fatalf("%s: ProcessCommit: %v", uid, err)
		}
	}
	g.epoch++
	return welcome
}

func (g *testGateway) uids() []string {
	var out []string
	for _, u := range g.leaves {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

func (g *testGateway) create(committer, joiner string, cs, js *Session) {
	cw, err := cs.ProcessProposals(g.proposals(g.addProposal(js)))
	if err != nil || cw == nil {
		g.t.Fatalf("initial commit: %v", err)
	}
	commit, welcome := split(g.t, cw)
	if _, err := cs.ProcessCommit(commit); err != nil {
		g.t.Fatal(err)
	}
	roster, err := js.ProcessWelcome(welcome)
	if err != nil {
		g.t.Fatal(err)
	}
	if len(roster) != 2 {
		g.t.Fatalf("welcome roster has %d entries", len(roster))
	}
	g.epoch = 1
	g.leaves = []string{committer, joiner}
	g.members[committer] = cs
	g.members[joiner] = js
}

func (g *testGateway) add(uid string, s *Session, winner string) {
	welcome := g.round(g.proposals(g.addProposal(s)), winner)
	if _, err := s.ProcessWelcome(welcome); err != nil {
		g.t.Fatalf("%s: ProcessWelcome: %v", uid, err)
	}
	g.members[uid] = s
	for i, u := range g.leaves {
		if u == "" {
			g.leaves[i] = uid
			return
		}
	}
	g.leaves = append(g.leaves, uid)
}

func (g *testGateway) remove(uid, winner string) {
	for i, u := range g.leaves {
		if u == uid {
			g.leaves[i] = ""
			delete(g.members, uid)
			g.round(g.proposals(&mls.Proposal{Type: mls.ProposalTypeRemove, Removed: mls.LeafIndex(i)}), winner)
			return
		}
	}
	g.t.Fatalf("unknown member %s", uid)
}

func (g *testGateway) verify() {
	uids := g.uids()
	auth := g.members[uids[0]].LastEpochAuthenticator()
	for _, u := range uids {
		if !bytes.Equal(g.members[u].LastEpochAuthenticator(), auth) {
			g.t.Fatalf("%s disagrees on the epoch authenticator", u)
		}
		if len(g.members[u].Roster()) != len(uids) {
			g.t.Fatalf("%s roster size %d, want %d", u, len(g.members[u].Roster()), len(uids))
		}
	}
	for _, sender := range uids {
		e := NewEncryptor()
		e.AssignSsrcToCodec(1, CodecOpus)
		e.SetKeyRatchet(g.members[sender].KeyRatchet(sender))
		frame := []byte("opus frame from " + sender)
		ct := make([]byte, e.MaxCiphertextByteSize(MediaTypeAudio, len(frame)))
		n, r := e.Encrypt(MediaTypeAudio, 1, frame, ct)
		if r != EncryptSuccess {
			g.t.Fatal(r)
		}
		for _, receiver := range uids {
			d := NewDecryptor()
			d.TransitionToKeyRatchet(g.members[receiver].KeyRatchet(sender), DefaultTransitionDuration)
			out := make([]byte, n)
			m, r := d.Decrypt(MediaTypeAudio, ct[:n], out)
			if r != DecryptSuccess || !bytes.Equal(out[:m], frame) {
				g.t.Fatalf("%s could not decrypt %s: %v", receiver, sender, r)
			}
		}
	}
}

func userIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strconv.Itoa(100000000000000000 + i)
	}
	return out
}

func TestSessionGroupLifecycle(t *testing.T) {
	ids := userIDs(6)
	g := newTestGateway(t)
	g.create(ids[0], ids[1], g.newSession(ids[0], ids...), g.newSession(ids[1], ids...))
	g.verify()
	g.add(ids[2], g.newSession(ids[2], ids...), ids[1])
	g.verify()
	g.add(ids[3], g.newSession(ids[3], ids...), ids[2])
	g.verify()
	g.remove(ids[1], ids[3]) // commit with an update path to an unmerged member
	g.verify()
	g.add(ids[4], g.newSession(ids[4], ids...), ids[0])
	g.verify()
	g.remove(ids[0], ids[4])
	g.remove(ids[3], ids[2])
	g.verify()
	g.add(ids[5], g.newSession(ids[5], ids...), ids[4])
	g.verify()
}

func TestSessionRejectsUnrecognizedAdd(t *testing.T) {
	ids := userIDs(3)
	g := newTestGateway(t)
	a := g.newSession(ids[0]) // recognizes nobody else
	b := g.newSession(ids[1], ids...)
	if _, err := a.ProcessProposals(g.proposals(g.addProposal(b))); err == nil {
		t.Fatal("add proposal for an unrecognized user was accepted")
	}
	a.AddRecognizedUser(ids[1])
	if cw, err := a.ProcessProposals(g.proposals(g.addProposal(b))); err != nil || cw == nil {
		t.Fatalf("recognized add rejected: %v", err)
	}
}

func TestSessionRevokeProposals(t *testing.T) {
	ids := userIDs(3)
	g := newTestGateway(t)
	a := g.newSession(ids[0], ids...)
	b := g.newSession(ids[1], ids...)
	msg, err := mls.NewExternalProposal(bigEndianBytes(g.groupID), 0, 0, g.addProposal(b), g.key)
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := msg.MarshalBinary()
	w := tls.NewWriter()
	w.U8(0)
	w.Vector(func(w *tls.Writer) { w.Raw(mb) })
	if cw, err := a.ProcessProposals(w.Bytes()); err != nil || cw == nil {
		t.Fatalf("append: %v", err)
	}
	// Compute the ref as the session does and revoke it.
	state := a.pendingGroupState.Clone()
	ac, err := state.Unwrap(msg)
	if err != nil {
		t.Fatal(err)
	}
	rw := tls.NewWriter()
	rw.U8(1)
	rw.Vector(func(w *tls.Writer) { w.Opaque(state.ProposalRef(ac)) })
	cw, err := a.ProcessProposals(rw.Bytes())
	if err != nil || cw != nil {
		t.Fatalf("revoke: %x, %v", cw, err)
	}
	if _, err := a.ProcessProposals(rw.Bytes()); err == nil {
		t.Fatal("revoking an unknown ref succeeded")
	}
}

func TestSessionRejectsWelcomeWithWrongExternalSender(t *testing.T) {
	ids := userIDs(2)
	g := newTestGateway(t)
	other := newTestGateway(t)
	a := g.newSession(ids[0], ids...)
	b := other.newSession(ids[1], ids...) // expects a different external sender
	cw, err := a.ProcessProposals(g.proposals(g.addProposal(b)))
	if err != nil {
		t.Fatal(err)
	}
	_, welcome := split(t, cw)
	if _, err := b.ProcessWelcome(welcome); err == nil {
		t.Fatal("welcome with an unexpected external sender was accepted")
	}
}

func TestSessionCommitWithoutStateIsIgnored(t *testing.T) {
	s := NewSession()
	if _, err := s.ProcessCommit([]byte{0, 1}); !errors.Is(err, ErrIgnored) {
		t.Fatalf("got %v, want ErrIgnored", err)
	}
}

func TestPairwiseFingerprint(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt is slow")
	}
	ids := userIDs(2)
	g := newTestGateway(t)
	g.create(ids[0], ids[1], g.newSession(ids[0], ids...), g.newSession(ids[1], ids...))
	f1, err := g.members[ids[0]].PairwiseFingerprint(0, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	f2, err := g.members[ids[1]].PairwiseFingerprint(0, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(f1) != 64 || !bytes.Equal(f1, f2) {
		t.Fatalf("fingerprints differ: %x / %x", f1, f2)
	}
	if _, err := GenerateDisplayableCode(f1, 45, 5); err != nil {
		t.Fatal(err)
	}
}
