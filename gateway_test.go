package dave

import (
	"bytes"
	"testing"

	"github.com/famomatic/puredave/mls"
)

type recordingCallbacks struct {
	keyPackages    [][]byte
	commitWelcomes [][]byte
	ready          []uint16
	invalid        []uint16
}

func (r *recordingCallbacks) SendMLSKeyPackage(b []byte) error {
	r.keyPackages = append(r.keyPackages, b)
	return nil
}
func (r *recordingCallbacks) SendMLSCommitWelcome(b []byte) error {
	r.commitWelcomes = append(r.commitWelcomes, b)
	return nil
}
func (r *recordingCallbacks) SendReadyForTransition(id uint16) error {
	r.ready = append(r.ready, id)
	return nil
}
func (r *recordingCallbacks) SendInvalidCommitWelcome(id uint16) error {
	r.invalid = append(r.invalid, id)
	return nil
}

func TestGatewaySessionFlow(t *testing.T) {
	ids := userIDs(2)
	g := newTestGateway(t)
	cbA, cbB := &recordingCallbacks{}, &recordingCallbacks{}
	errs := func(op string, err error) { t.Errorf("%s: %v", op, err) }
	a := NewGatewaySession(ids[0], cbA, WithErrorHandler(errs))
	b := NewGatewaySession(ids[1], cbB, WithErrorHandler(errs))
	for _, s := range []*GatewaySession{a, b} {
		s.SetChannelID(g.groupID)
		s.AssignSsrcToCodec(1, CodecOpus)
	}
	a.AddUser(ids[1])
	b.AddUser(ids[0])
	if a.Ready() {
		t.Fatal("ready before DAVE was negotiated")
	}

	// select_protocol_ack (4) with DAVE enabled: both send key packages.
	a.OnSelectProtocolAck(1)
	b.OnSelectProtocolAck(1)
	if len(cbA.keyPackages) != 1 || len(cbB.keyPackages) != 1 {
		t.Fatal("key packages not sent")
	}
	if a.Ready() || b.Ready() {
		t.Fatal("ready before joining a group")
	}
	// Before the group exists, frames pass through.
	out := make([]byte, 64)
	if n, err := a.Encrypt(MediaTypeAudio, 1, []byte("plain"), out); err != nil || !bytes.Equal(out[:n], []byte("plain")) {
		t.Fatalf("pre-DAVE passthrough: %v", err)
	}

	a.OnExternalSenderPackage(g.ext)
	b.OnExternalSenderPackage(g.ext)

	// The gateway proposes adding B to A's pending group (and vice versa).
	kpB, err := mls.UnmarshalKeyPackage(cbB.keyPackages[0])
	if err != nil {
		t.Fatal(err)
	}
	a.OnProposals(g.proposals(&mls.Proposal{Type: mls.ProposalTypeAdd, KeyPackage: kpB}))
	if len(cbA.commitWelcomes) != 1 {
		t.Fatal("A did not commit")
	}
	commit, welcome := split(t, cbA.commitWelcomes[0])
	const tid = 7
	a.OnAnnounceCommitTransition(tid, commit)
	b.OnWelcome(tid, welcome)
	if len(cbA.ready) != 1 || len(cbB.ready) != 1 || cbA.ready[0] != tid || cbB.ready[0] != tid {
		t.Fatalf("ready_for_transition not sent: %v %v", cbA.ready, cbB.ready)
	}
	if !bytes.Equal(a.EpochAuthenticator(), b.EpochAuthenticator()) {
		t.Fatal("epoch authenticators differ")
	}
	if b.Ready() {
		t.Fatal("ready before the transition executed")
	}
	a.OnExecuteTransition(tid)
	b.OnExecuteTransition(tid)
	if !a.Ready() || !b.Ready() {
		t.Fatal("not ready after the transition executed")
	}

	frame := []byte("encrypted opus frame")
	ct := make([]byte, a.MaxEncryptedFrameSize(MediaTypeAudio, len(frame)))
	n, err := a.Encrypt(MediaTypeAudio, 1, frame, ct)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct[:len(frame)], frame) {
		t.Fatal("frame was not encrypted")
	}
	pt := make([]byte, n)
	m, err := b.Decrypt(ids[0], MediaTypeAudio, ct[:n], pt)
	if err != nil || !bytes.Equal(pt[:m], frame) {
		t.Fatalf("B could not decrypt A: %v", err)
	}

	// Downgrade to transport encryption (protocol version 0).
	a.OnPrepareTransition(9, DisabledVersion)
	a.OnExecuteTransition(9)
	if n, err := a.Encrypt(MediaTypeAudio, 1, frame, ct); err != nil || !bytes.Equal(ct[:n], frame) {
		t.Fatal("downgrade did not enable passthrough")
	}
	if !a.Ready() {
		t.Fatal("not ready with DAVE disabled")
	}
	if len(cbA.invalid)+len(cbB.invalid) != 0 {
		t.Fatal("unexpected invalid commit/welcome")
	}
}

func TestGatewaySessionReadyWhenDisabled(t *testing.T) {
	s := NewGatewaySession(userIDs(1)[0], &recordingCallbacks{})
	if s.Ready() {
		t.Fatal("ready before select_protocol_ack")
	}
	s.OnSelectProtocolAck(DisabledVersion)
	if !s.Ready() {
		t.Fatal("not ready with DAVE disabled")
	}
}
