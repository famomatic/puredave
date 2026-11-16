package puregodave

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/famomatic/puredave/mls"
)

type callbacks struct {
	keyPackages    [][]byte
	commitWelcomes [][]byte
	ready          []uint16
	invalid        []uint16
}

func (c *callbacks) SendMLSKeyPackage(b []byte) error {
	c.keyPackages = append(c.keyPackages, b)
	return nil
}
func (c *callbacks) SendMLSCommitWelcome(b []byte) error {
	c.commitWelcomes = append(c.commitWelcomes, b)
	return nil
}
func (c *callbacks) SendReadyForTransition(id uint16) error {
	c.ready = append(c.ready, id)
	return nil
}
func (c *callbacks) SendInvalidCommitWelcome(id uint16) error {
	c.invalid = append(c.invalid, id)
	return nil
}

// externalProposals builds a dave_mls_proposals (27) body as the voice
// gateway would.
func externalProposals(t *testing.T, key *mls.SignaturePrivateKey, groupID uint64, kp []byte) []byte {
	pkg, err := mls.UnmarshalKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	gid := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		gid[i] = byte(groupID >> (8 * (7 - i)))
	}
	msg, err := mls.NewExternalProposal(gid, 0, 0, &mls.Proposal{Type: mls.ProposalTypeAdd, KeyPackage: pkg}, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= 1<<14 {
		t.Fatal("proposal too large for this helper")
	}
	return append([]byte{0, byte(len(b)>>8) | 0x40, byte(len(b))}, b...)
}

func TestSessionThroughGodaveInterface(t *testing.T) {
	const channel = 1234567890
	idA, idB := godave.UserID("100000000000000001"), godave.UserID("100000000000000002")
	cbA, cbB := &callbacks{}, &callbacks{}
	var a, b godave.Session = NewSession(slog.Default(), idA, cbA), NewSession(slog.Default(), idB, cbB)

	key, err := mls.GenerateSignaturePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ext, _ := (&mls.ExternalSender{SignatureKey: key.PublicKey(), Credential: mls.NewBasicCredential([]byte("gw"))}).MarshalBinary()

	for _, s := range []godave.Session{a, b} {
		s.SetChannelID(channel)
		s.AssignSsrcToCodec(1, godave.CodecOpus)
	}
	a.AddUser(idB)
	b.AddUser(idA)
	a.OnSelectProtocolAck(1)
	b.OnSelectProtocolAck(1)
	if a.Ready() || b.Ready() {
		t.Fatal("ready before the group exists")
	}
	a.OnDaveMLSExternalSenderPackage(ext)
	b.OnDaveMLSExternalSenderPackage(ext)

	a.OnDaveMLSProposals(externalProposals(t, key, channel, cbB.keyPackages[0]))
	if len(cbA.commitWelcomes) != 1 {
		t.Fatal("no commit")
	}
	cw := cbA.commitWelcomes[0]
	_, n, err := mls.DecodeMLSMessage(cw)
	if err != nil {
		t.Fatal(err)
	}
	a.OnDaveMLSPrepareCommitTransition(3, cw[:n])
	b.OnDaveMLSWelcome(3, cw[n:])
	a.OnDaveExecuteTransition(3)
	b.OnDaveExecuteTransition(3)
	if !a.Ready() || !b.Ready() || len(cbA.invalid)+len(cbB.invalid) != 0 {
		t.Fatal("E2EE not established")
	}

	frame := []byte("opus")
	enc := make([]byte, a.MaxEncryptedFrameSize(len(frame)))
	m, err := a.Encrypt(1, frame, enc)
	if err != nil {
		t.Fatal(err)
	}
	dec := make([]byte, b.MaxDecryptedFrameSize(idA, m))
	k, err := b.Decrypt(idA, enc[:m], dec)
	if err != nil || !bytes.Equal(dec[:k], frame) {
		t.Fatalf("decrypt: %v", err)
	}

	// Frames from users without a decryptor pass through unchanged.
	k, err = b.Decrypt("100000000000000009", frame, dec)
	if err != nil || !bytes.Equal(dec[:k], frame) {
		t.Fatalf("passthrough decrypt: %q %v", dec[:k], err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}
