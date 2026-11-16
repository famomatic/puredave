package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/famomatic/puredave/internal/tls"
)

// The RFC 9420 interoperability test vectors are fetched by
// scripts/fetch-test-vectors.sh into testdata/mls-vectors. Tests that need
// them are skipped when they are absent.

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s *string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == nil {
		*h = nil
		return nil
	}
	v, err := hex.DecodeString(*s)
	if err != nil {
		return err
	}
	*h = v
	return nil
}

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("MLS_TEST_VECTORS")
	if dir == "" {
		dir = filepath.Join("..", "testdata", "mls-vectors")
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		t.Skipf("test vectors unavailable (%v); run scripts/fetch-test-vectors.sh", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestTreeMathVectors(t *testing.T) {
	var vs []struct {
		NLeaves uint32    `json:"n_leaves"`
		NNodes  uint32    `json:"n_nodes"`
		Root    uint32    `json:"root"`
		Left    []*uint32 `json:"left"`
		Right   []*uint32 `json:"right"`
		Parent  []*uint32 `json:"parent"`
		Sibling []*uint32 `json:"sibling"`
	}
	loadVectors(t, "tree-math", &vs)
	for _, v := range vs {
		if NodeCount(v.NLeaves) != v.NNodes {
			t.Fatalf("n_nodes(%d) = %d, want %d", v.NLeaves, NodeCount(v.NLeaves), v.NNodes)
		}
		root := Root(v.NLeaves)
		if uint32(root) != v.Root {
			t.Fatalf("root(%d) = %d, want %d", v.NLeaves, root, v.Root)
		}
		for i := uint32(0); i < v.NNodes; i++ {
			n := NodeIndex(i)
			check := func(name string, got NodeIndex, ok bool, want *uint32) {
				if want == nil {
					if ok {
						t.Fatalf("%s(%d) in %d leaves should be null, got %d", name, i, v.NLeaves, got)
					}
					return
				}
				if !ok || uint32(got) != *want {
					t.Fatalf("%s(%d) in %d leaves = %d, want %d", name, i, v.NLeaves, got, *want)
				}
			}
			check("left", n.Left(), !n.IsLeaf(), v.Left[i])
			check("right", n.Right(), !n.IsLeaf(), v.Right[i])
			check("parent", n.Parent(), n != root, v.Parent[i])
			check("sibling", n.Sibling(), n != root, v.Sibling[i])
		}
	}
}

func TestDeserializationVectors(t *testing.T) {
	var vs []struct {
		Header hexBytes `json:"vlbytes_header"`
		Length int      `json:"length"`
	}
	loadVectors(t, "deserialization", &vs)
	for _, v := range vs {
		r := tls.NewReader(v.Header)
		if got := r.Varint(); got != v.Length || r.Err() != nil {
			t.Fatalf("varint %x = %d (%v), want %d", []byte(v.Header), got, r.Err(), v.Length)
		}
		w := tls.NewWriter()
		w.Varint(v.Length)
		if !bytes.Equal(w.Bytes(), v.Header) {
			t.Fatalf("encode %d = %x, want %x", v.Length, w.Bytes(), []byte(v.Header))
		}
	}
}

func TestCryptoBasicsVectors(t *testing.T) {
	var vs []struct {
		CipherSuite CipherSuite `json:"cipher_suite"`
		RefHash     struct {
			Label string   `json:"label"`
			Out   hexBytes `json:"out"`
			Value hexBytes `json:"value"`
		} `json:"ref_hash"`
		ExpandWithLabel struct {
			Secret  hexBytes `json:"secret"`
			Label   string   `json:"label"`
			Context hexBytes `json:"context"`
			Length  int      `json:"length"`
			Out     hexBytes `json:"out"`
		} `json:"expand_with_label"`
		DeriveSecret struct {
			Label  string   `json:"label"`
			Out    hexBytes `json:"out"`
			Secret hexBytes `json:"secret"`
		} `json:"derive_secret"`
		DeriveTreeSecret struct {
			Secret     hexBytes `json:"secret"`
			Label      string   `json:"label"`
			Generation uint32   `json:"generation"`
			Length     int      `json:"length"`
			Out        hexBytes `json:"out"`
		} `json:"derive_tree_secret"`
		SignWithLabel struct {
			Priv      hexBytes `json:"priv"`
			Pub       hexBytes `json:"pub"`
			Content   hexBytes `json:"content"`
			Label     string   `json:"label"`
			Signature hexBytes `json:"signature"`
		} `json:"sign_with_label"`
		EncryptWithLabel struct {
			Priv       hexBytes `json:"priv"`
			Pub        hexBytes `json:"pub"`
			Label      string   `json:"label"`
			Context    hexBytes `json:"context"`
			Plaintext  hexBytes `json:"plaintext"`
			KEMOutput  hexBytes `json:"kem_output"`
			Ciphertext hexBytes `json:"ciphertext"`
		} `json:"encrypt_with_label"`
	}
	loadVectors(t, "crypto-basics", &vs)
	ran := false
	for _, v := range vs {
		cs := v.CipherSuite
		if !cs.Supported() {
			continue
		}
		ran = true
		if got := cs.RefHash(v.RefHash.Label, v.RefHash.Value); !bytes.Equal(got, v.RefHash.Out) {
			t.Errorf("RefHash = %x", got)
		}
		e := v.ExpandWithLabel
		if got := cs.ExpandWithLabel(e.Secret, e.Label, e.Context, e.Length); !bytes.Equal(got, e.Out) {
			t.Errorf("ExpandWithLabel = %x", got)
		}
		if got := cs.DeriveSecret(v.DeriveSecret.Secret, v.DeriveSecret.Label); !bytes.Equal(got, v.DeriveSecret.Out) {
			t.Errorf("DeriveSecret = %x", got)
		}
		d := v.DeriveTreeSecret
		if got := cs.DeriveTreeSecret(d.Secret, d.Label, d.Generation, d.Length); !bytes.Equal(got, d.Out) {
			t.Errorf("DeriveTreeSecret = %x", got)
		}
		s := v.SignWithLabel
		if !SignaturePublicKey(s.Pub).VerifyWithLabel(s.Label, s.Content, s.Signature) {
			t.Errorf("VerifyWithLabel failed")
		}
		sk, err := ParseSignaturePrivateKey(s.Priv)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sk.PublicKey(), s.Pub) {
			t.Errorf("signature public key mismatch")
		}
		sig, err := sk.SignWithLabel(s.Label, s.Content)
		if err != nil || !SignaturePublicKey(s.Pub).VerifyWithLabel(s.Label, s.Content, sig) {
			t.Errorf("SignWithLabel round trip failed: %v", err)
		}
		x := v.EncryptWithLabel
		hk, err := ParseHPKEPrivateKey(x.Priv)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hk.PublicKey(), x.Pub) {
			t.Errorf("HPKE public key mismatch")
		}
		pt, err := hk.DecryptWithLabel(x.Label, x.Context, &HPKECiphertext{KEMOutput: x.KEMOutput, Ciphertext: x.Ciphertext})
		if err != nil || !bytes.Equal(pt, x.Plaintext) {
			t.Errorf("DecryptWithLabel = %x, %v", pt, err)
		}
		ct, err := EncryptWithLabel(HPKEPublicKey(x.Pub), x.Label, x.Context, x.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := hk.DecryptWithLabel(x.Label, x.Context, ct); err != nil || !bytes.Equal(pt, x.Plaintext) {
			t.Errorf("EncryptWithLabel round trip failed: %v", err)
		}
	}
	if !ran {
		t.Skip("no vectors for supported ciphersuites")
	}
}

func TestKeyScheduleVectors(t *testing.T) {
	var vs []struct {
		CipherSuite       CipherSuite `json:"cipher_suite"`
		GroupID           hexBytes    `json:"group_id"`
		InitialInitSecret hexBytes    `json:"initial_init_secret"`
		Epochs            []struct {
			TreeHash                hexBytes `json:"tree_hash"`
			CommitSecret            hexBytes `json:"commit_secret"`
			PSKSecret               hexBytes `json:"psk_secret"`
			ConfirmedTranscriptHash hexBytes `json:"confirmed_transcript_hash"`
			GroupContext            hexBytes `json:"group_context"`
			JoinerSecret            hexBytes `json:"joiner_secret"`
			WelcomeSecret           hexBytes `json:"welcome_secret"`
			InitSecret              hexBytes `json:"init_secret"`
			SenderDataSecret        hexBytes `json:"sender_data_secret"`
			EncryptionSecret        hexBytes `json:"encryption_secret"`
			ExporterSecret          hexBytes `json:"exporter_secret"`
			EpochAuthenticator      hexBytes `json:"epoch_authenticator"`
			ExternalSecret          hexBytes `json:"external_secret"`
			ConfirmationKey         hexBytes `json:"confirmation_key"`
			MembershipKey           hexBytes `json:"membership_key"`
			ResumptionPSK           hexBytes `json:"resumption_psk"`
			ExternalPub             hexBytes `json:"external_pub"`
			Exporter                struct {
				Label   string   `json:"label"` // used verbatim as the label
				Context hexBytes `json:"context"`
				Length  int      `json:"length"`
				Secret  hexBytes `json:"secret"`
			} `json:"exporter"`
		} `json:"epochs"`
	}
	loadVectors(t, "key-schedule", &vs)
	for _, v := range vs {
		cs := v.CipherSuite
		if !cs.Supported() {
			continue
		}
		ks := &keyScheduleEpoch{suite: cs, initSecret: v.InitialInitSecret}
		for i, e := range v.Epochs {
			gc := GroupContext{
				CipherSuite:             cs,
				GroupID:                 v.GroupID,
				Epoch:                   uint64(i),
				TreeHash:                e.TreeHash,
				ConfirmedTranscriptHash: e.ConfirmedTranscriptHash,
			}
			ctx := gc.Bytes()
			if !bytes.Equal(ctx, e.GroupContext) {
				t.Fatalf("epoch %d group context = %x", i, ctx)
			}
			next := ks.next(e.CommitSecret, e.PSKSecret, nil, e.ConfirmedTranscriptHash, ctx)
			checks := []struct {
				name      string
				got, want []byte
			}{
				{"joiner_secret", next.joinerSecret, e.JoinerSecret},
				{"init_secret", next.initSecret, e.InitSecret},
				{"sender_data_secret", next.senderDataSecret, e.SenderDataSecret},
				{"encryption_secret", next.encryptionSecret, e.EncryptionSecret},
				{"exporter_secret", next.exporterSecret, e.ExporterSecret},
				{"epoch_authenticator", next.epochAuthenticator, e.EpochAuthenticator},
				{"external_secret", next.externalSecret, e.ExternalSecret},
				{"confirmation_key", next.confirmationKey, e.ConfirmationKey},
				{"membership_key", next.membershipKey, e.MembershipKey},
				{"resumption_psk", next.resumptionPSK, e.ResumptionPSK},
			}
			for _, c := range checks {
				if !bytes.Equal(c.got, c.want) {
					t.Fatalf("epoch %d %s = %x, want %x", i, c.name, c.got, c.want)
				}
			}
			ws := cs.DeriveSecret(cs.Extract(next.joinerSecret, e.PSKSecret), "welcome")
			if !bytes.Equal(ws, e.WelcomeSecret) {
				t.Fatalf("epoch %d welcome_secret = %x", i, ws)
			}
			ext, err := DeriveHPKEPrivateKey(next.externalSecret)
			if err != nil || !bytes.Equal(ext.PublicKey(), e.ExternalPub) {
				t.Fatalf("epoch %d external_pub mismatch: %v", i, err)
			}
			if got := next.export(e.Exporter.Label, e.Exporter.Context, e.Exporter.Length); !bytes.Equal(got, e.Exporter.Secret) {
				t.Fatalf("epoch %d exporter = %x", i, got)
			}
			ks = next
		}
	}
}

func TestTranscriptHashVectors(t *testing.T) {
	var vs []struct {
		CipherSuite                  CipherSuite `json:"cipher_suite"`
		ConfirmationKey              hexBytes    `json:"confirmation_key"`
		AuthenticatedContent         hexBytes    `json:"authenticated_content"`
		InterimTranscriptHashBefore  hexBytes    `json:"interim_transcript_hash_before"`
		ConfirmedTranscriptHashAfter hexBytes    `json:"confirmed_transcript_hash_after"`
		InterimTranscriptHashAfter   hexBytes    `json:"interim_transcript_hash_after"`
	}
	loadVectors(t, "transcript-hashes", &vs)
	for _, v := range vs {
		cs := v.CipherSuite
		if !cs.Supported() {
			continue
		}
		ac := &AuthenticatedContent{}
		if err := decode(v.AuthenticatedContent, ac.unmarshal); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ac.Bytes(), v.AuthenticatedContent) {
			t.Fatal("AuthenticatedContent round trip mismatch")
		}
		th := transcriptHash{suite: cs, interim: v.InterimTranscriptHashBefore}
		th.confirmed = th.newConfirmed(ac.confirmedTranscriptHashInput())
		if !bytes.Equal(th.confirmed, v.ConfirmedTranscriptHashAfter) {
			t.Fatalf("confirmed = %x", th.confirmed)
		}
		if tag := cs.MAC(v.ConfirmationKey, th.confirmed); !bytes.Equal(tag, ac.Auth.ConfirmationTag) {
			t.Fatalf("confirmation tag = %x", tag)
		}
		th.updateInterim(ac.Auth.ConfirmationTag)
		if !bytes.Equal(th.interim, v.InterimTranscriptHashAfter) {
			t.Fatalf("interim = %x", th.interim)
		}
	}
}

func TestPSKSecretVectors(t *testing.T) {
	var vs []struct {
		CipherSuite CipherSuite `json:"cipher_suite"`
		PSKs        []struct {
			PSKID    hexBytes `json:"psk_id"`
			PSK      hexBytes `json:"psk"`
			PSKNonce hexBytes `json:"psk_nonce"`
		} `json:"psks"`
		PSKSecret hexBytes `json:"psk_secret"`
	}
	loadVectors(t, "psk_secret", &vs)
	for _, v := range vs {
		if !v.CipherSuite.Supported() {
			continue
		}
		var psks []PSKWithSecret
		for _, p := range v.PSKs {
			psks = append(psks, PSKWithSecret{
				ID:     PreSharedKeyID{Type: PSKTypeExternal, PSKID: p.PSKID, Nonce: p.PSKNonce},
				Secret: p.PSK,
			})
		}
		if got := makePSKSecret(v.CipherSuite, psks); !bytes.Equal(got, v.PSKSecret) {
			t.Fatalf("psk_secret = %x, want %x", got, []byte(v.PSKSecret))
		}
	}
}

func TestWelcomeVectors(t *testing.T) {
	var vs []struct {
		CipherSuite CipherSuite `json:"cipher_suite"`
		InitPriv    hexBytes    `json:"init_priv"`
		KeyPackage  hexBytes    `json:"key_package"`
		SignerPub   hexBytes    `json:"signer_pub"`
		Welcome     hexBytes    `json:"welcome"`
	}
	loadVectors(t, "welcome", &vs)
	for _, v := range vs {
		if !v.CipherSuite.Supported() {
			continue
		}
		kpMsg, err := UnmarshalMLSMessage(v.KeyPackage)
		if err != nil {
			t.Fatal(err)
		}
		wMsg, err := UnmarshalMLSMessage(v.Welcome)
		if err != nil {
			t.Fatal(err)
		}
		wl := wMsg.Welcome
		i, ok := wl.find(kpMsg.KeyPackage.Ref())
		if !ok {
			t.Fatal("key package not found in welcome")
		}
		initPriv, err := ParseHPKEPrivateKey(v.InitPriv)
		if err != nil {
			t.Fatal(err)
		}
		gs, err := wl.decryptSecrets(i, initPriv)
		if err != nil {
			t.Fatal(err)
		}
		gi, err := wl.decryptGroupInfo(gs.JoinerSecret, makePSKSecret(v.CipherSuite, nil))
		if err != nil {
			t.Fatal(err)
		}
		if !gi.verify(SignaturePublicKey(v.SignerPub)) {
			t.Fatal("GroupInfo signature invalid")
		}
		ks := newKeyScheduleFromJoiner(v.CipherSuite, gs.JoinerSecret, v.CipherSuite.Zero(), gi.GroupContext.ConfirmedTranscriptHash, gi.GroupContext.Bytes())
		if !bytes.Equal(ks.confirmationTag, gi.ConfirmationTag) {
			t.Fatal("confirmation tag mismatch")
		}
	}
}

func TestTreeValidationVectors(t *testing.T) {
	var vs []struct {
		CipherSuite CipherSuite   `json:"cipher_suite"`
		Tree        hexBytes      `json:"tree"`
		GroupID     hexBytes      `json:"group_id"`
		TreeHashes  []hexBytes    `json:"tree_hashes"`
		Resolutions [][]NodeIndex `json:"resolutions"`
	}
	loadVectors(t, "tree-validation", &vs)
	for n, v := range vs {
		if !v.CipherSuite.Supported() {
			continue
		}
		tree, err := UnmarshalRatchetTree(v.CipherSuite, v.Tree)
		if err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
		if b, _ := tree.MarshalBinary(); !bytes.Equal(b, v.Tree) {
			t.Fatalf("vector %d: tree round trip mismatch", n)
		}
		tree.setHashAll()
		for i, want := range v.TreeHashes {
			if got := tree.hash(NodeIndex(i)); !bytes.Equal(got, want) {
				t.Fatalf("vector %d: tree hash %d = %x", n, i, got)
			}
		}
		for i, want := range v.Resolutions {
			got := tree.resolve(NodeIndex(i))
			if len(got) != len(want) {
				t.Fatalf("vector %d: resolution %d = %v, want %v", n, i, got, want)
			}
			for k := range got {
				if got[k] != want[k] {
					t.Fatalf("vector %d: resolution %d = %v, want %v", n, i, got, want)
				}
			}
		}
		if !tree.parentHashValid() {
			t.Fatalf("vector %d: parent hashes invalid", n)
		}
		s := &State{suite: v.CipherSuite, groupID: v.GroupID, tree: tree}
		if !s.validateTree() {
			t.Fatalf("vector %d: tree failed validation", n)
		}
	}
}

func TestTreeKEMVectors(t *testing.T) {
	var vs []struct {
		CipherSuite             CipherSuite `json:"cipher_suite"`
		GroupID                 hexBytes    `json:"group_id"`
		Epoch                   uint64      `json:"epoch"`
		ConfirmedTranscriptHash hexBytes    `json:"confirmed_transcript_hash"`
		RatchetTree             hexBytes    `json:"ratchet_tree"`
		LeavesPrivate           []struct {
			Index          LeafIndex `json:"index"`
			EncryptionPriv hexBytes  `json:"encryption_priv"`
			SignaturePriv  hexBytes  `json:"signature_priv"`
			PathSecrets    []struct {
				Node       NodeIndex `json:"node"`
				PathSecret hexBytes  `json:"path_secret"`
			} `json:"path_secrets"`
		} `json:"leaves_private"`
		UpdatePaths []struct {
			Sender        LeafIndex  `json:"sender"`
			UpdatePath    hexBytes   `json:"update_path"`
			PathSecrets   []hexBytes `json:"path_secrets"`
			CommitSecret  hexBytes   `json:"commit_secret"`
			TreeHashAfter hexBytes   `json:"tree_hash_after"`
		} `json:"update_paths"`
	}
	loadVectors(t, "treekem", &vs)
	for n, v := range vs {
		cs := v.CipherSuite
		if !cs.Supported() {
			continue
		}
		base, err := UnmarshalRatchetTree(cs, v.RatchetTree)
		if err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
		base.setHashAll()
		privs := map[LeafIndex]*treePrivateKey{}
		for _, lp := range v.LeavesPrivate {
			k, err := ParseHPKEPrivateKey(lp.EncryptionPriv)
			if err != nil {
				t.Fatal(err)
			}
			p := soloTreePrivateKey(cs, lp.Index, k)
			for _, ps := range lp.PathSecrets {
				p.pathSecrets[ps.Node] = ps.PathSecret
			}
			if !p.consistent(base) {
				t.Fatalf("vector %d: leaf %d private key inconsistent", n, lp.Index)
			}
			privs[lp.Index] = p
		}
		for u, up := range v.UpdatePaths {
			path := &UpdatePath{}
			if err := decode(up.UpdatePath, path.unmarshal); err != nil {
				t.Fatalf("vector %d path %d: %v", n, u, err)
			}
			tree := base.clone()
			if !tree.parentHashValidPath(up.Sender, path) {
				t.Fatalf("vector %d path %d: parent hash invalid", n, u)
			}
			if !path.LeafNode.Verify(v.GroupID, up.Sender) {
				t.Fatalf("vector %d path %d: leaf signature invalid", n, u)
			}
			if err := tree.merge(up.Sender, path); err != nil {
				t.Fatal(err)
			}
			if got := tree.rootHash(); !bytes.Equal(got, up.TreeHashAfter) {
				t.Fatalf("vector %d path %d: tree hash after = %x", n, u, got)
			}
			ctx := (&GroupContext{
				CipherSuite:             cs,
				GroupID:                 v.GroupID,
				Epoch:                   v.Epoch,
				TreeHash:                up.TreeHashAfter,
				ConfirmedTranscriptHash: v.ConfirmedTranscriptHash,
			}).Bytes()
			for _, lp := range v.LeavesPrivate {
				want := up.PathSecrets[lp.Index]
				if lp.Index == up.Sender {
					continue
				}
				priv := privs[lp.Index].clone()
				coords, err := tree.decapCoords(lp.Index, up.Sender, nil, priv)
				if err != nil {
					t.Fatalf("vector %d path %d leaf %d: %v", n, u, lp.Index, err)
				}
				ct := &path.Nodes[coords.ancestorNodeIndex].EncryptedPathSecret[coords.resolutionNodeIndex]
				if err := priv.decap(up.Sender, tree, ctx, coords.resolutionNode, ct); err != nil {
					t.Fatalf("vector %d path %d leaf %d: %v", n, u, lp.Index, err)
				}
				anc := lp.Index.Ancestor(up.Sender)
				if !bytes.Equal(priv.pathSecrets[anc], want) {
					t.Fatalf("vector %d path %d leaf %d: path secret mismatch", n, u, lp.Index)
				}
				if !bytes.Equal(priv.updateSecret, up.CommitSecret) {
					t.Fatalf("vector %d path %d leaf %d: commit secret mismatch", n, u, lp.Index)
				}
			}
		}
	}
}

func TestMessagesVectors(t *testing.T) {
	var vs []map[string]hexBytes
	loadVectors(t, "messages", &vs)
	type codec struct {
		key string
		fn  func(b []byte) ([]byte, error)
	}
	roundTrip := func(un func(r *tls.Reader), m func(w *tls.Writer)) func([]byte) ([]byte, error) {
		return func(b []byte) ([]byte, error) {
			if err := decode(b, un); err != nil {
				return nil, err
			}
			return finish(m)
		}
	}
	for i, v := range vs {
		var (
			kp     KeyPackage
			tree   = newRatchetTree(CipherSuiteP256)
			gs     GroupSecrets
			add    Proposal
			update Proposal
			remove Proposal
			psk    Proposal
			reinit Proposal
			extI   Proposal
			gce    Proposal
			commit Commit
		)
		codecs := []codec{
			{"mls_welcome", func(b []byte) ([]byte, error) {
				m, err := UnmarshalMLSMessage(b)
				if err != nil {
					return nil, err
				}
				return m.MarshalBinary()
			}},
			{"mls_group_info", func(b []byte) ([]byte, error) {
				m, err := UnmarshalMLSMessage(b)
				if err != nil {
					return nil, err
				}
				return m.MarshalBinary()
			}},
			{"mls_key_package", func(b []byte) ([]byte, error) {
				m, err := UnmarshalMLSMessage(b)
				if err != nil {
					return nil, err
				}
				kp = *m.KeyPackage
				return m.MarshalBinary()
			}},
			{"ratchet_tree", roundTrip(tree.unmarshal, tree.marshal)},
			{"group_secrets", roundTrip(gs.unmarshal, gs.marshal)},
			{"add_proposal", roundTrip(func(r *tls.Reader) {
				add.Type = ProposalTypeAdd
				add.KeyPackage = &KeyPackage{}
				add.KeyPackage.unmarshal(r)
			}, func(w *tls.Writer) { add.KeyPackage.marshal(w) })},
			{"update_proposal", roundTrip(func(r *tls.Reader) { update.LeafNode = &LeafNode{}; update.LeafNode.unmarshal(r) }, func(w *tls.Writer) { update.LeafNode.marshal(w) })},
			{"remove_proposal", roundTrip(func(r *tls.Reader) { remove.Removed = LeafIndex(r.U32()) }, func(w *tls.Writer) { w.U32(uint32(remove.Removed)) })},
			{"pre_shared_key_proposal", roundTrip(func(r *tls.Reader) { psk.PSK = &PreSharedKeyID{}; psk.PSK.unmarshal(r) }, func(w *tls.Writer) { psk.PSK.marshal(w) })},
			{"re_init_proposal", roundTrip(func(r *tls.Reader) {
				reinit.ReInitGroupID = r.Opaque()
				reinit.ReInitVersion = r.U16()
				reinit.ReInitCipherSuite = CipherSuite(r.U16())
				reinit.ReInitExtensions.unmarshal(r)
			}, func(w *tls.Writer) {
				w.Opaque(reinit.ReInitGroupID)
				w.U16(reinit.ReInitVersion)
				w.U16(uint16(reinit.ReInitCipherSuite))
				reinit.ReInitExtensions.marshal(w)
			})},
			{"external_init_proposal", roundTrip(func(r *tls.Reader) { extI.KEMOutput = r.Opaque() }, func(w *tls.Writer) { w.Opaque(extI.KEMOutput) })},
			{"group_context_extensions_proposal", roundTrip(func(r *tls.Reader) { gce.Extensions.unmarshal(r) }, func(w *tls.Writer) { gce.Extensions.marshal(w) })},
			{"commit", roundTrip(commit.unmarshal, commit.marshal)},
			{"public_message_application", func(b []byte) ([]byte, error) {
				m, err := UnmarshalMLSMessage(b)
				if err != nil {
					return nil, err
				}
				return m.MarshalBinary()
			}},
			{"public_message_proposal", func(b []byte) ([]byte, error) {
				m, err := UnmarshalMLSMessage(b)
				if err != nil {
					return nil, err
				}
				return m.MarshalBinary()
			}},
			{"public_message_commit", func(b []byte) ([]byte, error) {
				m, err := UnmarshalMLSMessage(b)
				if err != nil {
					return nil, err
				}
				return m.MarshalBinary()
			}},
		}
		for _, c := range codecs {
			in := v[c.key]
			out, err := c.fn(in)
			if err != nil {
				t.Fatalf("vector %d %s: %v", i, c.key, err)
			}
			if !bytes.Equal(out, in) {
				t.Fatalf("vector %d %s: round trip mismatch", i, c.key)
			}
		}
		_ = kp
	}
}

type passiveClientVector struct {
	CipherSuite  CipherSuite `json:"cipher_suite"`
	ExternalPSKs []struct {
		PSKID hexBytes `json:"psk_id"`
		PSK   hexBytes `json:"psk"`
	} `json:"external_psks"`
	KeyPackage                hexBytes `json:"key_package"`
	SignaturePriv             hexBytes `json:"signature_priv"`
	EncryptionPriv            hexBytes `json:"encryption_priv"`
	InitPriv                  hexBytes `json:"init_priv"`
	Welcome                   hexBytes `json:"welcome"`
	RatchetTree               hexBytes `json:"ratchet_tree"`
	InitialEpochAuthenticator hexBytes `json:"initial_epoch_authenticator"`
	Epochs                    []struct {
		Proposals          []hexBytes `json:"proposals"`
		Commit             hexBytes   `json:"commit"`
		EpochAuthenticator hexBytes   `json:"epoch_authenticator"`
	} `json:"epochs"`
}

func runPassiveClient(t *testing.T, name string) {
	var vs []passiveClientVector
	loadVectors(t, name, &vs)
	ran := 0
	for n, v := range vs {
		cs := v.CipherSuite
		if !cs.Supported() {
			continue
		}
		ran++
		kpMsg, err := UnmarshalMLSMessage(v.KeyPackage)
		if err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
		wMsg, err := UnmarshalMLSMessage(v.Welcome)
		if err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
		initPriv, _ := ParseHPKEPrivateKey(v.InitPriv)
		encPriv, _ := ParseHPKEPrivateKey(v.EncryptionPriv)
		sigPriv, err := ParseSignaturePrivateKey(v.SignaturePriv)
		if err != nil {
			t.Fatal(err)
		}
		opts := &JoinOptions{ExternalPSKs: map[string][]byte{}}
		for _, p := range v.ExternalPSKs {
			opts.ExternalPSKs[string(p.PSKID)] = p.PSK
		}
		if v.RatchetTree != nil {
			tree, err := UnmarshalRatchetTree(cs, v.RatchetTree)
			if err != nil {
				t.Fatalf("vector %d: %v", n, err)
			}
			opts.Tree = tree
		}
		state, err := JoinFromWelcome(initPriv, encPriv, sigPriv, kpMsg.KeyPackage, wMsg.Welcome, opts)
		if err != nil {
			t.Fatalf("vector %d: join: %v", n, err)
		}
		if !bytes.Equal(state.EpochAuthenticator(), v.InitialEpochAuthenticator) {
			t.Fatalf("vector %d: initial epoch authenticator mismatch", n)
		}
		for e, ep := range v.Epochs {
			for _, pb := range ep.Proposals {
				m, err := UnmarshalMLSMessage(pb)
				if err != nil {
					t.Fatalf("vector %d epoch %d: %v", n, e, err)
				}
				ac, err := state.Unwrap(m)
				if err != nil {
					t.Skipf("vector %d epoch %d: proposal: %v", n, e, err)
				}
				if err := state.HandleProposal(ac); err != nil {
					t.Fatalf("vector %d epoch %d: handle proposal: %v", n, e, err)
				}
			}
			m, err := UnmarshalMLSMessage(ep.Commit)
			if err != nil {
				t.Fatalf("vector %d epoch %d: %v", n, e, err)
			}
			ac, err := state.Unwrap(m)
			if err != nil {
				t.Fatalf("vector %d epoch %d: commit: %v", n, e, err)
			}
			next, err := state.Handle(ac, nil)
			if err != nil {
				t.Fatalf("vector %d epoch %d: handle commit: %v", n, e, err)
			}
			if !bytes.Equal(next.EpochAuthenticator(), ep.EpochAuthenticator) {
				t.Fatalf("vector %d epoch %d: epoch authenticator mismatch", n, e)
			}
			state = next
		}
	}
	if ran == 0 {
		t.Skip("no vectors for supported ciphersuites")
	}
}

func TestPassiveClientWelcomeVectors(t *testing.T) { runPassiveClient(t, "passive-client-welcome") }

func TestPassiveClientHandlingCommitVectors(t *testing.T) {
	runPassiveClient(t, "passive-client-handling-commit")
}

func TestPassiveClientRandomVectors(t *testing.T) { runPassiveClient(t, "passive-client-random") }
