package main

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	dave "github.com/famomatic/puredave"
)

// corpus.json holds the frames of libdave's codec_utils_tests.cpp.
//
//go:embed corpus.json
var corpusJSON []byte

// differential encrypts the same frames with libdave and puredave using the
// same sender key ratchet and nonce sequence and requires identical output;
// it then decrypts each side's output with the other implementation.
func differential(g *gateway) {
	var cm *cMember
	var pm *pMember
	for _, u := range g.uids() {
		switch m := g.members[u].(type) {
		case *cMember:
			cm = m
		case *pMember:
			pm = m
		}
	}
	if cm == nil || pm == nil {
		return
	}
	var hexes []string
	if err := json.Unmarshal(corpusJSON, &hexes); err != nil {
		panic(err)
	}
	var corpus [][]byte
	for _, h := range hexes {
		f, _ := hex.DecodeString(h)
		corpus = append(corpus, f)
	}
	for i := 0; i < 50; i++ {
		f := make([]byte, 1+g.rng.Intn(400))
		rand.Read(f)
		corpus = append(corpus, f)
		// random frames with sprinkled start codes / OBU-ish headers
		h := append([]byte{0, 0, 0, 1, byte(g.rng.Intn(256))}, f...)
		corpus = append(corpus, h)
	}
	sender := cm.uid
	identical, checked := 0, 0
	for codec := 1; codec <= 6; codec++ {
		mt := 1
		if codec == 1 {
			mt = 0
		}
		ce := cm.NewEncryptorFor(sender, codec)
		pe := dave.NewEncryptor()
		pe.AssignSsrcToCodec(7, dave.Codec(codec))
		pe.SetKeyRatchet(pm.s.KeyRatchet(sender))
		cd := cm.NewDecryptorFor(sender)
		pd := dave.NewDecryptor()
		pd.TransitionToKeyRatchet(pm.s.KeyRatchet(sender), dave.DefaultTransitionDuration)
		for _, frame := range corpus {
			cOut, crc := ce.Encrypt(mt, frame)
			pBuf := make([]byte, pe.MaxCiphertextByteSize(dave.MediaType(mt), len(frame))+64)
			n, prc := pe.Encrypt(dave.MediaType(mt), 7, frame, pBuf)
			pOut := pBuf[:n]
			checked++
			if crc != int(prc) {
				fail("codec %d frame %x: libdave rc=%d puredave rc=%d", codec, frame, crc, prc)
			}
			if crc != 0 {
				continue
			}
			if !bytes.Equal(cOut, pOut) {
				fail("codec %d frame %x:\n libdave  %x\n puredave %x", codec, frame, cOut, pOut)
			}
			identical++
			// cross decrypt: libdave output by puredave, puredave output by libdave
			plain := make([]byte, len(cOut))
			n, r := pd.Decrypt(dave.MediaType(mt), cOut, plain)
			if r != dave.DecryptSuccess {
				fail("codec %d: puredave failed to decrypt libdave frame: %v", codec, r)
			}
			cPlain, rc := cd.Decrypt(mt, pOut)
			if rc != 0 {
				fail("codec %d: libdave failed to decrypt puredave frame: rc=%d", codec, rc)
			}
			if !bytes.Equal(plain[:n], cPlain) {
				fail("codec %d: decrypted frames differ", codec)
			}
		}
		ce.Close()
		cd.Close()
	}
	fmt.Printf("  differential: %d/%d frames byte-identical across 6 codecs, cross-decrypted\n", identical, checked)
}
