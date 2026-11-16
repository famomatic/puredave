// Command interop cross-checks puredave against libdave: see README.md.
package main

/*
#cgo pkg-config: dave
#include <stdlib.h>
#include <dave/dave.h>
*/
import "C"

import (
	"unsafe"
)

type cMember struct {
	uid string
	s   C.DAVESessionHandle
	enc C.DAVEEncryptorHandle
	dec map[string]C.DAVEDecryptorHandle
}

func cbytes(p *C.uint8_t, n C.size_t) []byte {
	if p == nil {
		return nil
	}
	b := C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.daveFree(unsafe.Pointer(p))
	return b
}

func newCMember(uid string, groupID uint64, ext []byte, others []string) *cMember {
	m := &cMember{uid: uid, dec: map[string]C.DAVEDecryptorHandle{}}
	m.s = C.daveSessionCreate(nil, nil, nil, nil)
	cu := C.CString(uid)
	defer C.free(unsafe.Pointer(cu))
	for _, o := range others {
		co := C.CString(o)
		C.daveSessionAddRecognizedUser(m.s, co)
		C.free(unsafe.Pointer(co))
	}
	C.daveSessionInit(m.s, 1, C.uint64_t(groupID), cu)
	C.daveSessionSetExternalSender(m.s, (*C.uint8_t)(unsafe.Pointer(&ext[0])), C.size_t(len(ext)))
	m.enc = C.daveEncryptorCreate()
	C.daveEncryptorAssignSsrcToCodec(m.enc, 1, C.DAVE_CODEC_OPUS)
	return m
}

func (m *cMember) UID() string { return m.uid }

func (m *cMember) KeyPackage() []byte {
	var p *C.uint8_t
	var n C.size_t
	C.daveSessionGetMarshalledKeyPackage(m.s, &p, &n)
	return cbytes(p, n)
}

func (m *cMember) ProcessProposals(b []byte) []byte {
	var p *C.uint8_t
	var n C.size_t
	C.daveSessionProcessProposals(m.s, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &p, &n)
	return cbytes(p, n)
}

func (m *cMember) ProcessCommit(b []byte) bool {
	r := C.daveSessionProcessCommit(m.s, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	defer C.daveCommitResultDestroy(r)
	return !bool(C.daveCommitResultIsFailed(r)) && !bool(C.daveCommitResultIsIgnored(r))
}

func (m *cMember) ProcessWelcome(b []byte) bool {
	r := C.daveSessionProcessWelcome(m.s, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	if r == nil {
		return false
	}
	C.daveWelcomeResultDestroy(r)
	return true
}

func (m *cMember) EpochAuthenticator() []byte {
	var p *C.uint8_t
	var n C.size_t
	C.daveSessionGetLastEpochAuthenticator(m.s, &p, &n)
	return cbytes(p, n)
}

func (m *cMember) ratchet(uid string) C.DAVEKeyRatchetHandle {
	cu := C.CString(uid)
	defer C.free(unsafe.Pointer(cu))
	return C.daveSessionGetKeyRatchet(m.s, cu)
}

func (m *cMember) SetupRatchets(peers []string) {
	C.daveEncryptorSetKeyRatchet(m.enc, m.ratchet(m.uid))
	for _, p := range peers {
		d, ok := m.dec[p]
		if !ok {
			d = C.daveDecryptorCreate()
			m.dec[p] = d
		}
		C.daveDecryptorTransitionToKeyRatchet(d, m.ratchet(p))
	}
}

func (m *cMember) Encrypt(frame []byte) []byte {
	out := make([]byte, len(frame)+128)
	var n C.size_t
	rc := C.daveEncryptorEncrypt(m.enc, C.DAVE_MEDIA_TYPE_AUDIO, 1, (*C.uint8_t)(unsafe.Pointer(&frame[0])), C.size_t(len(frame)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	if rc != 0 {
		return nil
	}
	return out[:n]
}

func (m *cMember) Decrypt(from string, frame []byte) []byte {
	out := make([]byte, len(frame))
	var n C.size_t
	rc := C.daveDecryptorDecrypt(m.dec[from], C.DAVE_MEDIA_TYPE_AUDIO, (*C.uint8_t)(unsafe.Pointer(&frame[0])), C.size_t(len(frame)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	if rc != 0 {
		return nil
	}
	return out[:n]
}

type cEncryptor struct{ e C.DAVEEncryptorHandle }

func (m *cMember) NewEncryptorFor(uid string, codec int) *cEncryptor {
	e := C.daveEncryptorCreate()
	C.daveEncryptorAssignSsrcToCodec(e, 7, C.DAVECodec(codec))
	C.daveEncryptorSetKeyRatchet(e, m.ratchet(uid))
	return &cEncryptor{e}
}

func (c *cEncryptor) Encrypt(mediaType int, frame []byte) ([]byte, int) {
	out := make([]byte, len(frame)+256)
	var n C.size_t
	var fp *C.uint8_t
	if len(frame) > 0 {
		fp = (*C.uint8_t)(unsafe.Pointer(&frame[0]))
	}
	rc := C.daveEncryptorEncrypt(c.e, C.DAVEMediaType(mediaType), 7, fp, C.size_t(len(frame)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	return out[:n], int(rc)
}

func (c *cEncryptor) Close() { C.daveEncryptorDestroy(c.e) }

type cDecryptor struct{ d C.DAVEDecryptorHandle }

func (m *cMember) NewDecryptorFor(uid string) *cDecryptor {
	d := C.daveDecryptorCreate()
	C.daveDecryptorTransitionToKeyRatchet(d, m.ratchet(uid))
	return &cDecryptor{d}
}

func (c *cDecryptor) Decrypt(mediaType int, frame []byte) ([]byte, int) {
	out := make([]byte, len(frame)+16)
	var n C.size_t
	rc := C.daveDecryptorDecrypt(c.d, C.DAVEMediaType(mediaType), (*C.uint8_t)(unsafe.Pointer(&frame[0])), C.size_t(len(frame)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	return out[:n], int(rc)
}

func (c *cDecryptor) Close() { C.daveDecryptorDestroy(c.d) }
