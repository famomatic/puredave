// Package puregodave implements github.com/disgoorg/godave's Session on top
// of puredave, a pure Go DAVE implementation. It is a drop-in replacement for
// golibdave that needs no cgo, libdave or pkg-config:
//
//	voice.WithDaveSessionCreateFunc(puregodave.NewSession)
package puregodave

import (
	"log/slog"

	"github.com/disgoorg/godave"
	dave "github.com/famomatic/puredave"
)

var (
	_ godave.SessionCreateFunc = NewSession
	_ godave.Session           = (*session)(nil)
)

// NewSession creates a godave.Session backed by puredave.
func NewSession(logger *slog.Logger, userID godave.UserID, callbacks godave.Callbacks) godave.Session {
	return NewSessionWithOptions(logger, userID, callbacks)
}

// NewSessionCreateFunc returns a godave.SessionCreateFunc that passes
// options to every session, for example dave.WithSigningKey to present the
// same identity key on all voice connections of a client.
func NewSessionCreateFunc(opts ...dave.GatewaySessionOption) godave.SessionCreateFunc {
	return func(logger *slog.Logger, userID godave.UserID, callbacks godave.Callbacks) godave.Session {
		return NewSessionWithOptions(logger, userID, callbacks, opts...)
	}
}

// NewSessionWithOptions creates a godave.Session with GatewaySession options.
func NewSessionWithOptions(logger *slog.Logger, userID godave.UserID, callbacks godave.Callbacks, opts ...dave.GatewaySessionOption) godave.Session {
	if logger == nil {
		logger = slog.Default()
	}
	opts = append([]dave.GatewaySessionOption{dave.WithErrorHandler(func(op string, err error) {
		logger.Error("dave: "+op+" failed", slog.Any("err", err))
	})}, opts...)
	return &session{gw: dave.NewGatewaySession(string(userID), callbacks, opts...)}
}

type session struct {
	gw *dave.GatewaySession
}

// GatewaySession exposes the underlying puredave session.
func GatewaySession(s godave.Session) (*dave.GatewaySession, bool) {
	ps, ok := s.(*session)
	if !ok {
		return nil, false
	}
	return ps.gw, true
}

func (s *session) MaxSupportedProtocolVersion() int { return int(dave.MaxSupportedProtocolVersion()) }

func (s *session) Ready() bool { return s.gw.Ready() }

func (s *session) Close() error { return nil }

func (s *session) SetChannelID(channelID godave.ChannelID) { s.gw.SetChannelID(uint64(channelID)) }

func (s *session) AssignSsrcToCodec(ssrc uint32, codec godave.Codec) {
	s.gw.AssignSsrcToCodec(ssrc, dave.Codec(codec))
}

func (s *session) MaxEncryptedFrameSize(frameSize int) int {
	return s.gw.MaxEncryptedFrameSize(dave.MediaTypeAudio, frameSize)
}

func (s *session) Encrypt(ssrc uint32, frame []byte, encryptedFrame []byte) (int, error) {
	return s.gw.Encrypt(dave.MediaTypeAudio, ssrc, frame, encryptedFrame)
}

func (s *session) MaxDecryptedFrameSize(userID godave.UserID, frameSize int) int {
	return s.gw.MaxDecryptedFrameSize(string(userID), dave.MediaTypeAudio, frameSize)
}

func (s *session) Decrypt(userID godave.UserID, frame []byte, decryptedFrame []byte) (int, error) {
	return s.gw.Decrypt(string(userID), dave.MediaTypeAudio, frame, decryptedFrame)
}

func (s *session) AddUser(userID godave.UserID) { s.gw.AddUser(string(userID)) }

func (s *session) RemoveUser(userID godave.UserID) { s.gw.RemoveUser(string(userID)) }

func (s *session) OnSelectProtocolAck(protocolVersion uint16) {
	s.gw.OnSelectProtocolAck(protocolVersion)
}

func (s *session) OnDavePrepareTransition(transitionID uint16, protocolVersion uint16) {
	s.gw.OnPrepareTransition(transitionID, protocolVersion)
}

// OnDaveExecuteTransition receives the transition ID (godave names the
// parameter protocolVersion, but the gateway sends the transition ID).
func (s *session) OnDaveExecuteTransition(transitionID uint16) {
	s.gw.OnExecuteTransition(transitionID)
}

func (s *session) OnDavePrepareEpoch(epoch int, protocolVersion uint16) {
	if epoch < 0 {
		return
	}
	s.gw.OnPrepareEpoch(uint64(epoch), protocolVersion)
}

func (s *session) OnDaveMLSExternalSenderPackage(externalSenderPackage []byte) {
	s.gw.OnExternalSenderPackage(externalSenderPackage)
}

func (s *session) OnDaveMLSProposals(proposals []byte) { s.gw.OnProposals(proposals) }

func (s *session) OnDaveMLSPrepareCommitTransition(transitionID uint16, commitMessage []byte) {
	s.gw.OnAnnounceCommitTransition(transitionID, commitMessage)
}

func (s *session) OnDaveMLSWelcome(transitionID uint16, welcomeMessage []byte) {
	s.gw.OnWelcome(transitionID, welcomeMessage)
}
