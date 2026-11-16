package dave

import "time"

type expiringCryptor struct {
	cryptor *cryptor
	expiry  time.Time
}

// cryptorManager owns the cryptors of one key ratchet on the receive side
// and enforces nonce uniqueness.
type cryptorManager struct {
	clock           Clock
	keyRatchet      KeyRatchet
	cryptors        map[KeyGeneration]*expiringCryptor
	ratchetCreation time.Time
	ratchetExpiry   time.Time

	oldestGeneration     KeyGeneration
	newestGeneration     KeyGeneration
	newestProcessedNonce *uint64
	missingNonces        []uint64
}

func newCryptorManager(clock Clock, ratchet KeyRatchet) *cryptorManager {
	return &cryptorManager{
		clock:           clock,
		keyRatchet:      ratchet,
		cryptors:        map[KeyGeneration]*expiringCryptor{},
		ratchetCreation: clock.Now(),
		ratchetExpiry:   farFuture,
	}
}

func (m *cryptorManager) updateExpiry(expiry time.Time) {
	if expiry.Before(m.ratchetExpiry) {
		m.ratchetExpiry = expiry
	}
}

func (m *cryptorManager) isExpired() bool { return m.clock.Now().After(m.ratchetExpiry) }

func (m *cryptorManager) domainIdentity() []byte { return m.keyRatchet.DomainIdentity() }

func (m *cryptorManager) computeWrappedGeneration(generation KeyGeneration) KeyGeneration {
	return computeWrappedGeneration(m.oldestGeneration, generation)
}

func (m *cryptorManager) expectedNonce() uint64 {
	if m.newestProcessedNonce != nil {
		return *m.newestProcessedNonce + 1
	}
	return 0
}

func (m *cryptorManager) canProcessNonce(generation KeyGeneration, nonce uint32) bool {
	big := computeWrappedBigNonce(generation, nonce)
	if big >= m.expectedNonce() {
		return true
	}
	for i := len(m.missingNonces) - 1; i >= 0; i-- {
		if m.missingNonces[i] == big {
			return true
		}
	}
	return false
}

func (m *cryptorManager) getCryptor(generation KeyGeneration) *cryptor {
	m.cleanupExpiredCryptors()
	if generation < m.oldestGeneration {
		logf(LogInfo, "received frame with old generation %d, oldest generation %d", generation, m.oldestGeneration)
		return nil
	}
	if generation > m.newestGeneration+maxGenerationGap {
		logf(LogInfo, "received frame with future generation %d, newest generation %d", generation, m.newestGeneration)
		return nil
	}
	lifetimeSec := int64(m.clock.Now().Sub(m.ratchetCreation) / time.Second)
	maxLifetimeFrames := maxFramesPerSecond * lifetimeSec
	maxLifetimeGenerations := maxLifetimeFrames >> ratchetGenerationShiftBits
	if int64(generation) > maxLifetimeGenerations {
		logf(LogInfo, "received frame with generation %d beyond ratchet max lifetime generations %d", generation, maxLifetimeGenerations)
		return nil
	}
	ec, ok := m.cryptors[generation]
	if !ok {
		ec = m.makeExpiringCryptor(generation)
		if ec == nil {
			return nil
		}
		m.cryptors[generation] = ec
	}
	return ec.cryptor
}

func (m *cryptorManager) reportCryptorSuccess(generation KeyGeneration, nonce uint32) {
	expected := m.expectedNonce()
	big := computeWrappedBigNonce(generation, nonce)
	if big >= expected {
		missing := big - expected
		if missing > maxMissingNonces {
			missing = maxMissingNonces
		}
		for len(m.missingNonces) > 0 && uint64(len(m.missingNonces))+missing > maxMissingNonces {
			m.missingNonces = m.missingNonces[1:]
		}
		for i := big - missing; i < big; i++ {
			m.missingNonces = append(m.missingNonces, i)
		}
		m.newestProcessedNonce = &big
	} else {
		for i := len(m.missingNonces) - 1; i >= 0; i-- {
			if m.missingNonces[i] == big {
				m.missingNonces = append(m.missingNonces[:i], m.missingNonces[i+1:]...)
				break
			}
		}
	}
	if generation <= m.newestGeneration {
		return
	}
	if _, ok := m.cryptors[generation]; !ok {
		return
	}
	logf(LogInfo, "reporting cryptor success, generation %d", generation)
	m.newestGeneration = generation
	expiry := m.clock.Now().Add(cryptorExpiry)
	for gen, c := range m.cryptors {
		if gen < m.newestGeneration && expiry.Before(c.expiry) {
			c.expiry = expiry
		}
	}
}

func (m *cryptorManager) makeExpiringCryptor(generation KeyGeneration) *expiringCryptor {
	key := m.keyRatchet.GetKey(generation)
	c, err := newCryptor(key)
	if err != nil {
		logf(LogError, "failed to create cryptor for generation %d: %v", generation, err)
		return nil
	}
	expiry := farFuture
	if generation < m.newestGeneration {
		logf(LogInfo, "creating cryptor for old generation %d", generation)
		expiry = m.clock.Now().Add(cryptorExpiry)
	} else {
		logf(LogInfo, "creating cryptor for new generation %d", generation)
	}
	return &expiringCryptor{cryptor: c, expiry: expiry}
}

func (m *cryptorManager) cleanupExpiredCryptors() {
	now := m.clock.Now()
	for gen, c := range m.cryptors {
		if c.expiry.Before(now) {
			logf(LogInfo, "removing expired cryptor, generation %d", gen)
			delete(m.cryptors, gen)
		}
	}
	for m.oldestGeneration < m.newestGeneration {
		if _, ok := m.cryptors[m.oldestGeneration]; ok {
			break
		}
		logf(LogInfo, "deleting key for old generation %d", m.oldestGeneration)
		m.keyRatchet.DeleteKey(m.oldestGeneration)
		m.oldestGeneration++
	}
}
