package dave

type frameRange struct {
	offset int
	size   int
}

func unencryptedRangesSize(ranges []frameRange) int {
	n := 0
	for _, r := range ranges {
		n += leb128Size(uint64(r.offset)) + leb128Size(uint64(r.size))
	}
	return n
}

func appendUnencryptedRanges(dst []byte, ranges []frameRange) []byte {
	for _, r := range ranges {
		dst = appendLeb128(dst, uint64(r.offset))
		dst = appendLeb128(dst, uint64(r.size))
	}
	return dst
}

// parseUnencryptedRanges decodes offset/size pairs spanning all of b.
func parseUnencryptedRanges(b []byte) ([]frameRange, bool) {
	var out []frameRange
	for len(b) > 0 {
		off, n, ok := readLeb128(b)
		if !ok {
			return nil, false
		}
		b = b[n:]
		size, n, ok := readLeb128(b)
		if !ok {
			return nil, false
		}
		b = b[n:]
		if off > uint64(maxInt) || size > uint64(maxInt) {
			return nil, false
		}
		out = append(out, frameRange{offset: int(off), size: int(size)})
	}
	return out, true
}

const maxInt = int(^uint(0) >> 1)

// validateUnencryptedRanges checks that ranges are ordered, disjoint and
// within frameSize.
func validateUnencryptedRanges(ranges []frameRange, frameSize int) bool {
	for i, cur := range ranges {
		maxEnd := frameSize
		if i+1 < len(ranges) {
			maxEnd = ranges[i+1].offset
		}
		end := cur.offset + cur.size
		if end < cur.offset || end > maxEnd {
			return false
		}
	}
	return true
}

// reconstruct interleaves rangeBytes at the given ranges with otherBytes
// filling the gaps, writing into out and returning the bytes written.
func reconstruct(ranges []frameRange, rangeBytes, otherBytes, out []byte) int {
	frameIndex, rangeIndex, otherIndex := 0, 0, 0
	copyRange := func(size int) {
		if len(rangeBytes)-rangeIndex < size || len(out)-frameIndex < size {
			return
		}
		copy(out[frameIndex:], rangeBytes[rangeIndex:rangeIndex+size])
		rangeIndex += size
		frameIndex += size
	}
	copyOther := func(size int) {
		if len(otherBytes)-otherIndex < size || len(out)-frameIndex < size {
			return
		}
		copy(out[frameIndex:], otherBytes[otherIndex:otherIndex+size])
		otherIndex += size
		frameIndex += size
	}
	for _, r := range ranges {
		if r.offset > frameIndex {
			copyOther(r.offset - frameIndex)
		}
		copyRange(r.size)
	}
	if otherIndex < len(otherBytes) {
		copyOther(len(otherBytes) - otherIndex)
	}
	return frameIndex
}

// inboundFrameProcessor parses a protocol frame on the receive side.
type inboundFrameProcessor struct {
	encrypted      bool
	originalSize   int
	tag            []byte
	truncatedNonce uint32
	ranges         []frameRange
	authenticated  []byte
	ciphertext     []byte
	plaintext      []byte
}

func (p *inboundFrameProcessor) clear() {
	p.encrypted = false
	p.originalSize = 0
	p.tag = nil
	p.truncatedNonce = ^uint32(0)
	p.ranges = p.ranges[:0]
	p.authenticated = p.authenticated[:0]
	p.ciphertext = p.ciphertext[:0]
	p.plaintext = p.plaintext[:0]
}

// parseFrame performs the protocol frame check and splits the frame.
func (p *inboundFrameProcessor) parseFrame(frame []byte) {
	p.clear()
	const minSupplemental = aesGCM128TruncatedTagBytes + 1 + 2
	if len(frame) < minSupplemental {
		return
	}
	if frame[len(frame)-2] != markerBytes[0] || frame[len(frame)-1] != markerBytes[1] {
		return
	}
	suppSize := int(frame[len(frame)-3])
	if len(frame) < suppSize || suppSize < minSupplemental {
		return
	}
	supp := frame[len(frame)-suppSize:]
	p.tag = supp[:aesGCM128TruncatedTagBytes]
	rest := supp[aesGCM128TruncatedTagBytes : len(supp)-3]
	nonce, n, ok := readLeb128(rest)
	if !ok {
		return
	}
	p.truncatedNonce = uint32(nonce)
	ranges, ok := parseUnencryptedRanges(rest[n:])
	if !ok {
		return
	}
	if !validateUnencryptedRanges(ranges, len(frame)) {
		return
	}
	p.ranges = append(p.ranges, ranges...)
	p.originalSize = len(frame)
	frameIndex := 0
	for _, r := range p.ranges {
		if r.offset > frameIndex {
			p.ciphertext = append(p.ciphertext, frame[frameIndex:r.offset]...)
		}
		p.authenticated = append(p.authenticated, frame[r.offset:r.offset+r.size]...)
		frameIndex = r.offset + r.size
	}
	actual := len(frame) - suppSize
	if frameIndex < actual {
		p.ciphertext = append(p.ciphertext, frame[frameIndex:actual]...)
	}
	if cap(p.plaintext) < len(p.ciphertext) {
		p.plaintext = make([]byte, len(p.ciphertext))
	} else {
		p.plaintext = p.plaintext[:len(p.ciphertext)]
	}
	p.encrypted = true
}

func (p *inboundFrameProcessor) reconstructFrame(out []byte) int {
	if !p.encrypted || len(p.authenticated)+len(p.plaintext) > len(out) {
		return 0
	}
	return reconstruct(p.ranges, p.authenticated, p.plaintext, out)
}

// outboundFrameProcessor splits a frame on the send side into the parts
// that must stay unencrypted for the packetizer and the encrypted remainder.
type outboundFrameProcessor struct {
	codec            Codec
	frameIndex       int
	unencryptedBytes []byte
	encryptedBytes   []byte
	ciphertextBytes  []byte
	ranges           []frameRange
}

func (p *outboundFrameProcessor) reset() {
	p.codec = CodecUnknown
	p.frameIndex = 0
	p.unencryptedBytes = p.unencryptedBytes[:0]
	p.encryptedBytes = p.encryptedBytes[:0]
	p.ranges = p.ranges[:0]
}

func (p *outboundFrameProcessor) processFrame(frame []byte, codec Codec) {
	p.reset()
	p.codec = codec
	var ok bool
	switch codec {
	case CodecOpus:
		ok = processFrameOpus(p, frame)
	case CodecVP8:
		ok = processFrameVP8(p, frame)
	case CodecVP9:
		ok = processFrameVP9(p, frame)
	case CodecH264:
		ok = processFrameH264(p, frame)
	case CodecH265:
		ok = processFrameH265(p, frame)
	case CodecAV1:
		ok = processFrameAV1(p, frame)
	default:
		logf(LogWarning, "unsupported codec for frame encryption: %v", codec)
	}
	if !ok {
		p.frameIndex = 0
		p.unencryptedBytes = p.unencryptedBytes[:0]
		p.encryptedBytes = p.encryptedBytes[:0]
		p.ranges = p.ranges[:0]
		p.addEncryptedBytes(frame)
	}
	if cap(p.ciphertextBytes) < len(p.encryptedBytes) {
		p.ciphertextBytes = make([]byte, len(p.encryptedBytes))
	} else {
		p.ciphertextBytes = p.ciphertextBytes[:len(p.encryptedBytes)]
	}
}

func (p *outboundFrameProcessor) reconstructFrame(out []byte) int {
	if len(p.unencryptedBytes)+len(p.ciphertextBytes) > len(out) {
		return 0
	}
	return reconstruct(p.ranges, p.unencryptedBytes, p.ciphertextBytes, out)
}

func (p *outboundFrameProcessor) addUnencryptedBytes(b []byte) {
	if n := len(p.ranges); n > 0 && p.ranges[n-1].offset+p.ranges[n-1].size == p.frameIndex {
		p.ranges[n-1].size += len(b)
	} else {
		p.ranges = append(p.ranges, frameRange{offset: p.frameIndex, size: len(b)})
	}
	p.unencryptedBytes = append(p.unencryptedBytes, b...)
	p.frameIndex += len(b)
}

func (p *outboundFrameProcessor) addEncryptedBytes(b []byte) {
	p.encryptedBytes = append(p.encryptedBytes, b...)
	p.frameIndex += len(b)
}
