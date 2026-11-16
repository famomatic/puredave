package dave

// Codec-specific frame handling: which bytes of an encoded frame must remain
// unencrypted so the WebRTC packetizer and depacketizer can process it.

func processFrameOpus(p *outboundFrameProcessor, frame []byte) bool {
	p.addEncryptedBytes(frame)
	return true
}

func processFrameVP8(p *outboundFrameProcessor, frame []byte) bool {
	const keyFrameUnencrypted = 10
	const deltaFrameUnencrypted = 1
	// RFC 7741 Section 4.3: the P bit is an inverse key frame flag.
	if len(frame) == 0 {
		logf(LogWarning, "VP8 frame is empty")
		return false
	}
	n := deltaFrameUnencrypted
	if frame[0]&0x01 == 0 {
		n = keyFrameUnencrypted
	}
	if len(frame) < n {
		logf(LogWarning, "VP8 frame is too small to contain its payload header")
		return false
	}
	p.addUnencryptedBytes(frame[:n])
	p.addEncryptedBytes(frame[n:])
	return true
}

func processFrameVP9(p *outboundFrameProcessor, frame []byte) bool {
	// The payload descriptor carried with each RTP packet holds everything
	// the depacketizer needs.
	p.addEncryptedBytes(frame)
	return true
}

// bytesCoveringH264PPS returns how many bytes of a slice payload cover the
// first three exp-Golomb values (first_mb_in_slice, slice_type, pps_id),
// skipping emulation prevention bytes, or 0 if malformed.
func bytesCoveringH264PPS(payload []byte) int {
	const emulationPreventionByte = 0x03
	bitIndex := 0
	zeroBits := 0
	parsed := 0
	for bitIndex < len(payload)*8 && parsed < 3 {
		bit := bitIndex % 8
		byteIndex := bitIndex / 8
		b := payload[byteIndex]
		if bit == 0 && byteIndex >= 2 && b == emulationPreventionByte && payload[byteIndex-1] == 0 && payload[byteIndex-2] == 0 {
			bitIndex += 8
			continue
		}
		if b&(1<<(7-bit)) == 0 {
			zeroBits++
			bitIndex++
			if zeroBits >= 32 {
				logf(LogWarning, "unexpectedly large exponential golomb encoded value")
				return 0
			}
		} else {
			parsed++
			bitIndex += 1 + zeroBits
			zeroBits = 0
		}
	}
	result := bitIndex/8 + 1
	if result > 0xffff {
		return 0
	}
	return result
}

var h26xLongStartCode = []byte{0, 0, 0, 1}

const h26xShortStartSequenceSize = 3

type h26xStartCode struct {
	offset        int
	nalUnitOffset int
}

// findNextH26XStartCode finds a 3 or 4 byte Annex B start code at or after
// start.
func findNextH26XStartCode(buf []byte, start int) (h26xStartCode, bool) {
	if len(buf) < h26xShortStartSequenceSize {
		return h26xStartCode{}, false
	}
	for i := start; i < len(buf)-h26xShortStartSequenceSize; {
		switch {
		case buf[i+2] > 1:
			i += h26xShortStartSequenceSize
		case buf[i+2] == 1:
			if buf[i+1] == 0 && buf[i] == 0 {
				nal := i + h26xShortStartSequenceSize
				if i > start && buf[i-1] == 0 {
					return h26xStartCode{offset: i - 1, nalUnitOffset: nal}, true
				}
				return h26xStartCode{offset: i, nalUnitOffset: nal}, true
			}
			i += h26xShortStartSequenceSize
		default:
			i++
		}
	}
	return h26xStartCode{}, false
}

func containsH26XStartCode(buf []byte) bool {
	_, ok := findNextH26XStartCode(buf, 0)
	return ok
}

func processFrameH26X(p *outboundFrameProcessor, frame []byte, nalHeaderSize int, prefix func(nal []byte) (int, bool)) bool {
	if len(frame) < h26xShortStartSequenceSize+nalHeaderSize {
		logf(LogWarning, "H26X frame is too small to contain a NAL unit")
		return false
	}
	sc, ok := findNextH26XStartCode(frame, 0)
	if !ok {
		logf(LogWarning, "H26X frame does not contain a NAL unit")
		return false
	}
	for _, b := range frame[:sc.offset] {
		if b != 0 {
			logf(LogWarning, "H26X frame does not start with an Annex B start code")
			return false
		}
	}
	for ok {
		nalOffset := sc.nalUnitOffset
		next, hasNext := findNextH26XStartCode(frame, nalOffset)
		end := len(frame)
		if hasNext {
			end = next.offset
		}
		nalSize := end - nalOffset
		if nalSize < nalHeaderSize {
			logf(LogWarning, "malformed H26X frame: NAL unit header is truncated")
			return false
		}
		nal := frame[nalOffset:end]
		n, good := prefix(nal)
		if !good {
			return false
		}
		// WebRTC converts all start codes to 4 bytes on the receiver side.
		p.addUnencryptedBytes(h26xLongStartCode)
		p.addUnencryptedBytes(nal[:n])
		if n < nalSize {
			p.addEncryptedBytes(nal[n:])
		}
		sc, ok = next, hasNext
	}
	return true
}

func processFrameH264(p *outboundFrameProcessor, frame []byte) bool {
	const typeMask = 0x1f
	const typeSlice = 1
	const typeIDR = 5
	const headerSize = 1
	return processFrameH26X(p, frame, headerSize, func(nal []byte) (int, bool) {
		t := nal[0] & typeMask
		if t != typeSlice && t != typeIDR {
			return len(nal), true
		}
		payload := nal[headerSize:]
		pps := bytesCoveringH264PPS(payload)
		if pps == 0 {
			return 0, false
		}
		if pps > len(payload) {
			logf(LogWarning, "malformed H264 frame: PPS ID overflows NAL unit")
			return 0, false
		}
		return headerSize + pps, true
	})
}

func processFrameH265(p *outboundFrameProcessor, frame []byte) bool {
	const typeMask = 0x7e
	const vclCutoff = 32
	const headerSize = 2
	return processFrameH26X(p, frame, headerSize, func(nal []byte) (int, bool) {
		t := (nal[0] & typeMask) >> 1
		if t < vclCutoff {
			return headerSize, true
		}
		return len(nal), true
	})
}

func processFrameAV1(p *outboundFrameProcessor, frame []byte) bool {
	const hasExtensionMask = 0b0000_0100
	const hasSizeMask = 0b0000_0010
	const typeMask = 0b0111_1000
	const obuTemporalDelimiter = 2
	const obuTileList = 8
	const obuPadding = 15
	i := 0
	for i < len(frame) {
		headerIndex := i
		header := frame[i]
		i++
		hasExtension := header&hasExtensionMask != 0
		hasSize := header&hasSizeMask != 0
		obuType := (header & typeMask) >> 3
		if hasExtension {
			i++
		}
		if i >= len(frame) {
			logf(LogWarning, "malformed AV1 frame: header overflows frame")
			return false
		}
		payloadSize := 0
		if hasSize {
			v, n, ok := readLeb128(frame[i:])
			if !ok {
				logf(LogWarning, "malformed AV1 frame: invalid LEB128 size")
				return false
			}
			i += n
			if v > uint64(len(frame)-i) {
				logf(LogWarning, "malformed AV1 frame: payload overflows frame")
				return false
			}
			payloadSize = int(v)
		} else {
			payloadSize = len(frame) - i
		}
		payloadIndex := i
		i += payloadSize
		if obuType == obuTemporalDelimiter || obuType == obuTileList || obuType == obuPadding {
			continue
		}
		rewrittenWithoutSize := false
		if i == len(frame) && hasSize {
			header &^= hasSizeMask
			rewrittenWithoutSize = true
		}
		p.addUnencryptedBytes([]byte{header})
		if hasExtension {
			p.addUnencryptedBytes(frame[headerIndex+1 : headerIndex+2])
		}
		if hasSize && !rewrittenWithoutSize {
			// Re-encode the size minimally: some encoders pad LEB128 values,
			// which the WebRTC packetizer would otherwise rewrite.
			p.addUnencryptedBytes(appendLeb128(make([]byte, 0, leb128MaxSize), uint64(payloadSize)))
		}
		p.addEncryptedBytes(frame[payloadIndex : payloadIndex+payloadSize])
	}
	return true
}

// validateEncryptedFrame checks that H26X ciphertext and supplemental data
// contain no start code, which would confuse the packetizer.
func validateEncryptedFrame(p *outboundFrameProcessor, frame []byte) bool {
	if p.codec != CodecH264 && p.codec != CodecH265 {
		return true
	}
	const padding = h26xShortStartSequenceSize - 1
	start := 0
	for _, r := range p.ranges {
		if start == r.offset {
			start += r.size
			continue
		}
		from := start - min(start, padding)
		to := min(r.offset+padding, len(frame))
		if containsH26XStartCode(frame[from:to]) {
			return false
		}
		start = r.offset + r.size
	}
	if start == len(frame) {
		return true
	}
	from := start - min(start, padding)
	return !containsH26XStartCode(frame[from:])
}
