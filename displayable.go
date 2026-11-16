package dave

import (
	"errors"
	"fmt"
	"strings"
)

// GenerateDisplayableCode renders data as groups of decimal digits, as used
// for epoch authenticators (30 digits in groups of 5) and pairwise
// fingerprints (45 digits in groups of 5).
func GenerateDisplayableCode(data []byte, desiredLength, groupSize int) (string, error) {
	if groupSize <= 0 || groupSize >= 8 {
		return "", errors.New("dave: group size must be in [1, 7]")
	}
	if len(data) < desiredLength {
		return "", errors.New("dave: data is too short for the desired code length")
	}
	if desiredLength%groupSize != 0 {
		return "", errors.New("dave: code length must be a multiple of the group size")
	}
	modulus := uint64(1)
	for i := 0; i < groupSize; i++ {
		modulus *= 10
	}
	var sb strings.Builder
	for i := 0; i < desiredLength; i += groupSize {
		var v uint64
		for j := 0; j < groupSize; j++ {
			v = v<<8 | uint64(data[i+j])
		}
		fmt.Fprintf(&sb, "%0*d", groupSize, v%modulus)
	}
	return sb.String(), nil
}
