package dave

import (
	"errors"
	"fmt"
	"strings"
)

// maxDisplayableGroupSize matches libdave's MAX_GROUP_SIZE: a group of 8
// bytes still fits a uint64.
const maxDisplayableGroupSize = 8

// GenerateDisplayableCode renders data as groups of decimal digits, as used
// for epoch authenticators (30 digits in groups of 5) and pairwise
// fingerprints (45 digits in groups of 5).
func GenerateDisplayableCode(data []byte, desiredLength, groupSize int) (string, error) {
	if groupSize <= 0 || groupSize > maxDisplayableGroupSize {
		return "", fmt.Errorf("dave: group size must be in [1, %d]", maxDisplayableGroupSize)
	}
	if desiredLength < 0 {
		return "", errors.New("dave: desired length must not be negative")
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
