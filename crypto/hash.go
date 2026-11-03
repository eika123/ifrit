package crypto

import "crypto/sha256"

// HashContent computes and returns the SHA-256 digest of data as a byte slice.
func HashContent(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

