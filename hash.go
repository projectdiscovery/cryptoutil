package cryptoutil

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256Sum(data []byte) string {
	hasher := sha256.New()
	_, _ = hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
