package argon2

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/JLugagne/libauth/passwords"
	"golang.org/x/crypto/argon2"
)

// Hasher implements the passwords.Hasher interface using Argon2id.
type Hasher struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

// NewHasher creates a new Argon2id hasher with sensible defaults.
// OWASP recommended (2021): m=64MB, t=1, p=4 for highly concurrent.
// We use a slightly balanced default.
func NewHasher() *Hasher {
	return &Hasher{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
		saltLen: 16,
	}
}

// Hash securely hashes the password using Argon2id and returns the PHC string format.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if password == "" {
		return "", passwords.ErrHashFailed
	}

	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%w: %v", passwords.ErrHashFailed, err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.time, h.memory, h.threads, h.keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64Salt, b64Hash)

	return phc, nil
}

// Compare checks a plaintext password against a PHC formatted Argon2id hash.
func (h *Hasher) Compare(ctx context.Context, hash, password string) error {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return passwords.ErrInvalidPassword
	}
	if parts[1] != "argon2id" {
		return passwords.ErrInvalidPassword
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return passwords.ErrInvalidPassword
	}
	if version != argon2.Version {
		return passwords.ErrInvalidPassword
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return passwords.ErrInvalidPassword
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return passwords.ErrInvalidPassword
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return passwords.ErrInvalidPassword
	}
	keyLen := uint32(len(decodedHash))

	comparisonHash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return passwords.ErrInvalidPassword
}

var _ passwords.Hasher = (*Hasher)(nil)
