// Package profilevault encrypts opaque client exports; it never parses, provisions or publishes them.
package profilevault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const MaxSize = 64 << 10
const nonceSize = 12
const purpose = "family-vpn/client-profile/v1"

var ErrKey = errors.New("client profile key unavailable or invalid")
var ErrEnvelope = errors.New("client profile authentication failed")
var ErrInput = errors.New("invalid client profile storage input")

type Context struct {
	ProfileID  string `json:"profile_id"`
	DeviceID   string `json:"device_id"`
	OwnerID    string `json:"owner_id"`
	Protocol   string `json:"protocol"`
	Generation int    `json:"generation"`
	Format     string `json:"format"`
}

func safeLabel(s string, limit int) bool {
	if len(s) < 1 || len(s) > limit {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func (c Context) Valid() bool {
	return safeLabel(c.ProfileID, 128) && safeLabel(c.DeviceID, 128) && safeLabel(c.OwnerID, 128) && safeLabel(c.Format, 64) && c.Generation > 0 && (c.Protocol == "awg" || c.Protocol == "reality")
}

// Vault is immutable and safe for concurrent use. The ID is purpose-separated from admin keys.
type Vault struct {
	aead cipher.AEAD
	id   string
}

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrKey
	}
	a, e := cipher.NewGCMWithRandomNonce(b)
	if e != nil {
		return nil, ErrKey
	}
	h := sha256.New()
	h.Write([]byte(purpose + "\x00"))
	h.Write(key)
	return &Vault{a, hex.EncodeToString(h.Sum(nil))}, nil
}
func (v *Vault) ID() string {
	if v == nil {
		return ""
	}
	return v.id
}
func (v *Vault) aad(c Context) []byte {
	b, _ := json.Marshal(c)
	return append([]byte(purpose+"\x00"+v.id+"\x00"), b...)
}

type Envelope struct {
	KeyID             string
	Nonce, Ciphertext []byte
}

func (v *Vault) Seal(c Context, plaintext []byte) (Envelope, error) {
	if v == nil {
		return Envelope{}, ErrKey
	}
	if !c.Valid() || len(plaintext) == 0 || len(plaintext) > MaxSize {
		return Envelope{}, ErrInput
	}
	combined := v.aead.Seal(nil, nil, plaintext, v.aad(c))
	return Envelope{v.id, combined[:nonceSize], combined[nonceSize:]}, nil
}
func (v *Vault) Open(c Context, envelope Envelope) ([]byte, error) {
	if v == nil || envelope.KeyID != v.id {
		return nil, ErrKey
	}
	if !c.Valid() || len(envelope.Nonce) != nonceSize || len(envelope.Ciphertext) < 17 || len(envelope.Ciphertext) > MaxSize+16 {
		return nil, ErrEnvelope
	}
	data := make([]byte, 0, len(envelope.Nonce)+len(envelope.Ciphertext))
	data = append(data, envelope.Nonce...)
	data = append(data, envelope.Ciphertext...)
	plain, e := v.aead.Open(nil, nil, data, v.aad(c))
	if e != nil {
		return nil, ErrEnvelope
	}
	if len(plain) == 0 || len(plain) > MaxSize {
		clear(plain)
		return nil, ErrEnvelope
	}
	return plain, nil // Caller must clear bytes when finished; never log plaintext.
}
