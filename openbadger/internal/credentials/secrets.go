package credentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	encryptedPayloadVersion   = "v1"
	encryptedPayloadAlgorithm = "AES-256-GCM"
	secretKeySizeBytes        = 32
)

type EncryptedPayload struct {
	Version    string `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type SecretBox struct {
	aead cipher.AEAD
	rand io.Reader
}

func NewSecretBox(encodedKey string) (*SecretBox, error) {
	key, err := decodeSecretKey(encodedKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create credential cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create credential aead: %w", err)
	}

	return &SecretBox{aead: aead, rand: crand.Reader}, nil
}

func decodeSecretKey(encodedKey string) ([]byte, error) {
	encodedKey = strings.TrimSpace(encodedKey)
	if encodedKey == "" {
		return nil, fmt.Errorf("credential encryption key is required")
	}

	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		decoded, err = encoding.DecodeString(encodedKey)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("decode credential encryption key: %w", err)
	}

	if len(decoded) != secretKeySizeBytes {
		return nil, fmt.Errorf("credential encryption key must decode to %d bytes", secretKeySizeBytes)
	}

	return decoded, nil
}

func (b *SecretBox) EncryptJSON(plaintext []byte) ([]byte, error) {
	plaintext = append([]byte(nil), plaintext...)
	if b == nil {
		return plaintext, nil
	}

	if b.rand == nil {
		return nil, fmt.Errorf("credential random source is required")
	}

	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(b.rand, nonce); err != nil {
		return nil, fmt.Errorf("generate credential nonce: %w", err)
	}

	ciphertext := b.aead.Seal(nil, nonce, plaintext, nil)
	envelope, err := json.Marshal(EncryptedPayload{
		Version:    encryptedPayloadVersion,
		Algorithm:  encryptedPayloadAlgorithm,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted credential payload: %w", err)
	}

	return envelope, nil
}

func (b *SecretBox) DecryptStoredJSON(payload []byte) ([]byte, error) {
	envelope, encrypted, err := parseEncryptedPayload(payload)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return append([]byte(nil), payload...), nil
	}

	if b == nil {
		return nil, fmt.Errorf("credential secret box is required to decrypt stored payload")
	}

	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted credential nonce: %w", err)
	}

	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted credential payload: %w", err)
	}

	plaintext, err := b.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt credential payload: %w", err)
	}

	return plaintext, nil
}

func parseEncryptedPayload(payload []byte) (EncryptedPayload, bool, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return EncryptedPayload{}, false, nil
	}

	var envelope EncryptedPayload
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return EncryptedPayload{}, false, nil
	}

	if envelope.Version == "" && envelope.Algorithm == "" && envelope.Nonce == "" && envelope.Ciphertext == "" {
		return EncryptedPayload{}, false, nil
	}

	if envelope.Version != encryptedPayloadVersion {
		return EncryptedPayload{}, false, fmt.Errorf("encrypted credential payload version %q is invalid", envelope.Version)
	}

	if envelope.Algorithm != encryptedPayloadAlgorithm {
		return EncryptedPayload{}, false, fmt.Errorf("encrypted credential payload algorithm %q is invalid", envelope.Algorithm)
	}

	if envelope.Nonce == "" || envelope.Ciphertext == "" {
		return EncryptedPayload{}, false, fmt.Errorf("encrypted credential payload is incomplete")
	}

	return envelope, true, nil
}
