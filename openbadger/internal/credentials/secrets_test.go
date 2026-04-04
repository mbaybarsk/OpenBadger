package credentials

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestSecretBoxEncryptDecryptJSON(t *testing.T) {
	t.Parallel()

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	box, err := NewSecretBox(key)
	if err != nil {
		t.Fatalf("NewSecretBox returned error: %v", err)
	}
	box.rand = bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))

	plaintext := []byte(`{"username":"observer","password":"secret-password"}`)
	encrypted, err := box.EncryptJSON(plaintext)
	if err != nil {
		t.Fatalf("EncryptJSON returned error: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("EncryptJSON returned plaintext, want encrypted payload")
	}

	decrypted, err := box.DecryptStoredJSON(encrypted)
	if err != nil {
		t.Fatalf("DecryptStoredJSON returned error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptStoredJSON = %q, want %q", decrypted, plaintext)
	}
}

func TestSecretBoxDecryptStoredJSONPassesPlaintextThrough(t *testing.T) {
	t.Parallel()

	plaintext := []byte(`{"community":"public"}`)
	decrypted, err := (*SecretBox)(nil).DecryptStoredJSON(plaintext)
	if err != nil {
		t.Fatalf("DecryptStoredJSON returned error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptStoredJSON = %q, want %q", decrypted, plaintext)
	}
}

func TestNewSecretBoxRejectsInvalidKey(t *testing.T) {
	t.Parallel()

	if _, err := NewSecretBox("not-base64"); err == nil {
		t.Fatal("NewSecretBox returned nil error, want error")
	}
}
