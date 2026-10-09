package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestNewKeyManager(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if km.PrivateKey() == nil {
		t.Fatal("private key should not be nil")
	}
	if km.PublicKey() == nil {
		t.Fatal("public key should not be nil")
	}
	if km.PrivateKey().Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %s", km.PrivateKey().Curve.Params().Name)
	}
}

func TestNewKeyManagerFromPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData func() []byte
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid P-256 key",
			pemData: func() []byte {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				der, _ := x509.MarshalECPrivateKey(key)
				return pem.EncodeToMemory(&pem.Block{Type: PEMBlockTypeECPrivateKey, Bytes: der})
			},
			wantErr: false,
		},
		{
			name: "invalid PEM data",
			pemData: func() []byte {
				return []byte("not-a-pem-block")
			},
			wantErr: true,
			errMsg:  "no PEM block found",
		},
		{
			name: "corrupted key bytes",
			pemData: func() []byte {
				return pem.EncodeToMemory(&pem.Block{
					Type:  PEMBlockTypeECPrivateKey,
					Bytes: []byte("corrupted-data"),
				})
			},
			wantErr: true,
		},
		{
			name: "wrong curve (P-384)",
			pemData: func() []byte {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				der, _ := x509.MarshalECPrivateKey(key)
				return pem.EncodeToMemory(&pem.Block{Type: PEMBlockTypeECPrivateKey, Bytes: der})
			},
			wantErr: true,
			errMsg:  "expected P-256 curve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := NewKeyManagerFromPEM(tt.pemData())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if km.PrivateKey() == nil {
				t.Fatal("private key should not be nil")
			}
			if km.PrivateKey().Curve != elliptic.P256() {
				t.Errorf("expected P-256 curve, got %s", km.PrivateKey().Curve.Params().Name)
			}
		})
	}
}

func TestKeyManager_RoundTrip(t *testing.T) {
	// Generate a key, marshal it, then load it again and verify it's the same
	km1, err := NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	pemData, err := km1.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	km2, err := NewKeyManagerFromPEM(pemData)
	if err != nil {
		t.Fatalf("failed to load key from PEM: %v", err)
	}

	// Verify the keys are the same after the round-trip
	if !km1.PublicKey().Equal(km2.PublicKey()) {
		t.Error("public keys do not match after round-trip")
	}
	if !km1.PrivateKey().Equal(km2.PrivateKey()) {
		t.Error("private keys do not match after round-trip")
	}
}

func TestKeyManager_MarshalPrivateKeyPEM(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	pemData, err := km.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM block")
		return // staticcheck (SA5011) does not see that t.Fatal stops the test with Go 1.26
	}
	if block.Type != PEMBlockTypeECPrivateKey {
		t.Errorf("PEM block type: got %s, want %s", block.Type, PEMBlockTypeECPrivateKey)
	}

	// Verify the PEM data is valid by parsing it
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse EC private key from PEM: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %s", key.Curve.Params().Name)
	}
}

func TestKeyManager_MarshalPublicKeyPEM(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	pemData, err := km.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM block")
		return // staticcheck (SA5011) does not see that t.Fatal stops the test with Go 1.26
	}
	if block.Type != PEMBlockTypePublicKey {
		t.Errorf("PEM block type: got %s, want %s", block.Type, PEMBlockTypePublicKey)
	}

	// Verify the PEM data is valid by parsing it
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key from PEM: %v", err)
	}
	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an ECDSA public key")
	}
	if ecPub.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %s", ecPub.Curve.Params().Name)
	}
}

func TestMultipleKeyManagersProduceDifferentKeys(t *testing.T) {
	km1, err := NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create first key manager: %v", err)
	}

	km2, err := NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create second key manager: %v", err)
	}

	if km1.PrivateKey().Equal(km2.PrivateKey()) {
		t.Error("two separately generated key managers should have different private keys")
	}
}
