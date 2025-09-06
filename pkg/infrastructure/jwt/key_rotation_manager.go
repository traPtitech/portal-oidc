package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type KeyInfo struct {
	KID        string            `json:"kid"`
	CreatedAt  time.Time         `json:"created_at"`
	PrivateKey *ecdsa.PrivateKey `json:"-"`
	PublicKey  *ecdsa.PublicKey  `json:"-"`
	PEMData    string            `json:"pem_data"`
}

type KeyRotationManager struct {
	mu              sync.RWMutex
	keys            []*KeyInfo
	currentKey      *KeyInfo
	rotationPeriod  time.Duration
	retentionPeriod time.Duration
	storePath       string
	stopCh          chan struct{}
}

func NewKeyRotationManager(storePath string, rotationPeriod, retentionPeriod time.Duration) (*KeyRotationManager, error) {
	manager := &KeyRotationManager{
		keys:            make([]*KeyInfo, 0),
		rotationPeriod:  rotationPeriod,
		retentionPeriod: retentionPeriod,
		storePath:       storePath,
		stopCh:          make(chan struct{}),
	}

	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	if err := manager.loadKeys(); err != nil {
		if err := manager.generateNewKey(); err != nil {
			return nil, fmt.Errorf("failed to generate initial key: %w", err)
		}
	}

	go manager.rotationScheduler()

	return manager, nil
}

func (m *KeyRotationManager) GetCurrentSigner() *ES256Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &ES256Signer{
		privateKey: m.currentKey.PrivateKey,
		kid:        m.currentKey.KID,
	}
}

func (m *KeyRotationManager) GetAllKeys() []*KeyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*KeyInfo, len(m.keys))
	copy(keys, m.keys)
	return keys
}

func (m *KeyRotationManager) GetKeyByKID(kid string) (*KeyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, key := range m.keys {
		if key.KID == kid {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key with KID %s not found", kid)
}

func (m *KeyRotationManager) rotationScheduler() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndRotate()
		case <-m.stopCh:
			return
		}
	}
}

func (m *KeyRotationManager) checkAndRotate() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	if m.currentKey != nil && now.Sub(m.currentKey.CreatedAt) >= m.rotationPeriod {
		if err := m.generateNewKeyLocked(); err != nil {
			fmt.Printf("Failed to rotate key: %v\n", err)
			return
		}
	}

	validKeys := make([]*KeyInfo, 0)
	for _, key := range m.keys {
		if now.Sub(key.CreatedAt) <= m.retentionPeriod {
			validKeys = append(validKeys, key)
		}
	}
	m.keys = validKeys

	m.saveKeysLocked()
}

func (m *KeyRotationManager) generateNewKey() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateNewKeyLocked()
}

func (m *KeyRotationManager) generateNewKeyLocked() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemData := string(pem.EncodeToMemory(pemBlock))

	kid := generateKID(&privateKey.PublicKey)

	keyInfo := &KeyInfo{
		KID:        kid,
		CreatedAt:  time.Now(),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		PEMData:    pemData,
	}

	m.keys = append(m.keys, keyInfo)
	m.currentKey = keyInfo

	return m.saveKeysLocked()
}

func (m *KeyRotationManager) loadKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	metadataPath := filepath.Join(m.storePath, "keys_metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no keys found")
		}
		return fmt.Errorf("failed to read keys metadata: %w", err)
	}

	var metadata []struct {
		KID       string    `json:"kid"`
		CreatedAt time.Time `json:"created_at"`
		IsCurrent bool      `json:"is_current"`
	}

	if err := json.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal keys metadata: %w", err)
	}

	m.keys = make([]*KeyInfo, 0, len(metadata))
	now := time.Now()

	for _, meta := range metadata {
		if now.Sub(meta.CreatedAt) > m.retentionPeriod {
			continue
		}

		pemPath := filepath.Join(m.storePath, fmt.Sprintf("%s.pem", meta.KID))
		pemData, err := os.ReadFile(pemPath)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			continue
		}

		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			continue
		}

		keyInfo := &KeyInfo{
			KID:        meta.KID,
			CreatedAt:  meta.CreatedAt,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			PEMData:    string(pemData),
		}

		m.keys = append(m.keys, keyInfo)

		if meta.IsCurrent {
			m.currentKey = keyInfo
		}
	}

	if m.currentKey == nil && len(m.keys) > 0 {
		m.currentKey = m.keys[len(m.keys)-1]
	}

	if len(m.keys) == 0 {
		return fmt.Errorf("no valid keys loaded")
	}

	return nil
}

func (m *KeyRotationManager) saveKeysLocked() error {
	metadata := make([]map[string]interface{}, 0, len(m.keys))

	for _, key := range m.keys {
		pemPath := filepath.Join(m.storePath, fmt.Sprintf("%s.pem", key.KID))
		if err := os.WriteFile(pemPath, []byte(key.PEMData), 0600); err != nil {
			return fmt.Errorf("failed to save key PEM: %w", err)
		}

		metadata = append(metadata, map[string]interface{}{
			"kid":        key.KID,
			"created_at": key.CreatedAt,
			"is_current": key.KID == m.currentKey.KID,
		})
	}

	metadataPath := filepath.Join(m.storePath, "keys_metadata.json")
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save keys metadata: %w", err)
	}

	return nil
}

func (m *KeyRotationManager) Stop() {
	close(m.stopCh)
}

func (m *KeyRotationManager) ForceRotation() error {
	return m.generateNewKey()
}
