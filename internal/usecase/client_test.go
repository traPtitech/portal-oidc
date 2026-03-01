package usecase

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

// mockClientRepository is an in-memory implementation for testing
type mockClientRepository struct {
	mu      sync.RWMutex
	clients map[uuid.UUID]*clientWithHash
}

type clientWithHash struct {
	client     *domain.Client
	secretHash string
}

func newMockClientRepository() *mockClientRepository {
	return &mockClientRepository{
		clients: make(map[uuid.UUID]*clientWithHash),
	}
}

func (r *mockClientRepository) Create(ctx context.Context, client *domain.Client, secretHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[client.ClientID] = &clientWithHash{
		client:     client,
		secretHash: secretHash,
	}
	return nil
}

func (r *mockClientRepository) Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.clients[clientID]; ok {
		return c.client, nil
	}
	return nil, repository.ErrClientNotFound
}

func (r *mockClientRepository) List(ctx context.Context) ([]*domain.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	clients := make([]*domain.Client, 0, len(r.clients))
	for _, c := range r.clients {
		clients = append(clients, c.client)
	}
	return clients, nil
}

func (r *mockClientRepository) Update(ctx context.Context, client *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[client.ClientID]; ok {
		c.client = client
		return nil
	}
	return repository.ErrClientNotFound
}

func (r *mockClientRepository) UpdateSecret(ctx context.Context, clientID uuid.UUID, secretHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[clientID]; ok {
		c.secretHash = secretHash
		return nil
	}
	return repository.ErrClientNotFound
}

func (r *mockClientRepository) Delete(ctx context.Context, clientID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, clientID)
	return nil
}

func (r *mockClientRepository) getSecretHash(clientID uuid.UUID) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.clients[clientID]; ok {
		return c.secretHash
	}
	return ""
}

func (r *mockClientRepository) GetWithSecretHash(ctx context.Context, clientID uuid.UUID) (*domain.Client, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.clients[clientID]; ok {
		return c.client, c.secretHash, nil
	}
	return nil, "", repository.ErrClientNotFound
}

func TestClientUseCase_Create(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	created, err := uc.Create(ctx, "test-client", domain.ClientTypeConfidential, []string{"http://localhost:3000/callback"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if created.ClientID == uuid.Nil {
		t.Error("ClientID should not be nil")
	}
	if created.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}
	if created.Name != "test-client" {
		t.Errorf("Name = %q, want %q", created.Name, "test-client")
	}
	if created.ClientType != domain.ClientTypeConfidential {
		t.Errorf("ClientType = %q, want %q", created.ClientType, domain.ClientTypeConfidential)
	}
	if len(created.RedirectURIs) != 1 || created.RedirectURIs[0] != "http://localhost:3000/callback" {
		t.Errorf("RedirectURIs = %v, want [http://localhost:3000/callback]", created.RedirectURIs)
	}
}

func TestClientUseCase_Get(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	created, _ := uc.Create(ctx, "test-client", domain.ClientTypeConfidential, []string{"http://localhost:3000/callback"})

	got, err := uc.Get(ctx, created.ClientID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if got.ClientID != created.ClientID {
		t.Errorf("ClientID = %s, want %s", got.ClientID, created.ClientID)
	}
	if got.Name != created.Name {
		t.Errorf("Name = %q, want %q", got.Name, created.Name)
	}
}

func TestClientUseCase_Get_NotFound(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	_, err := uc.Get(ctx, uuid.New())
	if err != ErrClientNotFound {
		t.Errorf("err = %v, want ErrClientNotFound", err)
	}
}

func TestClientUseCase_List(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	// Empty list
	list, err := uc.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("len(list) = %d, want 0", len(list))
	}

	// Create clients
	_, err = uc.Create(ctx, "client1", domain.ClientTypeConfidential, []string{"http://localhost:3000/callback"})
	if err != nil {
		t.Fatalf("Create client1 failed: %v", err)
	}
	_, err = uc.Create(ctx, "client2", domain.ClientTypePublic, []string{"http://localhost:3001/callback"})
	if err != nil {
		t.Fatalf("Create client2 failed: %v", err)
	}

	list, err = uc.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len(list) = %d, want 2", len(list))
	}
}

func TestClientUseCase_Update(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	created, _ := uc.Create(ctx, "original", domain.ClientTypeConfidential, []string{"http://localhost:3000/callback"})

	updated, err := uc.Update(ctx, created.ClientID, "updated", domain.ClientTypePublic, []string{"http://localhost:4000/callback"})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if updated.ClientID != created.ClientID {
		t.Error("ClientID should not change")
	}
	if updated.Name != "updated" {
		t.Errorf("Name = %q, want %q", updated.Name, "updated")
	}
	if updated.ClientType != domain.ClientTypePublic {
		t.Errorf("ClientType = %q, want %q", updated.ClientType, domain.ClientTypePublic)
	}
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "http://localhost:4000/callback" {
		t.Errorf("RedirectURIs = %v, want [http://localhost:4000/callback]", updated.RedirectURIs)
	}
}

func TestClientUseCase_Update_NotFound(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	_, err := uc.Update(ctx, uuid.New(), "name", domain.ClientTypeConfidential, []string{"http://localhost:3000"})
	if err != ErrClientNotFound {
		t.Errorf("err = %v, want ErrClientNotFound", err)
	}
}

func TestClientUseCase_Delete(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	created, _ := uc.Create(ctx, "test-client", domain.ClientTypeConfidential, []string{"http://localhost:3000/callback"})

	err := uc.Delete(ctx, created.ClientID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = uc.Get(ctx, created.ClientID)
	if err != ErrClientNotFound {
		t.Errorf("err = %v, want ErrClientNotFound", err)
	}
}

func TestClientUseCase_Delete_NotFound(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	err := uc.Delete(ctx, uuid.New())
	if err != ErrClientNotFound {
		t.Errorf("err = %v, want ErrClientNotFound", err)
	}
}

func TestClientUseCase_RegenerateSecret(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	created, _ := uc.Create(ctx, "test-client", domain.ClientTypeConfidential, []string{"http://localhost:3000/callback"})
	originalHash := repo.getSecretHash(created.ClientID)

	newSecret, err := uc.RegenerateSecret(ctx, created.ClientID)
	if err != nil {
		t.Fatalf("RegenerateSecret failed: %v", err)
	}

	if newSecret == "" {
		t.Error("new secret should not be empty")
	}
	if newSecret == created.ClientSecret {
		t.Error("new secret should be different from original")
	}

	newHash := repo.getSecretHash(created.ClientID)
	if newHash == originalHash {
		t.Error("secret hash should be updated")
	}
}

func TestClientUseCase_RegenerateSecret_NotFound(t *testing.T) {
	repo := newMockClientRepository()
	uc := NewClientUseCase(repo)
	ctx := context.Background()

	_, err := uc.RegenerateSecret(ctx, uuid.New())
	if err != ErrClientNotFound {
		t.Errorf("err = %v, want ErrClientNotFound", err)
	}
}
