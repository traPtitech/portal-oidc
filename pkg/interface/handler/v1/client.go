package v1

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (h *Handler) CreateClientHandler(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	req := createClientRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctype, err := domain.ParseClientType(req.Typ)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.UserID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	client, err := h.usecase.CreateClient(ctx, userID, ctype, req.Name, req.Description, req.RedirectURIs)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	res := createClientResponse{
		ClientID:     client.ID.String(),
		Typ:          client.Type.String(),
		Name:         client.Name,
		Description:  client.Description,
		RedirectURIs: client.RedirectURIs,
		Secret:       client.Secret,
		Expires:      0, // Never
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	return
}

func (h *Handler) ListClientsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.UserID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	clients, err := h.usecase.ListClientsByUser(ctx, userID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	res := make([]client, len(clients))
	for i, c := range clients {
		res[i] = client{
			ClientID:     c.ID.String(),
			Typ:          c.Type.String(),
			Name:         c.Name,
			Description:  c.Description,
			RedirectURIs: c.RedirectURIs,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	return
}

func (h *Handler) UpdateClientHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := client{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctype, err := domain.ParseClientType(req.Typ)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.UserID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(req.ClientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c, err := h.usecase.UpdateClient(ctx, domain.ClientID(id), userID, ctype, req.Name, req.Description, req.RedirectURIs)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	res := client{
		ClientID:     c.ID.String(),
		Typ:          c.Type.String(),
		Name:         c.Name,
		Description:  c.Description,
		RedirectURIs: c.RedirectURIs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	return
}

func (h *Handler) UpdateClientSecretHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := updateClientSecretRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.UserID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(req.ClientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c, err := h.usecase.UpdateClientSecret(ctx, userID, domain.ClientID(id))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	res := clientSecret{
		ClientID: c.ID.String(),
		Secret:   c.Secret,
		Expires:  0, // Never
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	return
}

func (h *Handler) DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := deleteClientRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.UserID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(req.ClientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = h.usecase.DeleteClient(ctx, userID, domain.ClientID(id))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return
}
