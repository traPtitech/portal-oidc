package repository

import "github.com/google/uuid"

// nullUUID converts an optional uuid.UUID into the form sqlc-generated
// parameter structs expect.
func nullUUID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}
