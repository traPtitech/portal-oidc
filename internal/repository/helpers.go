package repository

import (
	"database/sql"

	"github.com/google/uuid"
)

// nullString returns a sql.NullString that is invalid for the empty string,
// matching how callers represent "absent" values throughout the repository.
func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// nullUUID converts an optional uuid.UUID into the form sqlc-generated
// parameter structs expect.
func nullUUID(id *uuid.UUID) uuid.NullUUID { //nolint:unused // referenced by other repositories on feature branches
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}
