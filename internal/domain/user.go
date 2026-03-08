package domain

type User struct {
	ID     string
	TrapID string
}

type UserWithPassword struct {
	User
	PasswordHash string
}
