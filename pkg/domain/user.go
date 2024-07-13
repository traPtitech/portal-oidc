package domain

import "fmt"

type UserID interface {
	fmt.Stringer
	ID() any
}
