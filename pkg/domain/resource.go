package domain

import "fmt"

type ResourceID interface {
	fmt.Stringer
	ID() any
}

type Resource interface {
	ID() ResourceID
	Value() any
}
