package domain

type TrapID string

func (u TrapID) String() string {
	return string(u)
}
