package models

import (
	"errors"
	"time"
)

var (
	ErrNoRecord           = errors.New("models: no matching record found")
	ErrDuplicateUsername  = errors.New("models: duplicate username")
	ErrInvalidCredentials = errors.New("models: invalid credentials")
	ErrInvalidToken       = errors.New("models: refresh token is invalid")
)

type User struct {
	ID             int
	Username       string
	HashedPassword string
	Created        time.Time
	IsAdmin        bool
}
