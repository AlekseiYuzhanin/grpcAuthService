package storage

import "errors"

var (
	ErrExistUser   = errors.New("user already exists")
	ErrNotFound    = errors.New("user not found")
	ErrAppNotFound = errors.New("app not found")
)
