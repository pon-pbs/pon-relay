package common

import "errors"

var (
	ErrInvalidSlot        = errors.New("invalid slot")
	ErrInvalidHash        = errors.New("invalid hash")
	ErrInvalidPubkey      = errors.New("invalid pubkey")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidForkVersion = errors.New("invalid fork version")
	ErrHTTPErrorResponse  = errors.New("got an HTTP error response")
)
