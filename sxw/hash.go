package sxw

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/scrypt"
)

const (
	N int = 32768
	R int = 8
	P int = 1
	KEY_LEN int = 32
)

type Hash struct {
	Salt []byte
	hash []byte
}

func (h *Hash) GenerateSalt() error {
	h.Salt = make([]byte, 32)
	_, err := rand.Read(h.Salt)
	return err
}

func (h *Hash) Generate(password []byte) error {
	if h.Salt == nil {
		return errors.New("Salt not initialized yet. Either set Salt or call GenerateSalt().")
	}

	var err error
	h.hash, err = scrypt.Key(password, h.Salt, N, R, P, KEY_LEN)
	return err
}

func (h *Hash) ToBytes() ([]byte, error) {
	if h.hash == nil {
		return nil, errors.New("Hash not generated yet. Call Generate([]byte) first.")
	}

	return h.hash, nil
}


