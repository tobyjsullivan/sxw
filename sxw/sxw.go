package sxw

import (
	"crypto/aes"
	"github.com/tobyjsullivan/btckeygenie/btckey"
	"crypto/rand"
	"crypto/cipher"
	"errors"
	"io"
)

type SXW struct {
	privateKey []byte
}

func (w *SXW) Decrypt(encrypted []byte, hash *Hash) error {
	cblock, err := getCipherBlock(hash)
	if err != nil {
		return err
	}

	iv := encrypted[:aes.BlockSize]
	decrypter := cipher.NewCBCDecrypter(cblock, iv)

	w.privateKey = make([]byte, len(encrypted[aes.BlockSize:]))
	decrypter.CryptBlocks(w.privateKey, encrypted[aes.BlockSize:])

	return nil
}

func (w *SXW) Encrypt(hash *Hash) ([]byte, error) {
	if !w.isInitialized() {
		return nil, errors.New("SXW is not initialized. Use Generate() or Decode() first.")
	}

	cblock, err := getCipherBlock(hash)
	if err != nil {
		return nil, err
	}

	iv, err := generateIV(cblock.BlockSize())
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(iv) + len(w.privateKey))
	copy(out[:aes.BlockSize], iv)

	encrypter := cipher.NewCBCEncrypter(cblock, iv)

	encrypter.CryptBlocks(out[aes.BlockSize:], w.privateKey)
	return out, nil
}

func generateIV(blocksize int) ([]byte, error) {
	iv := make([]byte, blocksize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return iv, nil
}

func (w *SXW) isInitialized() bool {
	return w.privateKey != nil
}

func getCipherBlock(hash *Hash) (cipher.Block, error) {
	hashBytes, err := hash.ToBytes()
	if err != nil {
		return nil, err
	}

	return aes.NewCipher(hashBytes)
}

func (w *SXW) Generate() error {
	wallet, err := btckey.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	w.privateKey = wallet.ToBytes()

	return nil
}

func (w *SXW) ToAddress() (string, error) {
	privKey := btckey.PrivateKey{}
	err := privKey.FromBytes(w.privateKey)
	if err != nil {
		return "", err
	}

	return privKey.ToAddress(), nil
}
