package main

import (
	"os"
	"bufio"
	"strings"
	"encoding/hex"
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
	"github.com/tobyjsullivan/sxw/sxw"
)

var inputReader *bufio.Reader = bufio.NewReader(os.Stdin)

func main() {
	password, err := readPassword()
	if err != nil {
		println(err)
		os.Exit(1)
	}

	salt, err := readOrGenerateSalt()
	if err != nil {
		println(err)
		os.Exit(1)
	}

	n := 32768
	r := 8
	p := 1
	keyLen := 32


	hash, err := scrypt.Key(password, salt, n, r, p, keyLen)

	if err != nil {
		println(err)
		os.Exit(1)
	}

	println("Pass: " + string(password))
	println("Salt: " + hex.EncodeToString(salt))
	println("Hash: " + hex.EncodeToString(hash))

	wallet, err := readOrGenerateWallet(hash)
	if err != nil {
		println(err)
		os.Exit(1)
	}

	addr, err := wallet.ToAddress()
	if err != nil {
		println(err)
		os.Exit(1)
	}
	println("Wallet")
	println("Address: " + addr)
	encrypted, err := wallet.Encrypt(hash)
	if err != nil {
		println(err)
		os.Exit(1)
	}

	println("Encrypted wallet: " + hex.EncodeToString(encrypted))
}

func readPassword() ([]byte, error) {
	println("Password:");
	text, err := inputReader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	text = strings.Trim(text, "\n")
	password := []byte(text)

	return password, nil
}

func readOrGenerateSalt() ([]byte, error) {
	println("Specify a salt (hex) (none to generate):")
	saltIn, _ := inputReader.ReadString('\n')
	saltIn = strings.Trim(saltIn, "\n")

	salt, err := hex.DecodeString(saltIn)
	if err != nil {
		return nil, err
	}

	if len(salt) == 0 {
		salt, err = generateSalt()
		if err != nil {
			return nil, err
		}
	}

	return salt, nil
}

func generateSalt() ([]byte, error) {
	out := make([]byte, 32)
	_, err := rand.Read(out)
	return out, err
}

func readOrGenerateWallet(hash []byte) (*sxw.SXW, error) {
	println("Encrypted wallet (or none to generate):")
	walletIn, _ := inputReader.ReadString('\n')
	walletIn = strings.Trim(walletIn, "\n")

	encWallet, err := hex.DecodeString(walletIn)
	if err != nil {
		return &sxw.SXW{}, err
	}

	wallet := &sxw.SXW{}
	if len(encWallet) > 0 {
		err = wallet.Decrypt(encWallet, hash)
		if err != nil {
			return &sxw.SXW{}, err
		}
	} else {
		err = wallet.Generate()
		if err != nil {
			return &sxw.SXW{}, err
		}
	}

	return wallet, nil
}
