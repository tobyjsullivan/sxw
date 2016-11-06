package main

import (
	"os"
	"bufio"
	"strings"
	"encoding/hex"
	"github.com/tobyjsullivan/sxw/sxw"
)

var inputReader *bufio.Reader = bufio.NewReader(os.Stdin)

func main() {
	password, err := readPassword()
	if err != nil {
		panic(err)
	}

	hash := &sxw.Hash{}
	err = readOrGenerateSalt(hash)
	if err != nil {
		panic(err)
	}

	err = hash.Generate(password)
	if err != nil {
		panic(err)
	}

	println("Pass: " + string(password))
	println("Salt: " + hex.EncodeToString(hash.Salt))

	wallet, err := readOrGenerateWallet(hash)
	if err != nil {
		panic(err)
	}

	addr, err := wallet.ToAddress()
	if err != nil {
		panic(err)
	}
	println("Wallet")
	println("Address: " + addr)
	encrypted, err := wallet.Encrypt(hash)
	if err != nil {
		panic(err)
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

func readOrGenerateSalt(hash *sxw.Hash) error {
	println("Specify a salt (hex) (none to generate):")
	saltIn, _ := inputReader.ReadString('\n')
	saltIn = strings.Trim(saltIn, "\n")

	salt, err := hex.DecodeString(saltIn)
	if err != nil {
		return err
	}

	hash.Salt = salt
	if len(salt) == 0 {
		err = hash.GenerateSalt()
		if err != nil {
			return err
		}
	}

	return nil
}


func readOrGenerateWallet(hash *sxw.Hash) (*sxw.SXW, error) {
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
