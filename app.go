package main

import (
	"os"
	"bufio"
	"strings"
	"encoding/hex"
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
	"github.com/tobyjsullivan/btckeygenie/btckey"
	"crypto/aes"
	"crypto/cipher"
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

	// Create a new cipher keyed with hash
	cblock, err := aes.NewCipher(hash)
	if err != nil {
		println(err)
		os.Exit(1)
	}

	btcPrivKey, err := readOrGenerateWallet(cblock)
	if err != nil {
		println(err)
		os.Exit(1)
	}

	addr := btcPrivKey.ToAddress()
	println("Wallet")
	println("Address: " + addr)
	//wif := btcPrivKey.ToWIF()
	//println("WIF: " + wif)
	btcKeyBytes := btcPrivKey.ToBytes()
	//println("Unencrypted wallet: " + hex.EncodeToString(btcKeyBytes))

	cblock.Encrypt(btcKeyBytes, btcKeyBytes)
	println("Encrypted wallet: " + hex.EncodeToString(btcKeyBytes))
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

func readOrGenerateWallet(cblock cipher.Block) (btckey.PrivateKey, error) {
	println("Encrypted wallet (or none to generate):")
	walletIn, _ := inputReader.ReadString('\n')
	walletIn = strings.Trim(walletIn, "\n")

	encWallet, err := hex.DecodeString(walletIn)
	if err != nil {
		return btckey.PrivateKey{}, err
	}

	var wallet btckey.PrivateKey
	if len(encWallet) > 0 {
		cblock.Decrypt(encWallet, encWallet)
		wallet = btckey.PrivateKey{}
		err = wallet.FromBytes(encWallet)
		if err != nil {
			return btckey.PrivateKey{}, err
		}
	} else {
		wallet, err = btckey.GenerateKey(rand.Reader)
		if err != nil {
			return btckey.PrivateKey{}, err
		}
	}

	return wallet, nil
}
