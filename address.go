package main

import (
	"encoding/base32"
	"strings"

	// Use bine for ed25519: https://stackoverflow.com/questions/44810708/ed25519-public-result-is-different
	"github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	// 15 (constant string), 32 (raw public key), 1 (version) = 48
	checkSize = 48

	// 32 (raw pulic key), 2 (checksum), 1 (version) = 35
	addressSize = 35
	version     = 0x03
)

var salt = []byte(".onion checksum")

// V3AddressFromKeyPair calculates the V3 Tor address for an ed25519 key pair.
func V3AddressFromKeyPair(pair ed25519.KeyPair) string {
	checkBytes := make([]byte, checkSize)
	copy(checkBytes[:len(salt)], salt)
	checkBytes[checkSize-1] = version

	addressBytes := make([]byte, addressSize)
	addressBytes[addressSize-1] = version

	keyPair, _ := ed25519.GenerateKey(nil)
	copy(checkBytes[15:], keyPair.PublicKey())
	checksum := sha3.Sum256(checkBytes)

	// onion_address = base32(pubkey || checksum || version)
	copy(addressBytes[0:], keyPair.PublicKey())
	copy(addressBytes[32:], checksum[0:2])
	return strings.ToLower(base32.StdEncoding.EncodeToString(addressBytes))
}
