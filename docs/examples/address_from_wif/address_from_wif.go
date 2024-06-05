package main

import (
	"log"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	script "github.com/bitcoin-sv/go-sdk/script"
)

func main() {

	priv, _ := ec.PrivateKeyFromWif("Kxfd8ABTYZHBH3y1jToJ2AUJTMVbsNaqQsrkpo9gnnc1JXfBH8mn")

	// Print the private key
	log.Printf("Private key: %x\n", priv.Serialise())
	address, _ := script.NewAddressFromPublicKey(priv.PubKey(), true)

	// Print the address, and the pubkey hash
	println(address.AddressString, address.PublicKeyHash)

}
