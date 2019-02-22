package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"sync"

	// Use bine for ed25519: https://stackoverflow.com/questions/44810708/ed25519-public-result-is-different
	"github.com/cretz/bine/torutil/ed25519"
)

func startKeySearch(prefix string) {
	for {
		keyPair, _ := ed25519.GenerateKey(nil)
		address := V3AddressFromKeyPair(keyPair)
		if strings.HasPrefix(address, prefix) {
			fmt.Println(address)
			err := ioutil.WriteFile(fmt.Sprintf("%s.onion.key", address), keyPair.PrivateKey(), 0600)
			if err != nil {
				panic(err)
			}
		}
	}
}

func main() {
	prefix := os.Args[1]
	workerCount := runtime.NumCPU()
	runtime.GOMAXPROCS(workerCount)

	fmt.Printf("Looking for '%s'... Type CTRL-C to quit\n", prefix)
	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go startKeySearch(prefix)
	}

	// Wait forever because workers don't call wg.Done())
	wg.Wait()
}
