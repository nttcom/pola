package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("alpha release.\n")
	}

	if err := newRootCmd().Execute(); err != nil {
		log.Fatal(err)
	}
}
