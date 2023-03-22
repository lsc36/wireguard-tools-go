package main

import (
	"fmt"
	"os"

	"github.com/lsc36/wireguard-tools-go/internal/cmd/wgg"
)

func main() {
	if err := wgg.Main(os.Args[1:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
