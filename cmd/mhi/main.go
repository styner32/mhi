package main

import (
	"os"

	"github.com/styner32/mhi/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
