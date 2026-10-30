package main

import (
	"os"

	"github.com/sunjinlee/mhi/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
