package main

import (
	"os"

	"github.com/afterdarksys/systemapi-security/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
