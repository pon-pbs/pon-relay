package main

import (
	"pon-relay.com/cmd"
)

var Version = "dev" // is set during build process

func main() {
	cmd.Version = Version
	cmd.Execute()
}
