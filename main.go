package main

import (
	"pon-relay.com/cmd"
)

var Version = "dev"

func main() {
	cmd.Version = Version
	cmd.Execute()
}
