// Command portiko runs a Portiko identity provider with the built-in extension
// points: a display name and emoji avatar for the profile, and email by SMTP.
package main

import (
	"os"

	"github.com/Kolonnade/Portiko/provider"
	"github.com/Kolonnade/Portiko/server"
)

func main() {
	os.Exit(server.Main("portiko", os.Args[1:], provider.Options{}))
}
