package main

import (
	"familyvpn.local/platform/internal/app"
	"log"
)

func main() {
	if err := app.Run(true); err != nil {
		log.Fatal(err)
	}
}
