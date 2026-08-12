package main

import (
	"flag"
	"log"

	"github.com/davveo/unified-account-center/internal/app"
	"github.com/davveo/unified-account-center/internal/config"
)

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	defer application.Close()

	log.Printf("unified-account-center listening on %s", cfg.Server.Addr)
	if err := application.Router.Run(cfg.Server.Addr); err != nil {
		log.Fatalf("server: %v", err)
	}
}
