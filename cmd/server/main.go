package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	if err := cfg.ValidateForRuntime(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	defer application.Close()

	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           application.Router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		b, _ := json.Marshal(map[string]interface{}{"msg": "server_listen", "addr": cfg.Server.Addr})
		log.Println(string(b))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	b, _ := json.Marshal(map[string]string{"msg": "server_shutting_down"})
	log.Println(string(b))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
