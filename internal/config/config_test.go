package config_test

import (
	"testing"

	"github.com/davveo/unified-account-center/internal/config"
)

func TestValidateForRuntimeRejectsDefaultsInRelease(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "release"},
		Admin:  config.AdminConfig{Token: "admin-dev-token"},
		JWT:    config.JWTConfig{Secret: "dev-change-me-unified-account-center-secret"},
		Bootstrap: config.BootstrapConfig{
			CreateDefaultApp:    true,
			DefaultClientSecret: "demo_secret_change_me",
		},
	}
	if err := cfg.ValidateForRuntime(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateForRuntimeOKInDebug(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "debug"},
		Admin:  config.AdminConfig{Token: "admin-dev-token"},
		JWT:    config.JWTConfig{Secret: "dev-change-me-unified-account-center-secret"},
	}
	if err := cfg.ValidateForRuntime(); err != nil {
		t.Fatal(err)
	}
}
