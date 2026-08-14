package web

import (
	"embed"
	"fmt"
)

//go:embed admin/*
var AdminFS embed.FS

//go:embed hosted/*
var HostedFS embed.FS

//go:embed account/*
var AccountFS embed.FS

//go:embed openapi.yaml
var openapiYAML []byte

func OpenAPIYAML() ([]byte, error) {
	if len(openapiYAML) == 0 {
		return nil, fmt.Errorf("openapi.yaml not embedded")
	}
	return openapiYAML, nil
}
