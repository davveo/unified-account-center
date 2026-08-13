package web

import "embed"

//go:embed admin/*
var AdminFS embed.FS

//go:embed hosted/*
var HostedFS embed.FS
