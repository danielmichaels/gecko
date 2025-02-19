package server

import (
	"context"
	"github.com/danielmichaels/doublestag/internal/version"
)

const (
// genericServerError = "An internal server error occurred"
)

func (app *Server) handleHealthzGet(_ context.Context, _ *struct{}) (*struct{}, error) {
	return nil, nil
}

type VersionOutput struct {
	Body struct {
		Version string `json:"version" example:"1.0.0" doc:"Version of the API"`
	}
}

func (app *Server) handleVersionGet(_ context.Context, _ *struct{}) (*VersionOutput, error) {
	v := version.Get()
	resp := &VersionOutput{}
	resp.Body.Version = v
	return resp, nil
}

type DomainInput struct {
	Body struct {
		Domain string `json:"domain" example:"example.com" doc:"Domain name to be scanned"`
	}
}
type DomainOutput struct {
	Body struct {
		Domain string `json:"domain" example:"example.com" doc:"Domain name to be scanned"`
	}
}

func (app *Server) handleDomainCreate(
	ctx context.Context,
	i *DomainInput,
) (*DomainOutput, error) {
	resp := &DomainOutput{}
	resp.Body.Domain = ""
	return resp, nil
}
