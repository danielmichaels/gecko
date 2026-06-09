package server

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2/autopatch"

	"github.com/danielmichaels/gecko/assets"
	"github.com/danielmichaels/gecko/internal/version"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"

	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	_ "github.com/danielgtaylor/huma/v2/formats/cbor"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v2"
)

func (app *Server) routes() http.Handler {
	router := chi.NewMux()
	router.Use(middleware.Recoverer)
	router.Use(middleware.RealIP)
	router.Use(traceMiddleware)
	router.Use(compressExceptSSE(5))
	router.Use(httplog.RequestLogger(httpLogger(app.Conf)))
	router.Use(recordSSEStatus)

	cfg := huma.DefaultConfig("gecko", version.Get())
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"xApiKey": {
			Type: "apiKey",
			In:   "header",
			Name: "X-API-Key",
		},
	}
	api := humachi.New(router, cfg)
	autopatch.AutoPatch(api)

	cfg.Info.Title = "gecko API"
	cfg.Info.Description = "API for the gecko application"

	router.Get("/scalar", app.handleScalarDocsGet)

	app.registerEndpoints(api)
	fileServer := http.FileServer(http.FS(assets.EmbeddedAssets))
	router.Handle("/static/*", fileServer)

	router.Mount("/app", app.UIHandlers.Routes())
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/domains", http.StatusSeeOther)
	})

	return router
}

// handleScalarDocsGet is an HTTP handler that serves the API reference documentation
// for the application. It writes an HTML page that includes a script tag that loads
// the Scalar API reference viewer, which will fetch the OpenAPI specification from
// the "/openapi.json" endpoint.
func (app *Server) handleScalarDocsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(`<!doctype html>
<html>
  <head>
    <title>API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`))
}

func (app *Server) registerEndpoints(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "healthz",
		Method:        http.MethodGet,
		Path:          "/healthz",
		Summary:       "health check",
		Description:   "health check endpoint",
		DefaultStatus: http.StatusOK,
		Tags:          []string{"Monitoring"},
	}, app.handleHealthzGet)

	huma.Register(api, huma.Operation{
		OperationID: "version",
		Method:      http.MethodGet,
		Path:        "/version",
		Summary:     "Server version information",
		Description: "Return the version of the application.",
		Tags:        []string{"Monitoring"},
	}, app.handleVersionGet)
	// Domain Handlers
	huma.Register(api, huma.Operation{
		OperationID:   "create_domain",
		Method:        http.MethodPost,
		Path:          "/api/domains",
		Summary:       "Create a domain entry",
		Description:   "Create a domain entry",
		Tags:          []string{"Domains"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainCreate)

	huma.Register(api, huma.Operation{
		OperationID:   "list_domains",
		Method:        http.MethodGet,
		Path:          "/api/domains",
		Summary:       "List all domains",
		Tags:          []string{"Domains"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainList)

	huma.Register(api, huma.Operation{
		OperationID:   "get_domain",
		Method:        http.MethodGet,
		Path:          "/api/domains/{id}",
		Summary:       "Get domain by ID",
		Tags:          []string{"Domains"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainGet)

	huma.Register(api, huma.Operation{
		OperationID:   "update_domain",
		Method:        http.MethodPut,
		Path:          "/api/domains/{id}",
		Summary:       "Update domain",
		Tags:          []string{"Domains"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainUpdate)

	huma.Register(api, huma.Operation{
		OperationID:   "delete_domain",
		Method:        http.MethodDelete,
		Path:          "/api/domains/{id}",
		Summary:       "Delete domain",
		Tags:          []string{"Domains"},
		DefaultStatus: http.StatusNoContent,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainDelete)
	huma.Register(api, huma.Operation{
		OperationID:   "delete_domain_impact",
		Method:        http.MethodGet,
		Path:          "/api/domains/{id}/impact",
		Summary:       "Delete domain impact. How many domains will be affected by deleting this domain",
		Tags:          []string{"Domains"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainDeletionImpact)

	huma.Register(api, huma.Operation{
		OperationID:   "list_records",
		Method:        http.MethodGet,
		Path:          "/api/domains/{id}/records",
		Summary:       "List a domains DNS records",
		Tags:          []string{"Records"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleRecordsList)

	huma.Register(api, huma.Operation{
		OperationID:   "list_record_history",
		Method:        http.MethodGet,
		Path:          "/api/domains/{id}/records/history",
		Summary:       "List a domain's DNS record change timeline",
		Tags:          []string{"Records"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleRecordsHistory)

	huma.Register(api, huma.Operation{
		OperationID:   "domain_timeline",
		Method:        http.MethodGet,
		Path:          "/api/domains/{id}/timeline",
		Summary:       "Scan-by-scan change timeline for a domain (grouped by scan)",
		Tags:          []string{"Records"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainTimeline)

	// Auth handlers (public: signup, login, accept-invite)
	huma.Register(api, huma.Operation{
		OperationID:   "signup",
		Method:        http.MethodPost,
		Path:          "/api/auth/signup",
		Summary:       "Sign up a new team",
		Description:   "Create a tenant and its first owner, returning an API key.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
	}, app.handleSignup)

	huma.Register(api, huma.Operation{
		OperationID:   "login",
		Method:        http.MethodPost,
		Path:          "/api/auth/login",
		Summary:       "Log in",
		Description:   "Verify email/password and return an API key for CLI use.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusOK,
	}, app.handleLogin)

	huma.Register(api, huma.Operation{
		OperationID:   "accept_invitation",
		Method:        http.MethodPost,
		Path:          "/api/invitations/accept",
		Summary:       "Accept an invitation",
		Description:   "Consume an invitation token, set a password, and return an API key.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
	}, app.handleAcceptInvite)

	huma.Register(api, huma.Operation{
		OperationID:   "logout",
		Method:        http.MethodPost,
		Path:          "/api/auth/logout",
		Summary:       "Log out",
		Description:   "Revoke the API key used for this request.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusNoContent,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleLogout)

	huma.Register(api, huma.Operation{
		OperationID:   "me",
		Method:        http.MethodGet,
		Path:          "/api/auth/me",
		Summary:       "Current identity",
		Description:   "Return the authenticated caller's identity.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleMe)

	// API key handlers
	huma.Register(api, huma.Operation{
		OperationID:   "create_api_key",
		Method:        http.MethodPost,
		Path:          "/api/apikeys",
		Summary:       "Create an API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleAPIKeyCreate)

	huma.Register(api, huma.Operation{
		OperationID:   "list_api_keys",
		Method:        http.MethodGet,
		Path:          "/api/apikeys",
		Summary:       "List API keys",
		Tags:          []string{"API Keys"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleAPIKeyList)

	huma.Register(api, huma.Operation{
		OperationID:   "revoke_api_key",
		Method:        http.MethodDelete,
		Path:          "/api/apikeys/{uid}",
		Summary:       "Revoke an API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: http.StatusNoContent,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleAPIKeyRevoke)

	// Invitation handlers
	huma.Register(api, huma.Operation{
		OperationID:   "create_invitation",
		Method:        http.MethodPost,
		Path:          "/api/invitations",
		Summary:       "Invite a teammate",
		Tags:          []string{"Invitations"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleInviteCreate)

	huma.Register(api, huma.Operation{
		OperationID:   "list_invitations",
		Method:        http.MethodGet,
		Path:          "/api/invitations",
		Summary:       "List invitations",
		Tags:          []string{"Invitations"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleInviteList)

	huma.Register(api, huma.Operation{
		OperationID:   "revoke_invitation",
		Method:        http.MethodDelete,
		Path:          "/api/invitations/{uid}",
		Summary:       "Revoke an invitation",
		Tags:          []string{"Invitations"},
		DefaultStatus: http.StatusNoContent,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleInviteRevoke)

	// User management handlers
	huma.Register(api, huma.Operation{
		OperationID:   "list_users",
		Method:        http.MethodGet,
		Path:          "/api/users",
		Summary:       "List tenant users",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleUserList)

	huma.Register(api, huma.Operation{
		OperationID:   "update_user",
		Method:        http.MethodPut,
		Path:          "/api/users/{uid}",
		Summary:       "Update a user",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleUserUpdate)

	huma.Register(api, huma.Operation{
		OperationID:   "delete_user",
		Method:        http.MethodDelete,
		Path:          "/api/users/{uid}",
		Summary:       "Remove a user",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusNoContent,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleUserDelete)
}
