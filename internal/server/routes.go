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
	router.Use(middleware.ClientIPFromRemoteAddr)
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
	cfg.Info.Title = "gecko API"
	cfg.Info.Description = "API for the gecko application"
	cfg.DocsRenderer = huma.DocsRendererScalar
	cfg.DocsRendererConfig = map[string]any{
		"theme":      "default",
		"hideModels": true,
	}

	api := humachi.New(router, cfg)
	autopatch.AutoPatch(api)

	app.registerEndpoints(api)
	fileServer := http.FileServer(http.FS(assets.EmbeddedAssets))
	router.Handle("/static/*", fileServer)

	router.Mount("/app", app.UIHandlers.Routes())
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/domains", http.StatusSeeOther)
	})

	return router
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

	// Findings handlers
	huma.Register(api, huma.Operation{
		OperationID:   "list_domain_findings",
		Method:        http.MethodGet,
		Path:          "/api/domains/{id}/findings",
		Summary:       "List a domain's security findings",
		Tags:          []string{"Findings"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleDomainFindings)

	huma.Register(api, huma.Operation{
		OperationID:   "list_findings",
		Method:        http.MethodGet,
		Path:          "/api/findings",
		Summary:       "List all security findings across the tenant",
		Tags:          []string{"Findings"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleFindingsList)

	// Suppressions handlers (silence rules + per-finding acks)
	huma.Register(api, huma.Operation{
		OperationID:   "list_suppressions",
		Method:        http.MethodGet,
		Path:          "/api/suppressions",
		Summary:       "List silence rules and acknowledged findings for the tenant",
		Tags:          []string{"Suppressions"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleSuppressionsList)

	huma.Register(api, huma.Operation{
		OperationID:   "create_silence_rule",
		Method:        http.MethodPost,
		Path:          "/api/suppressions/rules",
		Summary:       "Silence a check (tenant-global or per-domain)",
		Tags:          []string{"Suppressions"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleSuppressionRuleCreate)

	huma.Register(api, huma.Operation{
		OperationID:   "delete_suppression",
		Method:        http.MethodDelete,
		Path:          "/api/suppressions/{uid}",
		Summary:       "Delete a silence rule or acknowledgement",
		Tags:          []string{"Suppressions"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleSuppressionDelete)

	huma.Register(api, huma.Operation{
		OperationID:   "acknowledge_finding",
		Method:        http.MethodPost,
		Path:          "/api/findings/{finding_uid}/acknowledge",
		Summary:       "Acknowledge or resolve a single finding",
		Tags:          []string{"Suppressions"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleFindingAcknowledge)

	huma.Register(api, huma.Operation{
		OperationID:   "unacknowledge_finding",
		Method:        http.MethodDelete,
		Path:          "/api/findings/{finding_uid}/acknowledge",
		Summary:       "Remove a finding's acknowledgement",
		Tags:          []string{"Suppressions"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleFindingUnacknowledge)

	// Scans handlers
	huma.Register(api, huma.Operation{
		OperationID:   "list_scans",
		Method:        http.MethodGet,
		Path:          "/api/scans",
		Summary:       "List the tenant-wide scan feed (newest first)",
		Tags:          []string{"Scans"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleScansList)
	huma.Register(api, huma.Operation{
		OperationID:   "get_scan",
		Method:        http.MethodGet,
		Path:          "/api/scans/{uid}",
		Summary:       "Get a single scan with its per-observation diff detail",
		Tags:          []string{"Scans"},
		DefaultStatus: http.StatusOK,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleScanDetail)

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
		OperationID:   "attach_invitation",
		Method:        http.MethodPost,
		Path:          "/api/invitations/attach",
		Summary:       "Join a tenant from an invitation",
		Description:   "For an existing account: attach the authenticated caller to the tenant named by an invitation token (addressed to their own email) and return an API key scoped to that tenant.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleAttachInvite)

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

	huma.Register(api, huma.Operation{
		OperationID:   "change_password",
		Method:        http.MethodPost,
		Path:          "/api/auth/change-password",
		Summary:       "Change password",
		Description:   "Verify the caller's current password and set a new one.",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusNoContent,
		Security:      []map[string][]string{{"xApiKey": []string{"x-api-key"}}},
		Middlewares:   huma.Middlewares{app.apiAuth(api)},
	}, app.handleChangePassword)

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
