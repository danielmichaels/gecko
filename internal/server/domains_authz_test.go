package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
)

// stubScheduler satisfies service.DomainScanScheduler without a live River queue
// so owner/manager Create/Update paths can commit during the integration test. It
// deliberately omits TenantStatsRefresher; the delete path just skips the refresh.
type stubScheduler struct{}

func (stubScheduler) Schedule(
	_ context.Context,
	_ pgx.Tx,
	_ *store.Queries,
	_ jobs.DomainScanTarget,
	_ store.DomainSource,
) (int64, error) {
	return 1, nil
}

// TestAuth_DomainMutationRoleGuard pins the domain mutation boundary: a viewer may
// read domains but must not create, update, or delete them. Owner and manager keep
// full access. This is the HTTP-path counterpart to the service-layer guard tests.
func TestAuth_DomainMutationRoleGuard(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc, stubScheduler{})

	owner := signup(t, base, "owner@a.com", "supersecret")
	mgr := inviteAccept(t, base, owner.APIKey, "mgr@a.com", "manager")
	viewer := inviteAccept(t, base, owner.APIKey, "viewer@a.com", "viewer")

	// Owner creates a domain the viewer will try to mutate.
	var dom struct {
		UID string `json:"uid"`
	}
	if code := doJSON(t, http.MethodPost, base+"/api/domains", owner.APIKey,
		map[string]string{"domain": "guarded.example.com"}, &dom); code != http.StatusCreated {
		t.Fatalf("owner create domain status = %d, want 201", code)
	}

	// Viewer is forbidden from every mutation.
	if code := doJSON(t, http.MethodPost, base+"/api/domains", viewer.APIKey,
		map[string]string{"domain": "viewer-add.example.com"}, nil); code != http.StatusForbidden {
		t.Errorf("viewer create status = %d, want 403", code)
	}
	if code := doJSON(t, http.MethodPut, base+"/api/domains/"+dom.UID, viewer.APIKey,
		map[string]string{"status": "inactive"}, nil); code != http.StatusForbidden {
		t.Errorf("viewer update status = %d, want 403", code)
	}
	if code := doJSON(t, http.MethodDelete, base+"/api/domains/"+dom.UID, viewer.APIKey,
		nil, nil); code != http.StatusForbidden {
		t.Errorf("viewer delete status = %d, want 403", code)
	}

	// The forbidden create added nothing and the forbidden delete removed nothing.
	if code := doJSON(t, http.MethodGet, base+"/api/domains/"+dom.UID, owner.APIKey, nil, nil); code != http.StatusOK {
		t.Errorf("domain after forbidden viewer delete status = %d, want 200", code)
	}

	// Manager retains full access: update succeeds.
	if code := doJSON(t, http.MethodPut, base+"/api/domains/"+dom.UID, mgr.APIKey,
		map[string]string{"status": "active"}, nil); code != http.StatusOK {
		t.Errorf("manager update status = %d, want 200", code)
	}
	// Manager can create.
	var mgrDom struct {
		UID string `json:"uid"`
	}
	if code := doJSON(t, http.MethodPost, base+"/api/domains", mgr.APIKey,
		map[string]string{"domain": "mgr-add.example.com"}, &mgrDom); code != http.StatusCreated {
		t.Errorf("manager create status = %d, want 201", code)
	}
	// Owner can delete.
	if code := doJSON(t, http.MethodDelete, base+"/api/domains/"+dom.UID, owner.APIKey,
		nil, nil); code != http.StatusNoContent {
		t.Errorf("owner delete status = %d, want 204", code)
	}
}
