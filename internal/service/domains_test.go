package service_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// fakeScheduler records Schedule calls and per-tenant stat-refresh enqueues for
// assertion; safe for concurrent use. It implements both DomainScanScheduler and
// TenantStatsRefresher so the service wires it as the refresher too.
type fakeScheduler struct {
	mu             sync.Mutex
	calls          int
	statsRefreshes []int32
	emails         []mailer.Message
}

func (f *fakeScheduler) Schedule(
	_ context.Context,
	_ pgx.Tx,
	_ *store.Queries,
	_ jobs.DomainScanTarget,
	_ store.DomainSource,
) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return 1, nil
}

func (f *fakeScheduler) Called() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeScheduler) RefreshTenantStats(_ context.Context, tenantID int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statsRefreshes = append(f.statsRefreshes, tenantID)
	return nil
}

func (f *fakeScheduler) StatsRefreshes() []int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int32(nil), f.statsRefreshes...)
}

func (f *fakeScheduler) EnqueueEmail(_ context.Context, _ pgx.Tx, msg mailer.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.emails = append(f.emails, msg)
	return nil
}

func (f *fakeScheduler) Emails() []mailer.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mailer.Message(nil), f.emails...)
}

// ownerPrincipal returns a synthetic owner principal for the given tenant.
func ownerPrincipal(tenantID int32) *auth.Principal {
	return &auth.Principal{
		UserID:   1,
		TenantID: tenantID,
		Role:     "owner",
		Email:    "test@example.com",
	}
}

// principalWithRole returns a synthetic principal for the given tenant and role.
func principalWithRole(tenantID int32, role string) *auth.Principal {
	return &auth.Principal{
		UserID:   1,
		TenantID: tenantID,
		Role:     role,
		Email:    "test@example.com",
	}
}

func newTestService(
	pc *testhelpers.PostgresContainer,
	sched service.DomainScanScheduler,
) *service.Service {
	cfg := config.AppConfig()
	return service.NewWithScheduler(
		cfg,
		slog.New(slog.DiscardHandler),
		pc.Queries,
		pc.Pool,
		sched,
	)
}

func seedDomain(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	name string,
) store.DomainsInsertRow {
	t.Helper()
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       name,
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("seed domain %s: %v", name, err)
	}
	return d
}

// createTenant inserts a tenant + owner user directly (mirroring signup) and returns the tenant ID.
func createTenant(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	email string,
) int32 {
	t.Helper()
	tenant, err := pc.Queries.TenantCreate(ctx, email)
	if err != nil {
		t.Fatalf("create tenant for %s: %v", email, err)
	}
	_, err = pc.Queries.UserProvision(ctx, store.UserProvisionParams{
		TenantID: pgtype.Int4{Int32: tenant.ID, Valid: true},
		Email:    email,
		Role:     store.UserRoleOwner,
	})
	if err != nil {
		t.Fatalf("create user for %s: %v", email, err)
	}
	return tenant.ID
}

func TestDomainsService_List_TenantScoped(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@list-test.com")
	tenantB := createTenant(t, ctx, pc, "b@list-test.com")

	seedDomain(t, ctx, pc, tenantA, "a-domain.example.com")
	seedDomain(t, ctx, pc, tenantA, "a-domain2.example.com")
	seedDomain(t, ctx, pc, tenantB, "b-domain.example.com")

	result, err := ds.List(ctx, ownerPrincipal(tenantA), service.DomainsListParams{PageSize: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if result.TotalCount != 2 {
		t.Errorf("A sees %d domains, want 2", result.TotalCount)
	}
	for _, d := range result.Domains {
		if d.TenantID.Int32 != tenantA {
			t.Errorf("A sees domain from wrong tenant: %v", d.Name)
		}
	}
}

func TestDomainsService_List_Search(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@search-test.com")
	seedDomain(t, ctx, pc, tenantA, "alpha.example.com")
	seedDomain(t, ctx, pc, tenantA, "beta.example.com")
	seedDomain(t, ctx, pc, tenantA, "gamma.example.com")

	result, err := ds.List(
		ctx,
		ownerPrincipal(tenantA),
		service.DomainsListParams{PageSize: 10, FilterName: "alpha"},
	)
	if err != nil {
		t.Fatalf("List search: %v", err)
	}
	if result.TotalCount != 1 {
		t.Errorf("search returned %d, want 1", result.TotalCount)
	}
	if result.Domains[0].Name != "alpha.example.com" {
		t.Errorf("wrong domain: %s", result.Domains[0].Name)
	}
}

func TestDomainsService_Get_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@get-test.com")
	d := seedDomain(t, ctx, pc, tenantA, "get.example.com")

	got, err := ds.Get(ctx, ownerPrincipal(tenantA), d.Uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "get.example.com" {
		t.Errorf("name = %s, want get.example.com", got.Name)
	}
}

func TestDomainsService_Get_CrossTenantReturnsNotFound(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@get-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@get-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-private.example.com")

	_, err = ds.Get(ctx, ownerPrincipal(tenantA), d.Uid)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant Get = %v, want ErrNotFound", err)
	}
}

func TestDomainsService_Create_SchedulesCalled(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@create-test.com")
	d, err := ds.Create(ctx, ownerPrincipal(tenantA), service.DomainsCreateParams{
		Domain: "new-domain.example.com",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.Name != "new-domain.example.com" {
		t.Errorf("name = %s, want new-domain.example.com", d.Name)
	}
	if sched.Called() != 1 {
		t.Errorf("scheduler called %d times, want 1", sched.Called())
	}
}

func TestDomainsService_Create_DuplicateReturnsConflict(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@dup-test.com")
	_, err = ds.Create(
		ctx,
		ownerPrincipal(tenantA),
		service.DomainsCreateParams{Domain: "dup.example.com"},
	)
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err = ds.Create(
		ctx,
		ownerPrincipal(tenantA),
		service.DomainsCreateParams{Domain: "dup.example.com"},
	)
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate Create = %v, want ErrConflict", err)
	}
}

func TestDomainsService_Update_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@update-test.com")
	d := seedDomain(t, ctx, pc, tenantA, "update.example.com")

	updated, err := ds.Update(ctx, ownerPrincipal(tenantA), d.Uid, service.DomainsUpdateParams{
		Status: "inactive",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Status != store.DomainStatusInactive {
		t.Errorf("status = %s, want inactive", updated.Status)
	}
	// The service always delegates to the scheduler; the active-status gate lives
	// inside the production scheduler (jobs.EnqueueDomainScan). The fake records
	// the call so we confirm the delegation happened exactly once.
	if sched.Called() != 1 {
		t.Errorf("scheduler called %d times, want 1", sched.Called())
	}
}

func TestDomainsService_Update_CrossTenantReturnsNotFound(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@update-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@update-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-update.example.com")

	_, err = ds.Update(
		ctx,
		ownerPrincipal(tenantA),
		d.Uid,
		service.DomainsUpdateParams{Status: "inactive"},
	)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant Update = %v, want ErrNotFound", err)
	}
}

func TestDomainsService_Delete_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@delete-test.com")
	d := seedDomain(t, ctx, pc, tenantA, "delete-me.example.com")

	if err := ds.Delete(ctx, ownerPrincipal(tenantA), d.Uid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// A successful delete enqueues a per-tenant stats refresh for that tenant.
	if got := sched.StatsRefreshes(); len(got) != 1 || got[0] != tenantA {
		t.Errorf("stats refreshes = %v, want [%d]", got, tenantA)
	}
	// Confirm it is gone.
	if err := ds.Delete(ctx, ownerPrincipal(tenantA), d.Uid); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
	// A no-op delete (already gone) does not enqueue another refresh.
	if got := sched.StatsRefreshes(); len(got) != 1 {
		t.Errorf("stats refreshes after no-op delete = %v, want 1", got)
	}
}

func TestDomainsService_Delete_CrossTenantReturnsNotFound(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@del-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@del-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-del.example.com")

	if err := ds.Delete(ctx, ownerPrincipal(tenantA), d.Uid); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant Delete = %v, want ErrNotFound", err)
	}
}

func TestDomainsService_DeletionImpact_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@impact-test.com")
	d := seedDomain(t, ctx, pc, tenantA, "impact.example.com")

	count, err := ds.DeletionImpact(ctx, ownerPrincipal(tenantA), d.Uid)
	if err != nil {
		t.Fatalf("DeletionImpact: %v", err)
	}
	if count < 1 {
		t.Errorf("count = %d, want >= 1", count)
	}
}

func TestDomainsService_Create_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@create-viewer.com")

	_, err = ds.Create(
		ctx,
		principalWithRole(tenantA, "viewer"),
		service.DomainsCreateParams{Domain: "viewer-create.example.com"},
	)
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("viewer Create = %v, want ErrForbidden", err)
	}
	if sched.Called() != 0 {
		t.Errorf("scheduler called %d times on forbidden create, want 0", sched.Called())
	}
	// No domain was inserted.
	result, err := ds.List(ctx, ownerPrincipal(tenantA), service.DomainsListParams{PageSize: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if result.TotalCount != 0 {
		t.Errorf("domains after forbidden create = %d, want 0", result.TotalCount)
	}
}

func TestDomainsService_Create_ManagerSucceeds(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@create-manager.com")

	d, err := ds.Create(
		ctx,
		principalWithRole(tenantA, "manager"),
		service.DomainsCreateParams{Domain: "manager-create.example.com"},
	)
	if err != nil {
		t.Fatalf("manager Create: %v", err)
	}
	if d.Name != "manager-create.example.com" {
		t.Errorf("name = %s, want manager-create.example.com", d.Name)
	}
	if sched.Called() != 1 {
		t.Errorf("scheduler called %d times, want 1", sched.Called())
	}
}

func TestDomainsService_Update_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@update-viewer.com")
	d := seedDomain(t, ctx, pc, tenantA, "update-viewer.example.com")

	_, err = ds.Update(
		ctx,
		principalWithRole(tenantA, "viewer"),
		d.Uid,
		service.DomainsUpdateParams{Status: "inactive"},
	)
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("viewer Update = %v, want ErrForbidden", err)
	}
	if sched.Called() != 0 {
		t.Errorf("scheduler called %d times on forbidden update, want 0", sched.Called())
	}
	// The domain is unchanged.
	got, err := ds.Get(ctx, ownerPrincipal(tenantA), d.Uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != store.DomainStatusActive {
		t.Errorf("status after forbidden update = %s, want active", got.Status)
	}
}

func TestDomainsService_Update_ManagerSucceeds(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@update-manager.com")
	d := seedDomain(t, ctx, pc, tenantA, "update-manager.example.com")

	updated, err := ds.Update(
		ctx,
		principalWithRole(tenantA, "manager"),
		d.Uid,
		service.DomainsUpdateParams{Status: "inactive"},
	)
	if err != nil {
		t.Fatalf("manager Update: %v", err)
	}
	if updated.Status != store.DomainStatusInactive {
		t.Errorf("status = %s, want inactive", updated.Status)
	}
}

func TestDomainsService_Delete_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@delete-viewer.com")
	d := seedDomain(t, ctx, pc, tenantA, "delete-viewer.example.com")

	if err := ds.Delete(ctx, principalWithRole(tenantA, "viewer"), d.Uid); !errors.Is(
		err,
		service.ErrForbidden,
	) {
		t.Fatalf("viewer Delete = %v, want ErrForbidden", err)
	}
	if got := sched.StatsRefreshes(); len(got) != 0 {
		t.Errorf("stats refreshes on forbidden delete = %v, want none", got)
	}
	// The domain still exists.
	if _, err := ds.Get(ctx, ownerPrincipal(tenantA), d.Uid); err != nil {
		t.Errorf("domain missing after forbidden delete: %v", err)
	}
}

func TestDomainsService_Delete_ManagerSucceeds(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@delete-manager.com")
	d := seedDomain(t, ctx, pc, tenantA, "delete-manager.example.com")

	if err := ds.Delete(ctx, principalWithRole(tenantA, "manager"), d.Uid); err != nil {
		t.Fatalf("manager Delete: %v", err)
	}
	if _, err := ds.Get(ctx, ownerPrincipal(tenantA), d.Uid); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("domain present after manager delete = %v, want ErrNotFound", err)
	}
}

func TestDomainsService_DeletionImpact_CrossTenantReturnsNotFound(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	sched := &fakeScheduler{}
	svc := newTestService(pc, sched)
	ds := svc.DomainsService()

	tenantA := createTenant(t, ctx, pc, "a@impact-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@impact-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-impact.example.com")

	_, err = ds.DeletionImpact(ctx, ownerPrincipal(tenantA), d.Uid)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant DeletionImpact = %v, want ErrNotFound", err)
	}
}
