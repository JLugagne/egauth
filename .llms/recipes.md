# Recipes

Every Go block is embedded from a compiled example. Search the root `example_test.go` and `adapters/pgx/pgxstore/example_test.go` for the originals.

## Memory-backed service

<!-- embed: example_test.go#ExampleNew -->
```go
key := make([]byte, 32)
_, _ = rand.Read(key)
k, _ := kek.NewLocal(key)
signer, _ := signing.EdDSA("k1", key)
mail := inbox{links: make(chan string, 1)}

auth, err := egauth.New(egauth.Config[struct{}]{
	PublicOrigin: "http://localhost:8080",
	Proxy:        egauth.DirectClients(),
	Storage:      memstore.New(k),
	KEK:          k,
	Sessions:     egauth.JWT(egauth.StaticKeys(signer)),
	Transport:    egauth.Bearer,
	Admin:        egauth.RoleAdmin("admin"),
	Email:        mail,
	Pages:        egauth.Pages{Login: "/login", AfterLogin: "/", ConfirmRegistration: "/confirm", PasswordReset: "/reset", SecurityRevert: "/revert"},
	Modules:      egauth.Modules{Password: &egauth.PasswordModule{}},
})
if err != nil {
	fmt.Println("new:", err)
	return
}
defer func() { _ = auth.Close() }()

h, err := auth.Routes().
	Protect("GET /me", func(w http.ResponseWriter, _ *http.Request, _ egauth.Principal[struct{}]) {
		_, _ = fmt.Fprintln(w, "hello")
	}).
	Build()
if err != nil {
	fmt.Println("routes:", err)
	return
}

call := func(method, path, token string, body map[string]any, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	var payload strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		payload = *strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, "http://localhost:8080"+path, &payload)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set(egauth.HeaderTransport, "bearer")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const email, password = "ada@example.com", "tapir-granite-velvet-orbit-29"
rec, begin := call("POST", "/auth"+egauth.PathRegister, "", map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: password})
fmt.Println("register:", rec.Code)

link, _ := url.Parse(<-mail.links)
bind, _ := begin[egauth.FieldBind].(string)
rec, _ = call("POST", "/auth"+egauth.PathRegisterConfirm, "", map[string]any{egauth.FieldToken: link.Query().Get(egauth.FieldToken), egauth.FieldBind: bind})
fmt.Println("confirm:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathLogin, "", map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: password})
access, refresh := rec.Header().Get("X-Egauth-Access-Token"), rec.Header().Get("X-Egauth-Refresh-Token")
fmt.Println("login:", rec.Code)

rec, _ = call("GET", "/me", access, nil)
fmt.Println("me:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathRefresh, "", nil, "X-Egauth-Refresh-Token", refresh)
access, refresh = rec.Header().Get("X-Egauth-Access-Token"), rec.Header().Get("X-Egauth-Refresh-Token")
fmt.Println("refresh:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathLogout, access, nil)
fmt.Println("logout:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathRefresh, "", nil, "X-Egauth-Refresh-Token", refresh)
fmt.Println("refresh after logout:", rec.Code)
// Output:
// register: 202
// confirm: 200
// login: 200
// me: 200
// refresh: 200
// logout: 200
// refresh after logout: 401
```

## Application routes

<!-- embed: example_test.go#ExampleRoutes -->
```go
var auth *egauth.Auth[struct{}]
var page, report, adminDisable egauth.PrincipalHandler[struct{}]
var health http.Handler

h, err := auth.Routes().
	Optional("GET /", page).
	Protect("POST /admin/disable/{id}", adminDisable,
		egauth.RequireAnyRole("admin"), egauth.RequireMFA(), egauth.RequireFreshAuth(egauth.Fresh5m)).
	ProtectAPI("GET /api/report", report, egauth.Kinds("automation"), egauth.RequireAnyScope("report:read")).
	Public("GET /healthz", health).
	Build()
if err != nil {
	return
}
_ = http.ListenAndServe("localhost:8080", h)
```

## Administration through a facade

<!-- embed: example_test.go#ExampleAccounts -->
```go
ctx := context.Background()
var auth *egauth.Auth[struct{}]
var admin principal.Caller
var user uuid.UUID

if err := auth.Accounts().Disable(ctx, admin, user); err != nil {
	if errors.Is(err, egauth.ErrForbidden) || errors.Is(err, store.ErrNotFound) {
		return
	}
}
```

## PostgreSQL

<!-- embed: adapters/pgx/pgxstore/example_test.go#ExampleNew_postgres -->
```go
ctx := context.Background()
pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
if err != nil {
	log.Fatal(err)
}
defer pool.Close()

if err := pgxstore.Migrate(ctx, pool); err != nil {
	log.Fatal(err)
}
storage, err := pgxstore.New(ctx, pool)
if err != nil {
	log.Fatal(err)
}

auth, err := egauth.New(egauth.Config[struct{}]{
	PublicOrigin: "https://auth.example.com",
	Proxy:        egauth.DirectClients(),
	Storage:      storage,
	KEK:          kekFromEnv("EGAUTH_KEK"),
	Sessions:     egauth.JWT(egauth.StaticKeys(signerFromEnv("EGAUTH_SIGNING_SEED"))),
	Admin:        egauth.RoleAdmin("admin"),
	Email:        mailer{},
	Pages:        egauth.Pages{Login: "/login", AfterLogin: "/", ConfirmRegistration: "/confirm", PasswordReset: "/reset", SecurityRevert: "/revert"},
	Modules:      egauth.Modules{Password: &egauth.PasswordModule{}},
})
if err != nil {
	log.Fatal(err)
}
defer func() { _ = auth.Close() }()
```

## Upgrading v0.16 secrets

<!-- embed: example_test.go#ExampleUpgradeSecretsV016 -->
```go
ctx := context.Background()
var storage egauth.Storage
var oldKey, newKey []byte

legacy, err := kek.LegacyLocalV016(oldKey)
if err != nil {
	return
}
current, err := kek.NewLocal(newKey)
if err != nil {
	return
}
report, err := egauth.UpgradeSecretsV016(ctx, storage, legacy, current)
if err != nil {
	return
}
fmt.Println(report)
```

## Choosing options

- Browser app: `egauth.Cookies` (default) with `egauth.JWT` or `egauth.Stateful`.
- Mobile or API client: `egauth.Bearer`, or `egauth.CookiesAndBearer` when both are served.
- Behind a reverse proxy: `egauth.TrustedProxies(prefix)`; direct exposure: `egauth.DirectClients()`.
- Several tenants on subdomains: `egauth.TenantBySubdomain()` with `egauth.TenantKeys()`.
- Machine access: enable `Modules.APIKeys`, issue keys through `Auth.APIKeys`, serve with `ProtectAPI`.
- A separate service that only verifies tokens: `egauth.NewResourceServer`.
