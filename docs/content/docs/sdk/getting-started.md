---
title: "Getting Started"
weight: 1
---

# Getting Started

## 1. Install

```sh
go get github.com/JLugagne/egauth
go get github.com/JLugagne/egauth/adapters/pgx
```

The second module holds the PostgreSQL stores. Go 1.26 or newer.

## 2. The minimal service

`memstore` keeps everything in memory, so this runs without a database. It registers a password user, confirms the emailed link, logs in, calls a protected route, refreshes and logs out.

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

What to notice:

- `PublicOrigin` is the one source of truth for cookies, redirects, CSRF and the passkey relying-party ID.
- `Storage`, `KEK` and `Sessions` are the three pieces of infrastructure. Everything else has a default.
- `Modules` enables features. At least one primary module is required.
- `Email` is a deliverer with one method per message kind.
- `Routes().Build()` returns the single handler to serve.

## 3. Production storage

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

`pgxstore.Migrate` is expand-only and idempotent. `pgxstore.New` only reads, and fails when a migration is missing.

## 4. Next

Read [Routes and Gates](../routes-and-gates/) to declare your own routes.
