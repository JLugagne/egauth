---
title: "Getting Started"
weight: 1
---

# Getting Started with `egauth`

This guide covers how to embed the `egauth` SDK into your Go application, initialize the database stores, and wire up the dependency injection.

## 1. Installation

Install the module using `go get`:

```bash
go get github.com/JLugagne/egauth
```

## 2. Infrastructure & Database

`egauth` relies heavily on interfaces for its storage (e.g., `identity.Store`, `tokens.Store`). Out of the box, it provides robust, production-ready PostgreSQL adapters using `jackc/pgx/v5`, as well as zero-dependency in-memory adapters for testing.

### Setting up PostgreSQL

You should use the `pgxpool` to manage your database connections. `egauth` packages come with built-in `//go:embed` migrations.

```go
package main

import (
	"context"
	"log"

	"github.com/JLugagne/egauth/identity"
	identitypg "github.com/JLugagne/egauth/identity/pgx"
	
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	// 1. Initialize the connection pool
	pool, err := pgxpool.New(ctx, "postgres://user:pass@localhost:5432/mydb")
	if err != nil {
		log.Fatalf("failed to connect to db: %v", err)
	}
	defer pool.Close()

	// 2. Run Automatic Migrations
	// Each module (identity, tokens, sessions) has its own pgx subpackage with Migrations.
	if err := identitypg.Migrate(ctx, pool); err != nil {
		log.Fatalf("identity migration failed: %v", err)
	}

	// 3. Initialize Stores
	identityStore := identitypg.NewStore(pool)

	// 4. Initialize Core Logic (e.g. Hasher and Password Policy)
	hasher := argon2.NewHasher(argon2.WithMemory(64*1024), argon2.WithTime(1))
	passwordPolicy := policy.NewDefaultPolicy() // 8 char minimum

	// 5. Wire the Service
	identityService := identity.NewService(identityStore, hasher, passwordPolicy)

	// Ready to use!
}
```

## 3. Emitting Audit Events

`egauth` operates silently by default, but it can emit critical security events (failed logins, lockouts) without logging sensitive data. Implement an `event.Sink` to capture these:

```go
import (
	"log/slog"

	"github.com/JLugagne/egauth/event"
)

// ... inside main ...
loggerSink := event.NewSlogSink(slog.Default())
identityService := identity.NewService(
    identityStore, hasher, passwordPolicy,
    identity.WithEventSink(loggerSink),
)
```
