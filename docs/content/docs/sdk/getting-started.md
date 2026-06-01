---
title: "Getting Started"
weight: 1
---

# Getting Started with egauth

Welcome to the `egauth` user manual! `egauth` provides composable, unopinionated modules for Identity and Authentication in Go. Rather than forcing you into a specific web framework, `egauth` supplies the foundational blocks (Stores, Services, and optionally HTTP Handlers) that you plug into your own architecture.

## Installation

Install the library using `go get`:

```bash
go get github.com/JLugagne/egauth
```

## Basic Setup (PostgreSQL)

`egauth` relies on database abstractions (like PostgreSQL via `pgx`) or in-memory stores for testing. Below is an example of how to connect to Postgres, run the migrations, and set up your core services.

```go
package main

import (
	"context"
	"log"

	"github.com/JLugagne/egauth/identity"
	pgxstore "github.com/JLugagne/egauth/identity/pgx"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	// 1. Connect to PostgreSQL using pgxpool
	pool, err := pgxpool.New(ctx, "postgres://user:pass@localhost:5432/mydb")
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	// 2. Run migrations automatically
	if err := pgxstore.Migrate(ctx, pool); err != nil {
		log.Fatal("failed to migrate:", err)
	}

	// 3. Instantiate the core components
	store := pgxstore.NewStore(pool)
	hasher := argon2.NewHasher()
	pol := policy.NewDefaultPolicy()
	
	// 4. Create the Identity Service
	identityService := identity.NewService(store, hasher, pol)
    
    // Your service is ready! You can now register and authenticate users.
}
```

In the next sections, we'll see how to actually use the `identityService` to register users, as well as how to generate tokens for API access.
