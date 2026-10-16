---
title: "Philosophy & Architecture"
weight: 10
---

# Philosophy & Architecture

Authentication bugs are usually configuration bugs: a cookie set up differently on two handlers, a gate added to one route and forgotten on its sibling, an option a constructor silently ignored. `egauth` is built so that these mistakes cannot be written, are refused at startup, or are caught by a CI guard.

## One composition object

`egauth.New` takes one `egauth.Config` and returns an `egauth.Auth`. The `Auth` owns every policy object, store handle and background worker until `Close`. The application never wires a cookie, issuer, limiter, event sink or gate into a handler, so no two of them can disagree. Every field carries a validation tag, and `New` returns all problems together. There is no request-time "misconfigured" answer.

## Deny-by-default routes

`Auth.Routes` is the only way to serve application routes. A route is declared as `Protect` (an established human session), `Optional` (everyone, with an anonymous principal when a gate fails), `ProtectAPI` (an API key of a declared kind) or `Public`. `Build` mounts the auth endpoints under the base path and answers 404 to everything undeclared. The gate set of each kind is fixed by the library.

## Sealed session state

A login mints its attributes once: subject, tenant, factors, authentication time, must-change, remember-me and return target. They are sealed, stored on every artefact and replayed. A later step may add a factor, never re-derive or upgrade one.

## State-derived revocation

A per-subject security epoch is bumped atomically with every security mutation and sealed into every artefact. Event fan-out only speeds cleanup up, so a missed event cannot leave a revoked session alive.

## Layering

Contract packages (`store/*`, `kek`, `signing`, `principal`, `event`) import nothing above them. Services live under `internal/` and sit on the contracts. The root package composes them. Adapters implement contracts and never import core `internal/` packages.

## Opt-outs

Every weakening of a default is a field of `egauth.InsecureOptOuts` with a written reason. `Auth.Posture` lists them, and a production configuration has none.

## Guards

Static guards (`tools/archtest`), behavioural journeys (`internal/journeytest`) and documentation guards (`tools/doclint`) fail the build when a contribution reopens one of these doors. The invariants and their guards are listed in [CONTRIBUTING.md](https://github.com/JLugagne/egauth/blob/main/CONTRIBUTING.md).

## Multi-tenancy

Tenancy is single-tenant, by subdomain, or resolved from the request. A request whose tenant cannot be resolved is refused, and credentials and ceremony handles are bound to their tenant.
