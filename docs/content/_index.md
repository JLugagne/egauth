---
title: "Introduction"
type: docs
---

# Welcome to egauth

**egauth** is an authentication and identity management library for Go, designed to be embedded in any application with maximum composability and minimum adherence.

## Motivation

While the Go ecosystem has many excellent authentication libraries, developers often have to choose between low-level primitives that require manual assembly, or full-featured frameworks that impose specific architectural choices (like a particular ORM or HTTP router).

`egauth` was built to provide a middle ground. It offers a comprehensive set of identity and authentication modules that are highly composable and unopinionated. It aims to integrate seamlessly into your existing Go project, offering flexibility over storage backends and HTTP routing without dictating your application's design.

### A note on how this project was built

Please read this before adopting `egauth` for anything sensitive. The library was developed largely through "vibe coding" (AI-assisted development), and its security review to date is an AI-driven audit rather than an external human one. It exists because I wanted a library like this for my own projects. The code is engineered carefully and secure-by-default, and an adversarial pass surfaced no high or critical issues — but it has not yet undergone an independent, third-party security audit. Weigh that status accordingly when deciding whether to rely on it.

## Key Features

- **Extreme Composability:** Separate business logic into independent modules (identity, sessions, tokens, passwords).
- **Programmatic API:** Provided as a first-class citizen.
- **A la carte HTTP Handlers:** Built directly within the respective modules via dependency injection.
- **Contract Testing:** Guarantees the correctness of each implementation.
- **Unopinionated:** Does not impose an ORM, HTTP framework, or global application structure.
- **Native Multi-tenancy:** Native support for tenant isolation via the Options pattern.
