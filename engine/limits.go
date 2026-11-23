package main

// Runtime policy, in two halves that must not be conflated.
//
// Forbidden: hidden application-level caps. A value the user supplied is
// passed through to execution without an application upper bound, and no cap
// may be applied from a constant the user cannot read or override.
//
// Allowed: explicit technical limits. Dial/connect/TLS/header deadlines,
// context.WithTimeout around outbound calls, worker-pool and semaphore sizes,
// broker quotas and sandbox bounds are legitimate engineering measures. Each one
// must arrive from a readable request field or a documented default, and must
// stay visible in the UI or status row.
//
// See the "Технічні межі виконання дозволені" section of AGENTS.md. This file
// carries no limits of its own; per-feature timeouts live next to the feature
// that owns them.
