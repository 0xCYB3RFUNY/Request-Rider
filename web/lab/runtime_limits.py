"""Runtime configuration policy module.

Two different rules meet here, and conflating them used to block real work.

**Forbidden:** hidden application-level caps. Historical environment-backed
caps were removed, and a value the user supplied must never be truncated by an
application upper bound the user cannot see or override.

**Allowed:** explicit technical limits. Timeouts, worker-pool sizes, broker
quotas and sandbox bounds are legitimate engineering measures, provided they
come from a readable field or a documented default and stay visible in the UI or
status row. See the "Технічні межі виконання дозволені" section of ``AGENTS.md``.

This module carries no limits of its own. It is the contract statement for the
policy, not the place where per-feature timeouts live: those belong to the
module that owns the feature, so that they are visible next to the request
field that configures them.
"""

from __future__ import annotations
