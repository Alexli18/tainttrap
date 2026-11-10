# 0001: The project is named TaintTrap

**Date:** 2026-10-11
**Status:** accepted

## Context
The working name ActionGate cannot be published: the PyPI name `actiongate` belongs to an unrelated project (actiongate-oss/actiongate, pre-execution gating and rate limiting of agent actions). The name had to be settled before the first release, while no package, hook or state directory existed outside the maintainer's machine, so the rename needs no compatibility alias.

## Decision
The project is TaintTrap. The PyPI package, the Python module and the commands are `tainttrap` and `tainttrap-hook`; state, configuration and runtime directories, sockets and environment variables (`TAINTTRAP_*`) follow. The repository is `Alexli18/tainttrap`. The name says what the product does: it follows where untrusted data and copied secrets go and stops the call that would let them out.

## Alternatives considered
- **actiongate** - taken on PyPI by actiongate-oss/actiongate.
- **agentbouncer** - next to `agent-bouncer` on PyPI (a policy enforcement point for agent spending) and an `agentbouncer` / `@agentbouncer/sdk` placeholder on npm; too easy to confuse.
- **taintcheck** - the name of the classic dynamic taint analysis system TaintCheck (Newsome and Song, NDSS 2005), and a generic term besides.

## Security consequences
None on detection. A distinct name makes the official-distribution rule in SECURITY.md enforceable: only `Alexli18/tainttrap` and the PyPI package `tainttrap` are official. Known risk: the GitHub organization `TaintTrap` exists (created 2014, Android taint-tracking forks from the TaintDroid era, last push 2016). It is not ours, and README and SECURITY.md must link the repository explicitly so nobody takes that organization for the project.

## False-positive consequences
None: a rename only. The detection benchmark gives the same outcome and reason codes for every case before and after (297/297 attacks caught, no benign case blocked).

## Revisit when
A trademark conflict appears, or the dormant `TaintTrap` organization becomes active in a way that confuses users.
