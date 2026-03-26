---
name: charon-guide
description: Use when porting Charon components to understand Go codebase architecture, workflow, design patterns, or component responsibilities
---

# Charon Architecture Guide

Reference for understanding the Charon Go codebase when porting to Pluto (Rust).

## What is Charon?

Distributed validator middleware for Ethereum staking. Enables running a single validator across multiple independent nodes using threshold BLS signatures. Each validator duty flows through a multi-stage workflow with consensus and signature aggregation.

## Knowledge Base

When you need deeper understanding:

| Topic | Location |
|-------|----------|
| High-level overview | `charon/README.md` |
| Detailed architecture | `charon/docs/architecture.md` |
| Go coding guidelines | `charon/docs/goguidelines.md` |
| Configuration options | `charon/docs/configuration.md` |
| DKG details | `charon/docs/dkg.md` |
| Consensus (QBFT) | `charon/docs/consensus.md`, `charon/core/qbft/README.md` |
| Metrics | `charon/docs/metrics.md` |
| Error reason codes | `charon/docs/reasons.md` |
| Package structure | `charon/docs/structure.md` |
| Product docs | https://docs.obol.org/next |

## Core Workflow

Every validator duty (attestation, block proposal, etc.) flows through these components in order:

```
Scheduler → Fetcher → Consensus → DutyDB → ValidatorAPI → ParSigDB → ParSigEx → SigAgg → AggSigDB → Bcast
```

| Component | Responsibility | Go Package |
|-----------|---------------|------------|
| **Scheduler** | Triggers duties at optimal times based on beacon chain state | `core/scheduler/` |
| **Fetcher** | Fetches unsigned duty data from beacon node | `core/fetcher/` |
| **Consensus** | QBFT consensus to agree on duty data across all nodes | `core/consensus/`, `core/qbft/` |
| **DutyDB** | Persists unsigned data, slashing protection | `core/dutydb/` |
| **ValidatorAPI** | Serves data to validator clients, receives partial signatures | `core/validatorapi/` |
| **ParSigDB** | Stores partial threshold BLS signatures from local/remote VCs | `core/parsigdb/` |
| **ParSigEx** | Exchanges partial signatures with peers via p2p | `core/parsigex/` |
| **SigAgg** | Aggregates partial signatures when threshold reached | `core/sigagg/` |
| **AggSigDB** | Persists aggregated signatures | `core/aggsigdb/` |
| **Bcast** | Broadcasts final signatures to beacon node | `core/bcast/` |

**Porting note:** When porting a component, trace its inputs and outputs through this pipeline.

## Key Abstractions

| Concept | Definition | Go Type |
|---------|------------|---------|
| **Duty** | Unit of work (slot + duty type). Cluster-level, not per-validator. | `core.Duty` |
| **PubKey** | DV root public key, validator identifier in workflow | `core.PubKey` |
| **UnsignedData** | Abstract type for attestation data, blocks, etc. | `core.UnsignedData` (interface) |
| **SignedData** | Fully signed duty data | `core.SignedData` (interface) |
| **ParSignedData** | Partially signed data from single threshold BLS share | `core.ParSignedData` (struct) |

**Type encoding:** Abstract types are encoded/decoded via `core/encode.go`. Always check this file when porting type serialization.

## Design Patterns

| Pattern | Description | Porting Impact |
|---------|-------------|----------------|
| **Immutable values** | Components consume and produce immutable values (actor-like) | Always `.Clone()` before sharing/caching in Rust |
| **Callback subscriptions** | Components decoupled via subscriptions, not direct calls | Use channels or callbacks in Rust |
| **Type-safe encoding** | Abstract types use custom encoding/decoding | Port `core/encode.go` logic carefully |

## Consensus (QBFT)

Charon uses **QBFT** (Istanbul BFT) for consensus. Each duty requires consensus to ensure all nodes sign identical data (required for BLS threshold signatures and slashing protection).

**Key files:**
- `core/qbft/` - QBFT implementation
- `core/consensus/` - Consensus component integration
- `charon/docs/consensus.md` - Design documentation

**Porting note:** QBFT is complex. Port incrementally and verify against Go test vectors.

## Package Structure

| Go Package | Purpose | Rust Equivalent |
|------------|---------|-----------------|
| `app/` | Application entrypoint, wiring, infrastructure (log, errors, tracer, lifecycle) | `pluto/crates/app/` |
| `cluster/` | Cluster config, lock files, DKG artifacts | `pluto/crates/cluster/` |
| `cmd/` | CLI commands (run, dkg, create, test, etc.) | `pluto/crates/cli/` |
| `core/` | Core workflow business logic and components | `pluto/crates/core/` |
| `dkg/` | Distributed Key Generation logic | `pluto/crates/dkg/` |
| `eth2util/` | ETH2 utilities (signing, deposits, keystores) | `pluto/crates/eth2util/` |
| `p2p/` | libp2p networking and discv5 peer discovery | `pluto/crates/p2p/` |
| `tbls/` | Threshold BLS signature scheme | `pluto/crates/crypto/` |
| `testutil/` | Test utilities, mocks, golden files | `pluto/crates/testutil/` |

## Common Porting Scenarios

### Porting a Workflow Component

1. Read `charon/docs/architecture.md` for component interfaces
2. Identify inputs (what triggers this component?)
3. Identify outputs (what does it produce? who consumes it?)
4. Check `core/<component>/` for implementation
5. Check subscriptions in `app/app.go` (wiring/stitching logic)
6. Port logic, preserving immutability and callback patterns

### Adding New Duty Types

When porting code that adds duty types:

1. Add to `core/types.go` (duty type constants)
2. Add to `core/encode.go` (encoding/decoding logic)
3. Update Scheduler, Fetcher, and relevant components

### Understanding Error Handling

Go style:
- Just return errors, don't log and return
- Wrap external errors: `errors.Wrap(err, "do something")`
- Use `app/errors` for structured errors with fields

Rust style: See `rust-style` skill and AGENTS.md.

### Working with Cluster Lock Files

- `cluster-definition.json`: Intended cluster config (operators, validators)
- `cluster-lock.json`: Extends definition with DV public keys and shares (DKG output)
- See `cluster/` package for parsing/validation

## Dependency Notes

Charon uses forked dependencies:
- `github.com/ObolNetwork/kryptology` (security fixes)
- `github.com/ObolNetwork/go-eth2-client` (kept up to date)

When porting code using these, check if Rust equivalents exist or if porting is needed.

## Version Compatibility

Important for protocol compatibility:

- **Compatible:** Same MAJOR version, different MINOR/PATCH
- **Incompatible:** Different MAJOR version
- **DKG:** Requires matching MAJOR and MINOR versions (PATCH can differ)

## Quick Reference Commands

When exploring Charon codebase:

```bash
# Find a function
grep -r "func FunctionName" charon/

# See package structure
ls -la charon/<directory>/

# Check imports
grep "^import" charon/path/to/file.go

# Run specific Go test (to understand behavior)
cd charon && go test -run TestFunctionName ./path/to/package
```
