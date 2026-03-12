# Pluto Implementation Plan - Team of 3 Developers

**Target:** Feature parity with Charon v1.7.1
**Team Size:** 3 developers
**Estimated Timeline:** 4-6 months
**Go Reference:** `~/projects/charon` (v1.7.1)

---

## Team Structure & Roles

### Developer A: Core Runtime & Integration Lead
**Focus:** Runtime orchestration, lifecycle, main execution loop
**Skills:** System design, async Rust, component wiring

### Developer B: Signature Flow & P2P
**Focus:** Consensus, partial signatures, DKG, cryptographic protocols
**Skills:** Distributed systems, crypto, P2P protocols

### Developer C: API & External Integration
**Focus:** Validator API, beacon client, CLI commands
**Skills:** HTTP APIs, client integration, CLI development

---

## Phase 1: Foundation (Weeks 1-4)
**Goal:** Build independent components with no cross-dependencies

### Developer A: Database Layer & Lifecycle
- [ ] **Week 1-2:** Implement `core/dutydb`
  - Go reference: `charon/core/dutydb/dutydb.go` (198 LOC)
  - Storage for scheduled duties
  - Query by duty type, validator index, epoch/slot
  - In-memory implementation sufficient for Phase 1
  - **Deliverable:** `crates/core/src/dutydb/` with tests

- [ ] **Week 2-3:** Implement `core/aggsigdb`
  - Go reference: `charon/core/aggsigdb/aggsigdb.go` (512 LOC)
  - Storage for aggregate signatures
  - Query by duty, pubkey
  - **Deliverable:** `crates/core/src/aggsigdb/` with tests

- [ ] **Week 3-4:** Implement `app/lifecycle`
  - Go reference: `charon/app/lifecycle/` (~400 LOC)
  - Component start/stop hooks
  - Graceful shutdown coordination
  - Dependency ordering
  - **Deliverable:** `crates/app/src/lifecycle.rs` with tests

### Developer B: P2P Communication Layer
- [ ] **Week 1-2:** Implement P2P sender/receiver abstractions
  - Go reference: `charon/app/peerinfo/` and P2P utilities
  - Abstraction over libp2p for sending protocol messages
  - Message routing by protocol ID
  - **Deliverable:** `crates/p2p/src/sender.rs`, `crates/p2p/src/receiver.rs`

- [ ] **Week 2-4:** Implement `core/parsigex` (Partial Signature Exchange)
  - Go reference: `charon/core/parsigex/parsigex.go` (~400 LOC)
  - P2P protocol for exchanging partial signatures
  - Uses existing `parasigdb` (already in Rust)
  - Verify partial signatures from peers
  - **Deliverable:** `crates/core/src/parsigex/` with tests
  - **Dependency:** P2P sender/receiver (Week 1-2)

### Developer C: Beacon Node Integration
- [ ] **Week 1-3:** Complete `eth2wrap` implementation
  - Go reference: `charon/app/eth2wrap/eth2wrap.go` (~2000 LOC)
  - Wrap beacon node API with timeout/retry
  - Multi-client support with fallback
  - Error handling and metrics
  - **Deliverable:** `crates/app/src/eth2wrap/` with full API coverage

- [ ] **Week 3-4:** Implement config file support
  - Go reference: `charon/app/config.go` (uses viper)
  - TOML config file parsing
  - Merge CLI flags with config file
  - Config validation
  - **Deliverable:** `crates/cli/src/config.rs` with tests

**Phase 1 Milestone:** All standalone components ready, no runtime integration yet

---

## Phase 2: Core Workflow Components (Weeks 5-8)
**Goal:** Implement duty lifecycle components

### Developer A: Scheduler
- [ ] **Week 5-6:** Implement `core/scheduler`
  - Go reference: `charon/core/scheduler/scheduler.go` (~300 LOC)
  - Subscribe to beacon node for duties
  - Assign duties to validators based on cluster share index
  - Store duties in DutyDB
  - Emit duty events
  - **Deliverable:** `crates/core/src/scheduler/` with tests
  - **Dependency:** DutyDB (Phase 1), eth2wrap (Phase 1)

- [ ] **Week 6-8:** Implement `core/fetcher`
  - Go reference: `charon/core/fetcher/fetcher.go` (~400 LOC)
  - Fetch unsigned data for duties (attestations, proposals, etc.)
  - Query beacon node for duty-specific data
  - Handle attester, proposer, sync committee duties
  - **Deliverable:** `crates/core/src/fetcher/` with tests
  - **Dependency:** DutyDB (Phase 1), eth2wrap (Phase 1)

### Developer B: Signature Aggregation & Broadcast
- [ ] **Week 5-6:** Implement `core/sigagg`
  - Go reference: `charon/core/sigagg/sigagg.go` (~200 LOC)
  - Collect partial signatures from ParSigDB
  - Aggregate using BLS threshold signatures
  - Store in AggSigDB
  - **Deliverable:** `crates/core/src/sigagg/` with tests
  - **Dependency:** ParSigDB (exists), AggSigDB (Phase 1), ParSigEx (Phase 1)

- [ ] **Week 6-8:** Implement `core/bcast`
  - Go reference: `charon/core/bcast/bcast.go` (~300 LOC)
  - Broadcast signed duties to beacon node
  - Handle broadcast failures and retries
  - Support all duty types
  - **Deliverable:** `crates/core/src/bcast/` with tests
  - **Dependency:** AggSigDB (Phase 1), eth2wrap (Phase 1)

### Developer C: Validator API Router
- [ ] **Week 5-8:** Implement `core/validatorapi`
  - Go reference: `charon/core/validatorapi/router.go` (~800 LOC)
  - HTTP server for validator client connections
  - Proxy read-only requests to beacon node
  - Intercept signing requests
  - Route to consensus layer
  - **Endpoints:** All standard validator API endpoints
  - **Deliverable:** `crates/core/src/validatorapi/` with integration tests
  - **Dependency:** eth2wrap (Phase 1), ParSigDB (exists)

**Phase 2 Milestone:** All duty lifecycle components ready for integration

---

## Phase 3: Runtime Integration (Weeks 9-11)
**Goal:** Wire everything together in main runtime

### Developer A: Main Runtime Loop
- [ ] **Week 9-11:** Implement `app::run()` and `run` command
  - Go reference: `charon/app/app.go` (1,256 LOC) + `charon/cmd/run.go` (221 LOC)
  - Initialize all components in correct order
  - Wire dataflow: Scheduler → Fetcher → Consensus → SigAgg → Bcast
  - Set up P2P networking
  - Configure lifecycle hooks
  - Graceful shutdown
  - **Deliverable:** Working `pluto run` command
  - **Dependency:** ALL Phase 2 components
  - **Testing:** Integration test with simnet

### Developer B: Consensus Integration & Priority Protocol
- [ ] **Week 9-10:** Wire QBFT consensus into runtime
  - Go reference: `charon/core/consensus/component.go`
  - Integrate existing QBFT implementation
  - Connect to Fetcher (input) and ParSigDB (output)
  - Protocol registration
  - **Deliverable:** Consensus component integrated

- [ ] **Week 10-11:** Implement `core/priority`
  - Go reference: `charon/core/priority/priority.go` (~200 LOC)
  - Priority protocol for leader election optimization
  - Protocol wire-up
  - **Deliverable:** `crates/core/src/priority/` with tests

### Developer C: Tracker & Monitoring
- [ ] **Week 9-11:** Implement `core/tracker`
  - Go reference: `charon/core/tracker/tracker.go` (~600 LOC)
  - Track duty execution through all stages
  - Performance metrics (inclusion delay, etc.)
  - Prometheus metrics
  - Duty status queries
  - **Deliverable:** `crates/core/src/tracker/` with metrics
  - **Dependency:** Integrated runtime (can develop in parallel with Dev A)

**Phase 3 Milestone:** Working distributed validator node - can perform duties

---

## Phase 4: DKG Implementation (Weeks 12-17)
**Goal:** Implement distributed key generation

### Developer A: DKG Orchestration & Command
- [ ] **Week 12-14:** Implement DKG orchestration
  - Go reference: `charon/dkg/dkg.go` (1,321 LOC)
  - DKG ceremony state machine
  - Phase coordination (sync, key generation, verification)
  - Integration with P2P and FROST
  - **Deliverable:** `crates/dkg/src/orchestrator.rs`
  - **Dependency:** FROST (Dev B), DKG broadcast (Dev B)

- [ ] **Week 15-16:** Implement `dkg` command
  - Go reference: `charon/cmd/dkg.go` (~80 LOC) + ceremony logic
  - CLI for running DKG ceremony
  - Connect to Obol API for ceremony coordination
  - Save lock file
  - **Deliverable:** Working `pluto dkg` command
  - **Dependency:** DKG orchestration

- [ ] **Week 16-17:** Implement `create dkg` command
  - Go reference: `charon/cmd/createdkg.go` (~200 LOC)
  - Create DKG definition file
  - Validation
  - **Deliverable:** `pluto create dkg` command

### Developer B: FROST Protocol & DKG Broadcast
- [ ] **Week 12-16:** Implement FROST protocol
  - Go reference: `charon/dkg/frost/` (~600 LOC) + crypto implementation
  - Distributed key generation using FROST threshold signatures
  - Round 1: Commitments
  - Round 2: Shares
  - Verification and aggregation
  - **Deliverable:** `crates/dkg/src/frost/` with comprehensive tests
  - **Note:** This is cryptographically complex, requires careful review

- [ ] **Week 16-17:** Implement `dkg/bcast`
  - Go reference: `charon/dkg/bcast/` (~500 LOC)
  - Broadcast mechanism for DKG messages
  - Reliable broadcast protocol
  - **Deliverable:** `crates/dkg/src/bcast/` with tests

### Developer C: Create Cluster & Validation
- [ ] **Week 12-14:** Implement `create cluster` command
  - Go reference: `charon/cmd/createcluster.go` (~400 LOC)
  - Create cluster definition and configuration
  - Generate ENRs for operators
  - Validation
  - **Deliverable:** `pluto create cluster` command

- [ ] **Week 14-16:** Implement `combine` command
  - Go reference: `charon/cmd/combine.go` (~150 LOC)
  - Combine keyshares for recovery
  - Validation and safety checks
  - **Deliverable:** `pluto combine` command

- [ ] **Week 16-17:** Implement `dkg/nodesigs`
  - Go reference: `charon/dkg/nodesigs/` (~300 LOC)
  - Node signature collection and verification
  - **Deliverable:** `crates/dkg/src/nodesigs/` with tests

**Phase 4 Milestone:** Full DKG ceremony support - can create new clusters

---

## Phase 5: Validator Lifecycle & Exit (Weeks 18-20)
**Goal:** Complete validator exit functionality

### Developer A: Exit Command Infrastructure
- [ ] **Week 18-19:** Implement exit message creation
  - Go reference: `charon/core/validatorapi/` exit logic
  - Partial exit message signing
  - Exit broadcast coordination
  - **Deliverable:** Core exit functionality

- [ ] **Week 19-20:** Implement exit CLI commands
  - Go reference: `charon/cmd/exit*.go`
  - `exit list` - List active validators
  - `exit sign` - Sign partial exit
  - `exit broadcast` - Broadcast full exit
  - `exit fetch` - Fetch from API
  - **Deliverable:** All exit subcommands

### Developer B: InfoSync & Priority Enhancements
- [ ] **Week 18-20:** Implement `core/infosync`
  - Go reference: `charon/core/infosync/` (~200 LOC)
  - Synchronize node information across cluster
  - Protocol version negotiation
  - **Deliverable:** `crates/core/src/infosync/`

### Developer C: Add Validators & Testing
- [ ] **Week 18-19:** Implement `alpha add-validators` command
  - Go reference: `charon/cmd/addvalidators.go`
  - Add validators to existing cluster
  - Re-sign lock file
  - **Deliverable:** `pluto alpha add-validators` command

- [ ] **Week 19-20:** Integration testing suite
  - Port critical Go integration tests
  - Simnet/mock beacon testing
  - End-to-end duty execution tests
  - **Deliverable:** Comprehensive integration test suite

**Phase 5 Milestone:** Complete validator lifecycle management

---

## Phase 6: Production Hardening (Weeks 21-24)
**Goal:** Production-ready features and testing

### All Developers (Parallel Work):

#### Developer A: Observability & Reliability
- [ ] Health checks (`app/health`)
- [ ] OpenTelemetry tracing (`app/tracer`)
- [ ] Metrics auto-registration (`app/promauto`)
- [ ] Private key file locking (`app/privkeylock`)
- [ ] Error handling utilities (`app/errors`)

#### Developer B: P2P Hardening
- [ ] Relay client implementation
- [ ] Ping protocol
- [ ] Bootnode support
- [ ] P2P resilience testing
- [ ] Connection management edge cases

#### Developer C: Testing & Documentation
- [ ] Port remaining Go tests
- [ ] Simnet integration
- [ ] Load testing
- [ ] CLI documentation
- [ ] Migration guide from Charon

#### All: Cross-Review & Verification
- [ ] Test parity validation (compare outputs with Go)
- [ ] Protocol compliance testing
- [ ] Performance benchmarking
- [ ] Security review (especially crypto code)
- [ ] End-to-end testnet validation

**Phase 6 Milestone:** Production-ready, feature-complete Pluto

---

## Dependency Graph Summary

```
Phase 1 (Parallel - No Dependencies):
├─ Dev A: DutyDB → AggSigDB → Lifecycle
├─ Dev B: P2P sender/receiver → ParSigEx
└─ Dev C: eth2wrap → Config

Phase 2 (Depends on Phase 1):
├─ Dev A: Scheduler (needs DutyDB, eth2wrap) → Fetcher (needs DutyDB, eth2wrap)
├─ Dev B: SigAgg (needs AggSigDB, ParSigEx) → Bcast (needs eth2wrap)
└─ Dev C: ValidatorAPI (needs eth2wrap)

Phase 3 (Depends on Phase 2):
├─ Dev A: app::run (needs ALL Phase 2) ← CRITICAL PATH
├─ Dev B: Consensus integration → Priority
└─ Dev C: Tracker (can parallel with Dev A)

Phase 4 (Parallel after Phase 3):
├─ Dev A: DKG orchestration → dkg command
├─ Dev B: FROST protocol → DKG broadcast
└─ Dev C: create cluster → combine

Phase 5 (Parallel):
├─ Dev A: Exit commands
├─ Dev B: InfoSync
└─ Dev C: Add validators + Testing

Phase 6 (Parallel):
└─ All: Hardening, testing, documentation
```

---

## Critical Path

The **longest dependency chain** (determines minimum timeline):

1. **Week 1-4:** Database Layer (Dev A) → 4 weeks
2. **Week 5-6:** Scheduler (Dev A) → 2 weeks
3. **Week 6-8:** Fetcher (Dev A) → 2 weeks
4. **Week 9-11:** Runtime Integration (Dev A) → 3 weeks
5. **Week 12-14:** DKG Orchestration (Dev A) → 3 weeks
6. **Week 15-16:** DKG Command (Dev A) → 2 weeks
7. **Week 18-20:** Exit Commands (Dev A) → 2 weeks
8. **Week 21-24:** Production Hardening (All) → 4 weeks

**Total Critical Path: 22 weeks (~5.5 months)**

---

## Risk Mitigation

### High-Risk Items

1. **FROST Protocol (Phase 4, Dev B)**
   - **Risk:** Complex cryptographic protocol, easy to introduce subtle bugs
   - **Mitigation:**
     - Port Go tests exactly
     - Generate test vectors from Go implementation
     - External cryptographic review before merge
     - Consider using existing FROST library if available

2. **Runtime Integration (Phase 3, Dev A)**
   - **Risk:** Complex component wiring, many failure modes
   - **Mitigation:**
     - Incremental integration (add one component at a time)
     - Comprehensive logging at component boundaries
     - Integration tests at each step
     - Simnet testing before mainnet

3. **ValidatorAPI (Phase 2, Dev C)**
   - **Risk:** Must match exact API spec, validator clients are picky
   - **Mitigation:**
     - Compare HTTP traces between Go and Rust implementations
     - Test with multiple validator clients (Lighthouse, Teku, etc.)
     - Port API tests from Go

4. **Test Parity (Phase 6)**
   - **Risk:** Insufficient testing leads to behavioral divergence
   - **Mitigation:**
     - Port tests alongside implementation (not after)
     - Golden file tests for serialization
     - Differential testing (compare Go vs Rust outputs)

### Weekly Sync Points

- **Monday:** Sprint planning, blockers discussion
- **Wednesday:** Mid-week check-in, dependency coordination
- **Friday:** Code review, integration testing, demos

### Definition of Done (Each Component)

- [ ] Functionally equivalent to Go reference (cite specific files/LOC)
- [ ] Unit tests ported from Go (or new tests if no Go tests exist)
- [ ] No clippy warnings
- [ ] Documentation for all public APIs
- [ ] Integration test (if applicable)
- [ ] Reviewed by at least one other team member
- [ ] Verified against Go output (for data/protocol components)

---

## Measurement & Success Criteria

### Phase Completion Gates

- **Phase 1:** All components have unit tests passing
- **Phase 2:** Integration test: fetch duty → store → query
- **Phase 3:** End-to-end test: `pluto run` executes one full duty cycle
- **Phase 4:** DKG ceremony completes successfully in simnet
- **Phase 5:** Validator exit executed successfully
- **Phase 6:** Pluto passes all ported Go integration tests

### Final Acceptance Criteria

1. **Functional Parity:**
   - [ ] All Go CLI commands present in Rust
   - [ ] Output formats match (JSON, protobuf, wire protocols)
   - [ ] Error messages equivalent

2. **Testing:**
   - [ ] 80%+ test coverage on core components
   - [ ] All critical Go tests ported
   - [ ] Integration tests passing

3. **Performance:**
   - [ ] Duty execution latency within 10% of Go
   - [ ] Memory usage comparable or better
   - [ ] P2P message throughput adequate

4. **Production Readiness:**
   - [ ] Runs on testnet for 1 week without issues
   - [ ] All observability hooks present
   - [ ] Documentation complete

---

## Adaptation & Flexibility

This plan assumes:
- Developers are experienced with Rust and async programming
- Go reference code is well-understood
- No major architectural surprises

**If behind schedule:**
1. Defer Phase 6 hardening items
2. Reduce test porting (keep critical tests only)
3. Skip `add-validators` command (low priority)
4. Simplify initial `combine` implementation

**If ahead of schedule:**
1. Add performance optimizations
2. Expand test coverage
3. Add simnet improvements
4. Start documentation early

---

## Communication & Coordination

### Daily Standups (15 min)
- What did I complete yesterday?
- What am I working on today?
- Any blockers or dependencies?

### Code Review Guidelines
- Reviews within 24 hours
- Focus on functional equivalence first
- Use Go reference as source of truth
- Require test evidence for behavioral claims

### Documentation Requirements
- Link to Go reference file:line in module doc comments
- Note any intentional deviations from Go
- Document failure modes and error conditions
- Add examples for complex APIs

---

## Getting Started Checklist

### Week 0 (Pre-work)
- [ ] All devs: Read `AGENTS.md` and understand porting workflow
- [ ] All devs: Verify Go reference checkout at `~/projects/charon` (tag v1.7.1)
- [ ] All devs: Run `cargo test` to verify Rust environment
- [ ] All devs: Identify IDE/tools for Go ↔ Rust cross-referencing
- [ ] Dev A: Read `charon/app/app.go` and `charon/core/dutydb/`
- [ ] Dev B: Read `charon/core/parsigex/` and P2P layer
- [ ] Dev C: Read `charon/app/eth2wrap/` and `charon/core/validatorapi/`
- [ ] Create shared tracking document (GitHub project or similar)
- [ ] Set up CI pipeline for Rust workspace
- [ ] Establish code review rotation

**Ready to start Phase 1 on Week 1!**
