# Pluto DKG Priority Implementation Plan - Team of 3

**Primary Goal:** Implement DKG ceremony ASAP
**Secondary Goal:** Validator runtime (deferred)
**Team Size:** 3 developers
**Estimated Timeline:** 8-10 weeks for working DKG

---

## Executive Summary

This plan focuses exclusively on getting DKG (Distributed Key Generation) working first, allowing cluster creation and key ceremony execution. The main validator runtime (`pluto run`) is deferred to a later phase.

**Why DKG First:**
- Self-contained feature with fewer dependencies
- Enables cluster creation workflow immediately
- Critical for new validator onboarding
- Can be tested independently without beacon nodes
- Unblocks ecosystem integration (Obol Launchpad, etc.)

**What Gets Deferred:**
- Main validator runtime (`pluto run`)
- Duty execution (scheduler, fetcher, sigagg, bcast)
- Validator API
- Live validator operations

---

## Revised Team Structure

### Developer A: DKG Orchestration & CLI Lead
**Focus:** DKG state machine, command wiring, cluster creation
**Skills:** State machines, async coordination, CLI development

### Developer B: Cryptography & FROST Protocol Lead
**Focus:** FROST implementation, node signatures, crypto validation
**Skills:** Cryptography, threshold signatures, BLS signatures

### Developer C: P2P & Broadcast Lead
**Focus:** P2P messaging, DKG broadcast protocol, sync coordination
**Skills:** Distributed systems, P2P protocols, consensus

---

## Phase 1: DKG Foundation (Weeks 1-3)
**Goal:** Build independent components needed for DKG

### Developer A: Cluster Definition & Config
- [ ] **Week 1:** Verify cluster definition parsing is complete
  - Audit `crates/cluster/` against Go reference
  - Ensure all DKG-relevant fields are present
  - Test cluster definition validation
  - **Deliverable:** Confirmed cluster module is DKG-ready

- [ ] **Week 1-2:** Implement `create dkg` command
  - Go reference: `charon/cmd/createdkg.go` (~200 LOC)
  - Create DKG definition file
  - Operator enumeration
  - Network configuration
  - Validation logic
  - **Deliverable:** `pluto create dkg` command
  - **Status check:** `crates/cli/src/cmd/create/dkg.rs`

- [ ] **Week 2-3:** Implement `create cluster` command
  - Go reference: `charon/cmd/createcluster.go` (~400 LOC)
  - Generate cluster definition
  - ENR generation for operators
  - Withdrawal/fee recipient configuration
  - **Deliverable:** `pluto create cluster` command
  - **Status check:** `crates/cli/src/cmd/create/cluster.rs`

### Developer B: Cryptographic Foundations
- [ ] **Week 1:** Audit existing crypto utilities
  - Review `crates/crypto/` completeness
  - Verify BLS signature support (threshold signatures)
  - Ensure `k1util` secp256k1 support is sufficient
  - Test vectors for BLS operations
  - **Deliverable:** Crypto audit report + gaps identified

- [ ] **Week 1-2:** Implement keyshare structures
  - Go reference: `charon/tbls/` (threshold BLS)
  - Secret share representation
  - Public key aggregation
  - Share verification
  - **Deliverable:** `crates/crypto/src/keyshare.rs` with tests

- [ ] **Week 2-3:** Start FROST protocol scaffolding
  - Go reference: `charon/dkg/frost/frost.go` (~600 LOC)
  - Define FROST message types (already in protobuf)
  - Round 1 structure (commitments)
  - Round 2 structure (shares)
  - **Deliverable:** FROST types and message handling stubs
  - **Status check:** `crates/dkg/src/frost/`

### Developer C: P2P Communication Infrastructure
- [ ] **Week 1-2:** Implement P2P sender/receiver abstractions
  - Go reference: `charon/p2p/sender.go`, `charon/p2p/receive.go`
  - Generic send/receive over libp2p
  - Protocol ID routing
  - Message serialization (protobuf)
  - Error handling and timeouts
  - **Deliverable:** `crates/p2p/src/sender.rs`, `crates/p2p/src/receiver.rs`
  - **Status check:** Audit existing `crates/p2p/src/` implementation

- [ ] **Week 2-3:** Implement DKG sync protocol
  - Go reference: `charon/dkg/sync/sync.go` (~300 LOC)
  - Uses existing `dkgpb::sync` protobuf
  - Peer discovery for DKG ceremony
  - Sync message exchange (who's ready, what phase)
  - **Deliverable:** `crates/dkg/src/sync/` fully implemented
  - **Status check:** `crates/dkg/src/sync/` exists with stubs

**Phase 1 Milestone:** All DKG prerequisites ready, can create definitions

---

## Phase 2: DKG Broadcast & Node Signatures (Weeks 4-5)
**Goal:** Implement reliable broadcast and signature collection

### Developer A: Obol API Integration
- [ ] **Week 4:** Enhance Obol API client for DKG
  - Go reference: `charon/app/obolapi/` DKG endpoints
  - POST lock file to Obol API
  - GET ceremony status
  - Verify DKG signatures
  - **Deliverable:** DKG-specific API client methods
  - **Status check:** `crates/app/src/obolapi/` exists, may need DKG additions

- [ ] **Week 4-5:** Implement lock file handling
  - Go reference: `charon/cluster/lock.go` (may already be in Rust)
  - Lock file creation from DKG output
  - Lock file validation
  - Lock file signing
  - **Deliverable:** Lock file utilities
  - **Status check:** `crates/cluster/src/lock.rs`

### Developer B: Node Signatures
- [ ] **Week 4-5:** Implement `dkg/nodesigs`
  - Go reference: `charon/dkg/nodesigs/nodesigs.go` (~300 LOC)
  - Collect signatures from all nodes
  - Verify operator signatures
  - Aggregate signatures for lock file
  - Handle signature failures/timeouts
  - **Deliverable:** `crates/dkg/src/nodesigs/` with tests

### Developer C: DKG Broadcast Protocol
- [ ] **Week 4-5:** Implement `dkg/bcast`
  - Go reference: `charon/dkg/bcast/bcast.go` (~500 LOC)
  - Reliable broadcast for DKG messages
  - Ensure all-or-nothing delivery
  - Handle network partitions
  - Broadcast verification
  - **Deliverable:** `crates/dkg/src/bcast/` with tests
  - **Note:** Uses P2P abstractions from Phase 1

**Phase 2 Milestone:** All DKG communication primitives working

---

## Phase 3: FROST Protocol Implementation (Weeks 6-7)
**Goal:** Implement core cryptographic DKG protocol

### Developer B: FROST Protocol (PRIMARY FOCUS)
- [ ] **Week 6-7:** Implement complete FROST protocol
  - Go reference: `charon/dkg/frost/frost.go` (~600 LOC)
  - **Round 1: Commitment Phase**
    - Generate secret coefficients
    - Compute commitments
    - Broadcast commitments to peers
    - Collect and verify peer commitments
  - **Round 2: Share Distribution**
    - Generate shares for each peer
    - Send shares via P2P
    - Receive and verify shares from peers
    - Compute secret share and group public key
  - **Verification:**
    - Verify shares against commitments
    - Detect malicious participants
    - Abort on verification failure
  - **Deliverable:** Complete FROST implementation
  - **Critical:** Port ALL Go tests, generate test vectors from Go
  - **Review:** Requires cryptographic expert review

### Developer A: FROST Integration Support (ASSIST DEV B)
- [ ] **Week 6:** Create FROST test infrastructure
  - Multi-node test harness
  - Simulated network delays
  - Byzantine participant simulation
  - Test vector generation from Go
  - **Deliverable:** `crates/dkg/src/frost/tests/`

- [ ] **Week 7:** FROST integration testing
  - End-to-end FROST ceremony
  - Failure mode testing
  - Network partition scenarios
  - **Deliverable:** Comprehensive FROST test suite

### Developer C: P2P FROST Message Handling (ASSIST DEV B)
- [ ] **Week 6-7:** Wire FROST to P2P layer
  - Protocol handlers for FROST messages
  - Message routing by DKG phase
  - Timeout handling
  - Retry logic
  - **Deliverable:** FROST messages flowing over P2P

**Phase 3 Milestone:** FROST protocol complete and tested

---

## Phase 4: DKG Orchestration (Weeks 8-9)
**Goal:** Wire everything together into DKG state machine

### Developer A: DKG Orchestration (PRIMARY FOCUS)
- [ ] **Week 8-9:** Implement DKG orchestration
  - Go reference: `charon/dkg/dkg.go` (1,321 LOC)
  - **State Machine:**
    - Phase 0: Initialization and sync
    - Phase 1: FROST Round 1 (commitments)
    - Phase 2: FROST Round 2 (shares)
    - Phase 3: Key verification
    - Phase 4: Lock file creation and signing
    - Phase 5: Lock file publication
  - **Coordination:**
    - Wait for all peers to reach each phase
    - Timeout handling per phase
    - Abort on failures
    - Progress tracking
  - **Integration:**
    - Use sync protocol (Dev C, Phase 1)
    - Use broadcast (Dev C, Phase 2)
    - Use FROST (Dev B, Phase 3)
    - Use nodesigs (Dev B, Phase 2)
  - **Deliverable:** `crates/dkg/src/orchestrator.rs`

### Developer B: Lock File Generation
- [ ] **Week 8-9:** Implement lock file output
  - Generate cluster lock from DKG results
  - Include all validator pubkeys
  - Include threshold signature data
  - Sign lock file
  - Validate lock file
  - **Deliverable:** Lock file generation from DKG output

### Developer C: DKG Networking
- [ ] **Week 8-9:** Complete DKG network stack
  - Connection management
  - Peer timeout detection
  - Reconnection logic
  - DKG-specific P2P metrics
  - **Deliverable:** Robust DKG networking

**Phase 4 Milestone:** End-to-end DKG orchestration working

---

## Phase 5: DKG Command & Testing (Week 10)
**Goal:** Working `pluto dkg` command

### Developer A: DKG Command
- [ ] **Week 10:** Implement `dkg` command
  - Go reference: `charon/cmd/dkg.go` (~80 LOC)
  - CLI argument parsing
  - Load DKG definition
  - Initialize P2P
  - Run DKG orchestrator
  - Save lock file
  - Publish to Obol API (if specified)
  - **Deliverable:** `pluto dkg` command fully functional

### Developer B: DKG Testing
- [ ] **Week 10:** End-to-end DKG testing
  - Multi-node DKG ceremony (3, 4, 5 nodes)
  - Network failure scenarios
  - Malicious node simulation
  - Compare output with Go implementation
  - **Deliverable:** Comprehensive DKG test suite

### Developer C: DKG Testing Infrastructure
- [ ] **Week 10:** DKG test harness
  - Docker compose for multi-node testing
  - Automated ceremony execution
  - Output validation
  - Performance benchmarking
  - **Deliverable:** `test-infra/dkg/` test setup

**Phase 5 Milestone:** COMPLETE DKG IMPLEMENTATION

---

## Phase 6: Additional DKG Commands (Week 11)
**Goal:** Complete DKG ecosystem

### Developer A: Combine Command
- [ ] **Week 11:** Implement `combine` command
  - Go reference: `charon/cmd/combine.go` (~150 LOC)
  - Combine keyshares for recovery
  - Validation and safety checks
  - Output validator keystore
  - **Deliverable:** `pluto combine` command

### Developer B: DKG Verification Tools
- [ ] **Week 11:** Implement verification utilities
  - Verify lock file signatures
  - Validate threshold crypto setup
  - Check DKG output correctness
  - **Deliverable:** Lock file verification tools

### Developer C: Documentation & Examples
- [ ] **Week 11:** DKG documentation
  - DKG ceremony guide
  - Troubleshooting guide
  - Example workflows
  - Migration from Charon DKG
  - **Deliverable:** Complete DKG documentation

**Phase 6 Milestone:** Production-ready DKG with all tooling

---

## Dependency Graph (DKG-Focused)

```
Phase 1 (Weeks 1-3) - Parallel:
├─ Dev A: create dkg → create cluster
├─ Dev B: Crypto audit → Keyshares → FROST scaffolding
└─ Dev C: P2P sender/receiver → DKG sync

Phase 2 (Weeks 4-5) - Depends on Phase 1:
├─ Dev A: Obol API → Lock file handling
├─ Dev B: Node signatures (needs P2P from Phase 1)
└─ Dev C: DKG broadcast (needs P2P from Phase 1)

Phase 3 (Weeks 6-7) - Depends on Phase 2:
├─ Dev B: FROST protocol (PRIMARY) ← CRITICAL
├─ Dev A: FROST testing (supports Dev B)
└─ Dev C: FROST P2P integration (supports Dev B)

Phase 4 (Weeks 8-9) - Depends on Phase 3:
├─ Dev A: DKG orchestration (PRIMARY) ← CRITICAL
├─ Dev B: Lock file generation
└─ Dev C: DKG networking

Phase 5 (Week 10) - Depends on Phase 4:
├─ Dev A: dkg command
├─ Dev B: DKG testing
└─ Dev C: Test infrastructure

Phase 6 (Week 11) - Polish:
└─ All: Additional commands, docs, verification
```

---

## Critical Path for DKG

**Weeks 1-3:** Foundations (parallel, no blockers)
**Weeks 4-5:** Communication primitives (needs P2P)
**Weeks 6-7:** FROST protocol ← HIGHEST RISK
**Weeks 8-9:** DKG orchestration ← SECOND CRITICAL
**Week 10:** DKG command & testing
**Week 11:** Finalization

**Total: 11 weeks to working DKG**

---

## What Already Exists in Rust (Verified)

Based on the codebase exploration:

### ✅ Already Implemented (Can Skip):
1. **Cluster module** - Complete
   - `crates/cluster/src/` - definition, lock, manifest, operator
   - May need minor DKG-specific additions
2. **Protobuf definitions** - Complete
   - `crates/dkg/src/dkgpb/` - All FROST, sync, bcast, nodesigs protos
3. **P2P infrastructure** - Mostly complete
   - `crates/p2p/src/` - libp2p setup, peers, config
   - Need sender/receiver abstractions (thin layer)
4. **DKG sync stubs** - Partial
   - `crates/dkg/src/sync/` - Protocol stubs exist
5. **Obol API client** - Exists
   - `crates/app/src/obolapi/` - May need DKG endpoints
6. **Crypto utilities** - Partial
   - `crates/crypto/src/` - Some BLS support
   - Need threshold signature specifics

### ⚠️ Needs Implementation:
1. **FROST protocol** - ~600 LOC (HIGH RISK)
2. **DKG orchestration** - ~1,300 LOC (HIGH RISK)
3. **DKG broadcast** - ~500 LOC
4. **Node signatures** - ~300 LOC
5. **DKG command** - ~80 LOC + ceremony logic
6. **Create commands** - ~600 LOC total
7. **Combine command** - ~150 LOC

**Total new code estimate: ~3,500 LOC**

---

## Risk Assessment & Mitigation

### Critical Risks

#### 1. FROST Protocol Complexity (HIGHEST RISK)
**Impact:** Incorrect implementation breaks entire DKG
**Probability:** High (cryptographic protocols are subtle)

**Mitigation:**
- [ ] Port ALL Go FROST tests exactly
- [ ] Generate test vectors from Go (freeze Go at specific inputs, capture outputs)
- [ ] Use same cryptographic libraries as Go (if possible)
- [ ] Independent cryptographic review before Phase 4
- [ ] Cross-validate: run same inputs through Go and Rust, compare outputs
- [ ] Consider using existing FROST library (e.g., `frost-core` crate) if compatible

#### 2. DKG State Machine Complexity (HIGH RISK)
**Impact:** Ceremony hangs, deadlocks, or produces invalid output
**Probability:** Medium (complex async coordination)

**Mitigation:**
- [ ] Comprehensive state machine tests (all transitions)
- [ ] Timeout on every phase with clear error messages
- [ ] Extensive logging at phase boundaries
- [ ] Simulate network failures in tests
- [ ] Compare state transitions with Go implementation
- [ ] Manual testing with 3+ nodes before declaring done

#### 3. P2P Communication Reliability (MEDIUM RISK)
**Impact:** Messages lost, ceremony fails intermittently
**Probability:** Medium (network failures are common)

**Mitigation:**
- [ ] Implement retry logic with exponential backoff
- [ ] Message acknowledgments
- [ ] Timeout detection per peer
- [ ] Network partition testing
- [ ] Use existing libp2p reliability features

#### 4. Threshold Crypto Library Compatibility (MEDIUM RISK)
**Impact:** Key shares incompatible with Go implementation
**Probability:** Low-Medium (if using different crypto libraries)

**Mitigation:**
- [ ] Use same BLS library as Go (if possible)
- [ ] Test interop: Rust DKG output used by Go validator (if feasible)
- [ ] Verify group public key matches across implementations
- [ ] Test vectors for all crypto operations

---

## Testing Strategy

### Unit Tests (Throughout)
- Every component has unit tests
- Port Go tests where they exist
- Target 80%+ coverage on crypto and orchestration code

### Integration Tests (Phases 3-4)
- Multi-node FROST ceremony (simulated in-process)
- State machine transitions
- Network failure injection

### End-to-End Tests (Phase 5)
- Full DKG ceremony with 3, 4, 5, 7 nodes
- Docker compose multi-node setup
- Byzantine node simulation (one node sends bad data)
- Network partition scenarios

### Interoperability Tests (Phase 5-6)
- **Critical:** Verify Rust DKG output matches Go format exactly
- Lock file compatibility
- Protobuf wire format validation
- Ideally: Rust DKG → Go validator (if validator runtime exists in Go)

### Test Vectors (Throughout)
For every cryptographic operation:
1. Run Go implementation with known inputs
2. Capture outputs (commitments, shares, signatures)
3. Hardcode as Rust test vectors
4. Rust must produce identical outputs

**Example (FROST Round 1):**
```rust
#[test]
fn test_frost_round1_commitment() {
    // Input: secret from Go test
    let secret = hex::decode("...").unwrap();

    // Expected: commitment from Go output
    let expected_commitment = hex::decode("...").unwrap();

    // Actual: Rust implementation
    let commitment = frost::round1_commitment(&secret);

    assert_eq!(commitment, expected_commitment);
}
```

---

## Success Criteria

### Phase 5 Complete (Week 10) - Minimum Viable DKG:
- [ ] `pluto create dkg` generates valid definition file
- [ ] `pluto dkg` completes ceremony with 4 nodes successfully
- [ ] Lock file output matches Go format (validated by inspection)
- [ ] Lock file validates with existing Charon tooling (if applicable)
- [ ] All unit tests passing
- [ ] Integration tests passing (3-7 nodes)
- [ ] No panics or crashes in normal operation

### Phase 6 Complete (Week 11) - Production Ready:
- [ ] DKG ceremony succeeds 10/10 times in test environment
- [ ] Handles network failures gracefully (retries, timeouts)
- [ ] One Byzantine node detected and ceremony aborts correctly
- [ ] Documentation complete
- [ ] Testnet validation (if possible)
- [ ] Performance acceptable (ceremony completes in < 5 minutes for 7 nodes)

---

## Development Workflow

### Daily Standups (15 min)
- Focus: Blockers, dependencies, crypto questions
- Escalate crypto concerns immediately

### Weekly Reviews (Fridays)
- **Week 3:** Review Phase 1 completeness
- **Week 5:** Review Phase 2 completeness
- **Week 7:** **CRITICAL REVIEW** - FROST implementation review (external crypto expert if possible)
- **Week 9:** Review DKG orchestration
- **Week 10:** End-to-end testing review
- **Week 11:** Production readiness review

### Code Review Guidelines
- FROST code: TWO reviewers minimum, one with crypto expertise
- All code: Compare behavior with Go reference (cite file:line)
- Tests: Must include test vector validation for crypto
- PRs: Link to Go reference in description

---

## Week-by-Week Detailed Plan

### Week 1: Foundation Setup
**Dev A:**
- Day 1-2: Audit cluster module, ensure DKG-ready
- Day 3-5: Implement `create dkg` command

**Dev B:**
- Day 1-3: Audit crypto module, identify gaps
- Day 4-5: Start keyshare structures

**Dev C:**
- Day 1-5: Implement P2P sender/receiver abstractions

**Deliverables:** `create dkg`, crypto audit report, P2P abstractions

### Week 2: Create Commands & Crypto
**Dev A:**
- Day 1-5: Implement `create cluster` command

**Dev B:**
- Day 1-3: Complete keyshare structures
- Day 4-5: Start FROST scaffolding

**Dev C:**
- Day 1-5: Implement DKG sync protocol

**Deliverables:** `create cluster`, keyshares, DKG sync

### Week 3: Complete Foundation
**Dev A:**
- Day 1-5: Finalize create commands, start Obol API work

**Dev B:**
- Day 1-5: Complete FROST scaffolding, prepare for full implementation

**Dev C:**
- Day 1-5: Complete DKG sync, start broadcast design

**Milestone:** Phase 1 complete, can create DKG definitions

### Week 4: Communication Primitives
**Dev A:**
- Day 1-5: Obol API DKG integration

**Dev B:**
- Day 1-5: Implement node signatures

**Dev C:**
- Day 1-5: Implement DKG broadcast (most of it)

**Deliverables:** Obol API integration, nodesigs, partial bcast

### Week 5: Complete Communication
**Dev A:**
- Day 1-5: Lock file handling

**Dev B:**
- Day 1-5: Complete node signatures with tests

**Dev C:**
- Day 1-5: Complete DKG broadcast with tests

**Milestone:** Phase 2 complete, all communication primitives ready

### Week 6: FROST Implementation (CRITICAL WEEK)
**All devs focus on FROST:**

**Dev B (Primary):**
- Day 1-2: FROST Round 1 (commitments)
- Day 3-4: FROST Round 2 (shares)
- Day 5: Verification logic

**Dev A (Support):**
- Day 1-5: Create test infrastructure, generate test vectors from Go

**Dev C (Support):**
- Day 1-5: Wire FROST to P2P layer

**Deliverables:** Partial FROST implementation, test vectors

### Week 7: Complete FROST (CRITICAL WEEK)
**Dev B (Primary):**
- Day 1-3: Complete FROST implementation
- Day 4-5: Fix bugs from testing

**Dev A (Support):**
- Day 1-5: Integration testing, bug reporting

**Dev C (Support):**
- Day 1-5: P2P integration testing

**Milestone:** FROST complete and tested - MOST IMPORTANT MILESTONE

### Week 8: DKG Orchestration Part 1
**Dev A (Primary):**
- Day 1-5: DKG state machine (phases 0-2)

**Dev B:**
- Day 1-5: Lock file generation logic

**Dev C:**
- Day 1-5: DKG networking improvements

**Deliverables:** Partial orchestration

### Week 9: DKG Orchestration Part 2
**Dev A (Primary):**
- Day 1-5: Complete DKG state machine (phases 3-5)

**Dev B:**
- Day 1-5: Complete lock file generation, validation

**Dev C:**
- Day 1-5: Connection management, retries

**Milestone:** Phase 4 complete, end-to-end orchestration ready

### Week 10: DKG Command & Testing
**Dev A:**
- Day 1-3: Implement `dkg` command
- Day 4-5: Integration testing

**Dev B:**
- Day 1-5: End-to-end testing, bug fixes

**Dev C:**
- Day 1-5: Test infrastructure, multi-node setup

**Milestone:** WORKING DKG - PRIMARY GOAL ACHIEVED

### Week 11: Finalization
**Dev A:**
- Day 1-3: `combine` command
- Day 4-5: Final testing

**Dev B:**
- Day 1-5: Verification tools, additional testing

**Dev C:**
- Day 1-5: Documentation, examples

**Milestone:** Production-ready DKG with all tooling

---

## Communication & Escalation

### Escalation Triggers
1. **FROST implementation blocked** → Immediate escalation, consider external help
2. **Test vector mismatch with Go** → Stop, investigate before proceeding
3. **Ceremony fails in testing** → Don't merge, debug thoroughly
4. **Timeline slipping beyond Week 7** → Reassess, possibly reduce scope

### External Resources
- Consider engaging cryptography consultant for FROST review (Week 7)
- Obol team consultation for API integration (Week 4)
- Community testing for end-to-end validation (Week 10-11)

---

## After DKG: What's Next?

Once DKG is complete (Week 11), the team can pivot to:

### Option A: Validator Runtime (Original Plan Phases 1-3)
- 12-14 additional weeks
- Enables `pluto run` command
- Full distributed validator operation

### Option B: Exit Commands (Original Plan Phase 5)
- 3-4 weeks
- Validator lifecycle management
- Useful for existing clusters

### Option C: Additional DKG Features
- DKG ceremony monitoring/dashboards
- Advanced validation tools
- DKG ceremony replay/debugging

**Recommendation:** After DKG, implement Exit commands (Option B) as they're useful immediately and relatively quick, then proceed to validator runtime (Option A).

---

## Getting Started Checklist (Week 0)

### All Developers:
- [ ] Read `AGENTS.md` - understand porting workflow
- [ ] Verify Go reference at `~/projects/charon` (tag v1.7.1)
- [ ] Run `cargo test` in `charon-rs/` - verify environment
- [ ] Set up IDE for Go ↔ Rust cross-referencing

### Developer A (DKG Orchestration Lead):
- [ ] Read `charon/dkg/dkg.go` (1,321 LOC) - understand state machine
- [ ] Read `charon/cmd/createdkg.go` and `charon/cmd/createcluster.go`
- [ ] Audit `charon-rs/crates/cluster/` completeness

### Developer B (Crypto Lead):
- [ ] Read `charon/dkg/frost/frost.go` (~600 LOC) - understand FROST
- [ ] Read `charon/tbls/` - threshold BLS implementation
- [ ] Research Rust BLS libraries (compare with Go)
- [ ] Audit `charon-rs/crates/crypto/` completeness

### Developer C (P2P Lead):
- [ ] Read `charon/p2p/sender.go` and `charon/p2p/receive.go`
- [ ] Read `charon/dkg/bcast/` - understand broadcast protocol
- [ ] Read `charon/dkg/sync/` - understand sync protocol
- [ ] Audit `charon-rs/crates/p2p/` completeness

### All: Setup
- [ ] Create GitHub project board for tracking
- [ ] Set up CI for Rust workspace (if not exists)
- [ ] Establish code review rotation
- [ ] Schedule Week 1 kickoff meeting

---

## Summary

**Timeline:** 11 weeks to production-ready DKG
**Critical Weeks:** 6-7 (FROST), 8-9 (Orchestration)
**Highest Risk:** FROST protocol implementation
**Expected Outcome:** `pluto dkg` command that can create validator clusters

**Key Success Factor:** Rigorous testing with test vectors from Go implementation at every step, especially for cryptographic operations.

**Ready to start Week 1!**
