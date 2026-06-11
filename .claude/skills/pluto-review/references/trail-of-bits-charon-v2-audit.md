# Trail of Bits Charon V2 Audit Overlay

Source: [February 20, 2026 Trail of Bits Charon Pedersen DKG audit](https://github.com/ObolNetwork/charon/blob/main/docs/audit/2026%20-%20Charon%20V2%20Audit%20-%20TrailOfBits.pdf)

Use Charon `v1.7.1` as the default Pluto parity baseline. For DKG, sync, reshare, `FetchDefinition`, and peer-indexed broadcast code, this audit is a required security overlay. When `v1.7.1` behavior conflicts with an audited fix, port or review against the fix intent.

The final fix review commit was `eb187246`, released in Charon `v1.9.0`. The audit marks all nine findings resolved there. Pluto still uses Charon `v1.7.1` as the default parity baseline; use the `v1.9.0` fixes only as the security overlay described below.

## Findings

### TOB-CHARON-1: Complete cluster replacement produces invalid shares

- Severity: Medium
- Target: `dkg/pedersen/reshare.go`
- Failure mode: reshare accepted complete replacement of all old nodes. The old remove check only required at least one old node to participate; it did not ensure any original node remained in the post-reshare cluster, and it did not enforce enough old nodes to reconstruct the old secret.
- Impact: protocol could complete and log success while producing validator shares whose public-share entries did not verify the secret shares. Operators could deploy an unusable cluster and miss duties.
- Compliance: reject complete replacement and reject remove operations with fewer than `oldThreshold` old nodes participating. Charon v1.9.0 fix shape: call `validateReshareNodeCounts` to reject `oldNodesCount < oldThreshold`, and keep a separate remove-operation guard that rejects `oldNodesRemaining == 0`.
- Fix review: resolved in Charon PR #4298.

### TOB-CHARON-2: Missing threshold validation in DKG operations

- Severity: Low
- Target: `dkg/pedersen/dkg.go`, `dkg/pedersen/reshare.go`
- Failure mode: `RunDKG` and `RunReshareDKG` passed configured thresholds to Kyber without first checking lower or upper bounds.
- Impact: invalid thresholds could fail late or produce unusable ceremonies. Examples: threshold greater than node count requires more signatures than exist; threshold zero relies on Kyber defaults instead of explicit Charon validation.
- Compliance: before constructing Kyber DKG config, reject threshold values below 1 or above node count. For zero/negative configured values, apply the Charon default via `cluster.Threshold` deliberately before validation. The audit also recommends a BFT threshold greater than half the node count; Charon fix review notes this was not enforced by `validateThreshold`, so do not treat it as an existing Charon hard requirement unless Pluto explicitly chooses stronger validation.
- Fix review: resolved in Charon PR #4268.

### TOB-CHARON-3: Unbounded sync protocol allocation enables denial of service

- Severity: Medium
- Target: `dkg/sync/server.go`
- Failure mode: `readSizedProto` read an attacker-controlled 8-byte little-endian size from the network and allocated `make([]byte, size)` before authentication.
- Impact: unauthenticated peers could request the sync protocol and send a huge or invalid size, causing out-of-memory panic or process termination before `validReq()` signature checks.
- Compliance: reject nonpositive and oversized message sizes before allocating. Charon fix shape: add a `maxMessageSize` cap of 32 MB in `readSizedProto`, return an error before allocation, and keep authentication/resource-limit hardening as defense in depth.
- Fix review: resolved in Charon PR #4280.

### TOB-CHARON-4: Node signature broadcast trusts claimed peer index

- Severity: Informational
- Target: `dkg/nodesigs.go`
- Failure mode: `broadcastCallback` ignored the actual sender `peer.ID` and trusted the untrusted `PeerIndex` field in `MsgNodeSig`.
- Impact: reliable broadcast deduplication made the issue not directly exploitable beyond a peer withholding its own slot, but the callback still accepted mismatched identity claims. The `noneData` path also skipped signature verification, making identity binding important.
- Compliance: verify the sender identity matches the claimed peer index before processing. Charon fix shape: reject if `n.peers[msgPeerIdx].ID != senderID`; longer-term hardening is signature-slot immutability once a valid slot is set.
- Fix review: resolved in Charon PR #4281 and PR #4330.

### TOB-CHARON-5: Share index remapping corrupts `PublicShares`

- Severity: Medium
- Target: `dkg/pedersen/dkg.go`
- Failure mode: `processKey` converted `oldShareIndices` into `PublicShares` using compact loop positions (`i + 1`) instead of actual share indices (`oi`).
- Impact: noncontiguous participant sets, especially reshare with offline nodes, stored public keys under wrong indices. Later signature verification looked up `PublicShares[s.ShareIdx]` and verified against the wrong key, failing with unclear errors.
- Compliance: preserve actual share indices. Required code shape: `publicShares[oi] = pk`, not `publicShares[i+1] = pk`. Add validation that `PublicShares` contains every expected share index before signature operations when practical.
- Fix review: resolved in Charon PR #4261.

### TOB-CHARON-6: DKG nonce reuse enables replay across iterations

- Severity: Medium
- Target: `dkg/pedersen/dkg.go`
- Failure mode: `RunDKG` generated one nonce before the per-validator loop and reused it for each DKG iteration when `numVals > 1`.
- Impact: Kyber uses the nonce to derive session identity. Reusing it lets a malicious participant replay messages from iteration `N` into `N+1`, causing honest peers to be flagged as equivocating and failing the ceremony.
- Compliance: generate a distinct nonce for every validator iteration in both initial DKG and reshare DKG. Charon fix shape: move nonce generation inside the per-validator loop and include the iteration index in `generateNonce`. The audit also recommended `SessionID` validation in deal, response, and justification handlers, but Charon v1.9.0/fix review did not make that a resolved hard requirement; treat it as optional defense in depth unless Pluto explicitly chooses stronger validation.
- Fix review: resolved in Charon PR #4282.

### TOB-CHARON-7: `restoreCommits` panics on out-of-bounds `shareNum`

- Severity: Medium
- Target: `dkg/pedersen/reshare.go`
- Failure mode: `restoreCommits` indexed `pks[shareNum]` for every node without checking whether each provided enough public key shares.
- Impact: a malicious old node could broadcast too few shares during add-node reshare. New nodes would panic with an index-out-of-range error while restoring commits, preventing them from joining.
- Compliance: validate `shareNum < len(pks)` for every node before indexing and return a structured error naming the malformed share set. Prefer boundary validation in `makeNodes`: old nodes should provide exactly `TotalShares` public key shares before reshare proceeds.
- Fix review: resolved in Charon PR #4301.

### TOB-CHARON-8: New nodes do not validate reshare polynomial commitments

- Severity: Medium
- Target: `dkg/pedersen/reshare.go`
- Failure mode: new nodes reconstructed public polynomial commitments from old-node public shares via Lagrange interpolation, but did not verify that recovered `commits[0]` matched the expected validator public key from the cluster lock.
- Impact: a malicious old node could broadcast an invalid G1 point, causing new nodes to reconstruct the wrong group public key and reject honest old-node deals as invalid.
- Compliance: pass the expected validator public key into commit restoration for new-node reshare paths, marshal/compare recovered `commits[0]` against it, and error on mismatch. Existing-node paths already performed equivalent validation through `restoreDistKeyShare`; new-node paths must match that standard.
- Fix review: resolved in Charon PR #4301.

### TOB-CHARON-9: `FetchDefinition` reads unbounded HTTP bodies

- Severity: Low
- Target: `cluster/helpers.go`, `dkg/disk.go`
- Failure mode: `FetchDefinition` used `io.ReadAll(resp.Body)` on remote definition URLs without a size cap.
- Impact: a malicious or compromised definition server could stream a large response and exhaust memory. The 10-second timeout reduced exposure but did not bound allocation on fast connections.
- Compliance: wrap the response body with an explicit limit before reading and reject payloads exceeding the cap. Charon fix shape: `maxDefinitionSize` is 16 MB, use `io.LimitReader(resp.Body, maxDefinitionSize+1)`, then check length after read and return a clear error if the response exceeds the limit.
- Fix review: resolved in Charon PR #4300.

## Review Use

- Treat affected code as non-compliant unless the implementation shows the required behavior or the finding is clearly not applicable.
- Cite exact Rust evidence and Go/audit evidence when raising findings.
- If a finding is not applicable, state why using code-path evidence.
- Do not replace the `v1.7.1` baseline with a later Charon version unless explicitly requested.
