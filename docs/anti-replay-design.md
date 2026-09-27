# Bounded Authenticated-Initiator Replay Defense — Design (2026-08-22, rev 6)

Gateway-side design deliverable of the validated security-audit remediation
plan. Revision 3 superseded revision 2, which revalidation rejected; its
changes (explicit sustained-lockout trade-off acceptance, exact wrap/retry/
ordering contracts, completed downstream matrix, deque RAM accounting) stand.
Changes in revision 4 — three consistency/completeness corrections, nothing
else: (1) the pre-authentication purge carries a written side-effect proof
and the spoof-resistance invariant is narrowed precisely (live-entry
immutability; strictly-expired-prefix reclamation permitted); (2) the resume
ordering contract is completed — session-existence and role checks are placed
exactly, every state observable before the MAC is enumerated including global
cache saturation, and the active-session boundary is documented truthfully
against source; (3) the downstream-failure matrix gains named
malformed-provider-key and null-ECDH-output tests on both paths.
Changes in revision 5 — three precision corrections, nothing else:
(1) the install malformed-provider-key test is re-targeted to the actual
failure site: a gateway-local static key returned `Ok` but malformed by
`get_static_pubkey`, rejected by encoding validation immediately after
retrieval (post-authentication, pre-ECDH); a wire-supplied peer point cannot
reach ECDH on either install role — the same key must first clear
`SecureElement::verify_ecdsa`, whose trait contract mandates rejecting
off-curve/infinity verifying keys — so that case is documented honestly as
defense-in-depth under a defective provider, while resume's stored session
peer key flows unverified straight into ECDH and keeps its own named test at
that exact step; (2) the downstream matrix states explicitly why no
additional named failure test exists after the install admission stamp —
every injectable site in the stamp-to-insert segment is already named, the
fixed-shape helpers are infallible for shipped constants, the pending insert
is structurally impossible, and the stamp itself is unable to fail; (3)
install cache occupancy is disclosed (exactly one slot per accepted
handshake, persisting until horizon expiry or reboot) together with the
pre-authentication saturation-refusal exposure, explicitly accepted and
pinned, and the adversarial suite is renumbered one-function-per-entry
(28 named tests). Design only;
the only public-API additions are two error variants (Section 9).
Changes in revision 6 (2026-09-27) — one addition, nothing else:
a new Section 15 appendix cross-references the USB-serial link tier's
replay discipline in its shipped form; every statement there was verified
against `src/usbserial`, and no existing section, table, or decision record
above is modified.

## 1. Problem statement

Two clear-text handshake initiators reach expensive secure-element work on the
gateway and stay replayable forever: an InstallRequest re-drives two ECDSA
verifications and, on success, static-ECDH + gateway signing + pending
occupancy; a ResumeRequest MAC binds only `sensor_mac ‖ sensor_nonce`, so
after each 15 s per-peer cooldown a recording replays into SE-ECDH again.
Accepted nonces are cached nowhere today; cooldowns cannot bound replays
spread over many identities. The class is availability, not authentication
bypass. The forward-secrecy decision chose formal acceptance with no wire
change, so the defense uses gateway-local state only.

## 2. Constraints

* `no_std`, no heap: fixed-capacity, compile-time-bounded structures only.
* Wire-compatible; only public-API additions are the two new error variants.
* Spoof-resistance: unauthenticated senders must never insert, evict, alter,
  refresh, or otherwise influence any LIVE cache entry, and hold no write
  path into the cache at all. Their only possible cache effect is earlier
  reclamation of strictly expired entries by the shared purge pass — proven
  in Section 4 and reflected in the forged-frame test (Section 13).
* Existing semantics preserved except where explicitly declared: per-peer
  cooldowns (15 s), idempotent pending retransmission, guard-before-SE
  ordering, fail-atomic pending transitions, and the install admission-stamp
  position (post-authentication) are unchanged; the single intentional resume
  precedence adjustment is documented in Section 10.
* Timebase: absolute seconds in `u32`; one `u32` wrap accepted (~2106 unix);
  Section 6 defines exact wrap behavior. Host-budget composition mandatory
  (Section 11); no library-side global rate limiter.

## 3. Threat model and replay definition

Attacker capability: passive recording then scheduled RF replay across many
recorded identities, airtime-bounded; plus attacker-owned devices that pass
attestation or hold valid PSKs, generating unlimited fresh **authenticated**
initiators.

Definition: a **handshake replay** is an incoming initiator frame whose exact
`(handshake_kind, peer_mac, initiator_nonce)` triple was already accepted as
cryptographically authenticated **to successful completion** by the same
handler within the replay horizon; the kind tag keeps Install and Resume
namespaces disjoint. Consequences: only verified-and-completed triples enter
the cache (spoof-proof inserts); legitimate sensors never reuse `(identity,
nonce)` (fresh CSPRNG nonces per `start_*`), so an exact match is an RF
duplicate/retransmission or an attack frame; renew/data stay covered by the
AEAD RX window. Sensor cost: zero bytes.

## 4. Design overview

One crate-private, gateway-gated store beside the existing stores:
`ReplayCache` holding a `heapless::Deque<ReplayCacheEntry, N>` — a true FIFO
ring capped at the manager capacity `N`. Handler rule, symmetric for both
clear-text initiators:

1. Run the existing cheap local guards in their documented order (Section 10
   step tables; includes the one declared resume precedence adjustment).
2. Parse the request body to expose `(claimed_peer, initiator_nonce)`.
3. Prefix-purge strictly-expired entries, then exact-triple lookup over the
   live remainder. Hit ⇒ return `HandshakeReplay { peer }` immediately: zero
   SE/HKDF calls, zero pending mutations. The purge is the ONLY cache effect
   any pre-authentication frame can cause (proof below).
4. Capacity pre-check: if the post-purge cache is still full, refuse the fresh
   initiator with `ReplayCacheFull { peer }` before any cryptographic work
   (fail-closed bounded refusal; Section 5).
5. Authenticate and continue the existing flow (signatures / request-MAC,
   admission stamp where applicable, ECDH, challenge build, pending commit).
6. Insert `(kind, peer, nonce, now)` only as the final step of a successful
   invocation, after pending commit and challenge finalization, immediately
   before returning the Transmit event (Section 7).

Purge placement proof — why step 3 may run before authentication (disposition
chosen over relocating the purge behind authentication): the pass pops from
the ring front while, and only while, the Contract A arithmetic classifies
the front entry as strictly expired (`age >= REPLAY_HORIZON_SECS`); stamps
are written exactly once at success-only insertion and have no refresh path.
An unauthenticated frame therefore cannot extend any entry's lifetime (it
controls nothing that feeds `seen_at`), cannot evict, reorder, or alter any
live entry (a live entry's age is below the horizon, so it never satisfies
the pop predicate), and cannot flip the lookup verdict for any in-horizon
triple. Under the monotonic-stamp contract expired entries form a ring
prefix, so the pass deterministically stops at the first live entry. The sole
attacker-influenceable effect is the TIMING of reclaiming already-dead slots:
availability-positive, security-neutral, identical in kind to the admission
table's documented pre-authentication expired-entry reclamation and to the
optional `tick(now)` purge. Relocation was evaluated and rejected: behind
authentication, expired ghosts would still occupy slots at the pre-auth
capacity check, producing false `ReplayCacheFull` refusals of fresh initiators
(breaking automatic recovery through expiry, Section 5) or forcing a second
expiry-aware counting scan purely to hide them — extra complexity for zero
additional live-state guarantee.

## 5. Saturation policy: the explicit availability trade-off (decision)

The fundamental trade-off, stated first: unbounded-horizon replay protection,
zero false rejection of fresh handshakes, and fixed memory cannot all hold
under adversarial pressure. An attacker owning authenticated identities can
aim fresh valid triples at any finite structure forever, so exactly one of
the three properties must yield. This design deliberately yields
**fresh-handshake availability** — never replay safety:

* TTL expiry beyond the horizon is the ONLY silent removal mechanism; no live
  entry is ever evicted or overwritten.
* A cache full of unexpired entries refuses new initiations with
  `ReplayCacheFull { peer }` before any cryptographic work.

Owner-visible design decision: under sustained authenticated churn exceeding
cache capacity, NEW handshake initiation is temporarily refused
(`ReplayCacheFull`) while ESTABLISHED Data sessions continue unaffected — a
deliberate availability trade-off; the host-side global admission budget is
the primary outer defense and bounds the rate at which the cache can be
filled; recovery is automatic as entries expire (horizon
≤ 3,600 s). Stated plainly: while churn continues, the refusal persists —
it is not self-healing against a persistent attacker, only against stopped
or budget-throttled pressure.

What the attacker achieves, precisely: denial of NEW Install/Resume
handshakes. Established Data traffic, renew rotation, pending recovery,
cached retransmission, and recorded-pair suppression are all unaffected, and
every refused frame consumes zero crypto, bounding the attacker's amplification.
Why this is the least-harm resolution — the alternatives each restore a worse
failure:

* (a) Evict live entries under pressure (v1 design): provably reopens a
  within-horizon replay bypass after churn; trades a bounded availability
  loss for an unbounded security loss. Rejected.
* (b) Unbounded or grown-on-demand storage: violates fixed-memory `no_std`.
  Rejected.
* (c) Larger constant capacity: any finite C falls to C+1 authenticated
  initiators — a bigger constant, not a fix. Rejected.
* (d) Two-tier probation/confirmed structures: the promotion boundary must
  still drop some live entry; the flaw moves one level deeper at higher RAM
  and complexity. Rejected.

Role of the host global admission budget: mandatory composition (Section 11);
it bounds the RATE at which authenticated initiators reach the library, hence
how fast the cache fills, and is the operator's primary lever against
sustained lockout. Honest scope statement: the library alone proves replay
safety and bounded memory; fleet-wide fairness between legitimate and hostile
initiators under sustained churn is a host-policy property and is not claimed
by the library.

Mitigation lever: operators size the cache through the manager generic `N`
(sessions == pending == admission == cache). Total gateway RAM =
`40·N + 12` bytes on the intended 32-bit target:

| N | Entry slots | Total (32-bit) |
|---|---|---|
| 2 | 80 B | 92 B |
| 8 | 320 B | 332 B |
| 32 | 1,280 B | 1,292 B |
| 128 (gateway default) | 5,120 B | 5,132 B ≈ 5.0 KiB |

Proof (adversarial churn included): every successful invocation inserts its
exact triple, and nothing except TTL expiry ever removes entries. A frame
replaying a triple accepted at `t`, delivered at `now ∈ [t, t+H)`, finds its
entry present and unexpired, and the pre-crypto lookup rejects it before any
SE, HKDF, or pending mutation. Churn only adds entries; it cannot remove or
overwrite live ones, so no authenticated flooding resurrects a recorded pair
inside the horizon; beyond capacity it produces exactly the bounded refusals
this section accepts. Outside `[t, t+H)` the once-per-horizon residual
applies by design.

## 6. Contract A — wrap-aware expiry comparison (formula and proof)

Clock contract: monotonic non-decreasing `u32` seconds counter; the only
permitted decrease is the single wrap at `u32::MAX`; horizon far below half
range; AND elapsed time between two consecutive cache observations stays
below half the counter range (< 2³¹ s ≈ 68 years). The per-request purge plus
an ordinary `tick(now)` cadence satisfy this trivially.

```rust
const REPLAY_HORIZON_SECS: u32 = 3_600; // owner-tunable

/// True when `seen_at` is at least `REPLAY_HORIZON_SECS` old at `now`.
fn expired(seen_at: u32, now: u32) -> bool {
    if now >= seen_at {
        now - seen_at >= REPLAY_HORIZON_SECS // same wrap epoch
    } else {
        // One wrap between stamp and observation: tail + head, u64-safe.
        (u32::MAX - seen_at) as u64 + 1 + now as u64 >= REPLAY_HORIZON_SECS as u64
    }
}
```

Proof: define age `= (now − seen_at) mod 2³²`. With at most one wrap between
stamp and observation — implied by the half-range contract — age equals the
true elapsed seconds in both branches: plain subtraction when no wrap
occurred, the cross-wrap tail-plus-head sum when it did. An entry is expired
exactly when its true age is ≥ H. Boundary behavior: a stamp
`seen_at = u32::MAX − k` stays fresh across the wrap and expires at the first
post-wrap `now` with `(k + 1) + now ≥ H`; freshness and expiry are continuous
and exact to the tick. If the half-range contract is broken (no observation
for nearly a full period), an ancient entry aliases to "same epoch, small
age" and its triple keeps being SUPPRESSED although stale: fail-closed false
freshness — a denial of that stale recording, never a replay acceptance.
The removed v1 formulation computed age 0 forever after wrap (fail-open) and
is gone.

Purge: stamps are non-decreasing under the contract, so expired entries form
a ring prefix; pop front while expired — one pass per invocation, mirroring
the admission store purge (which shares the same property: unauthenticated
callers can trigger only expired-entry reclamation); hooking it into
`tick(now)` stays optional but is recommended to uphold the observation-gap
clause. This pass is the single pre-authentication mutation channel on the
cache; Section 4 proves it touches strictly-expired entries only.
Lookup: linear scan comparing `(kind, peer, nonce)` — negligible next to one
ECDSA verify. Insert: `push_back` exactly once, only at successful completion
(Section 7).

## 7. Contract B — retry atomicity: insertion strictly post-commit

The cache insert is the FINAL mutation of a successful invocation and runs
only after all of: authentication complete, ECDH and key material derived,
challenge fully built into the caller's output buffer, and the pending entry
committed by its fail-atomic insert — immediately before the Transmit return.
Every error return therefore leaves the cache byte-identical: a failed
handshake writes no triple, so no legitimate retry is ever denied
`HandshakeReplay` by its own earlier failure. Remove-on-failure staging stays
rejected: rollback would have to hook every fallible post-authentication site
enumerated in Section 13, and each missed site permanently false-rejects an
identity for a whole horizon; completion-time insertion has no rollback
machinery to miss and is atomic by construction.

Retry truth differs by path because the existing cooldown stamps differ; both
are preserved exactly:

* RESUME: the cooldown stamp (`mark_resume_request`) executes only after the
  pending insert succeeds. A downstream failure leaves neither cache entry
  nor fresh cooldown, so an identical immediate retry walks the normal path
  and succeeds.
* INSTALL: the admission cooldown is stamped after signature verification but
  before RNG/ECDH/signing/build/pending work (existing position, unchanged).
  A downstream failure leaves that 15 s cooldown live: an identical immediate
  retry returns `RateLimited` — NOT `HandshakeReplay`; tests assert the cache
  stayed unchanged — and the identical retry succeeds at the cooldown
  boundary.

A success inserts exactly once; later duplicate deliveries meet either the
running cooldown (`RateLimited`, the cached-retransmission recovery window)
or, once it lapses, `HandshakeReplay` — hosts abandon the stale attempt and
restart with a fresh nonce. On both paths the insert strictly follows the
pending/TX commit.

## 8. Data structures and RAM budget

```rust
pub(crate) struct ReplayCacheEntry {
    pub(crate) peer: PeerId,        // [u8; 17], authenticated remote MAC
    pub(crate) nonce: [u8; 16],     // initiator nonce from the request
    pub(crate) kind: HandshakeKind, // Install | Resume (1 byte)
    pub(crate) seen_at: u32,        // acceptance time, absolute seconds
} // size_of == 40 bytes (38 payload, align 4)
```

The store is `struct ReplayCache<const N: usize>` wrapping one
`heapless::Deque<ReplayCacheEntry, N>` — a true O(1) FIFO ring
(`push_back` / `pop_front`, no element shifting). Bookkeeping correction:
heapless 0.8 `Deque` stores two `usize` ring indices and one `bool` beside
the entry array — a control block of 12 bytes on the intended 32-bit gateway
(after padding) and 24 bytes on 64-bit hosts, not ≤ 8 as previously stated.
True totals:

| Component | N = 2 | N = 128 (default) |
|---|---|---|
| Entry slots (40 B each) | 80 B | 5,120 B |
| Deque control block | 12 B | 12 B |
| Total, 32-bit target | 92 B | 5,132 B ≈ 5.01 KiB |
| Total, 64-bit host build | 104 B | 5,144 B |

Per-entry cost: a fixed 40 B slot; the control block amortizes to `12/N`
(< 0.1 B per entry at the default). Gateway feature only; the sensor pays
zero bytes. Planning numbers — measure on the final image per the footprint
procedure. Raw values beat hashed digests: digests halve RAM but risk
false-positive rejection of legitimate handshakes.

## 9. Error reporting

Two new variants land on the plain public enum (breaking exhaustive matches;
major-version discipline applies), both secret-free in `Display`:

* `HandshakeReplay { peer }` — the exact `(kind, peer, initiator_nonce)`
  triple re-delivered within the horizon; distinct from the AEAD data-path
  `Replay`. Host policy: reject/drop the frame — never retry it, never cancel
  pending.
* `ReplayCacheFull { peer }` — cache saturated with live entries; a fresh
  initiator was refused fail-closed before any crypto. This is the accepted
  trade-off of Section 5: recovery flows through expiry once filling pressure
  stops or the host budget throttles it, and persists while churn continues.
  Host policy: back off, enforce the global budget, optionally raise `N`;
  family of the table-full variants.

## 10. Path ordering (exact step tables)

Intentional outcomes: replay-hit and saturation-refusal sit between the cheap
guards and the first cryptographic operation; every other step keeps its
current-source order. Install first (current source order, no delta):

| # | Step | Cache effect |
|---|---|---|
| 1 | Lifetime validate; parse; outer-header ↔ body identity match; pubkey encoding checks | none |
| 2 | Same-peer pending guard (`PendingAlreadyExists` unless replacing stale commit-sent) | none |
| 3 | Session-table-full guard (full table + unknown peer) | none |
| 4 | Pending-table-full guard (slot available) | none |
| 5 | `admit_install`: cooldown `RateLimited` first, then post-purge `AdmissionTableFull` | none |
| 6 | Prefix purge (strictly-expired entries only — Section 4 proof) + exact lookup (Install); hit ⇒ `HandshakeReplay` | pops expired prefix only |
| 7 | Capacity pre-check; full ⇒ `ReplayCacheFull`, zero crypto | none |
| 8 | Factory-cert ECDSA verify (pre-authentication SE work, unchanged) | none |
| 9 | Device signature verify (unchanged) | none |
| 10 | `stamp_install_request` — position unchanged (post-authentication, pre-ECDH) | none |
| 11 | Provider retrievals — the `get_static_pubkey` result is encoding-validated immediately, so a malformed gateway-local key fails HERE (post-stamp, pre-ECDH; Section 13) — then factory cert/metadata; RNG nonce, static ECDH through the constant-time null gate, HKDF-class derivations, challenge sign/build; any failure ⇒ error, cache untouched | none |
| 12 | Pending insert (fail-atomic; stale-commit replacement remove precedes) | none |
| 13 | Cache insert — success-only, final step before Transmit | push_back |

Install cache occupancy and exposure, precisely. Occupancy: one accepted
install handshake holds EXACTLY ONE slot — the `(Install, sensor_mac,
sensor_nonce)` triple inserted once at row 13. Stamps never refresh:
duplicate deliveries inside the cooldown return `RateLimited` without
touching the cache, so retransmissions carry no occupancy cost; a later
re-pairing with a fresh nonce inserts one additional entry. Persistence:
the slot lives until its age reaches the horizon (`REPLAY_HORIZON_SECS`,
default 3,600 s) or reboot clears RAM, whichever comes first — steady-state
cost is at most one slot per distinct pairing attempt per horizon, the
number operators size `N` against (Section 11). Exposure: because rows 6–7
run BEFORE signature authentication (rows 8–9), a syntactically valid forged
InstallRequest that clears rows 1–5 can distinguish global cache saturation
via `ReplayCacheFull` with zero crypto — an occupancy oracle analogous to
the Resume disclosure below. Explicitly accepted: it exposes a single binary
global state, leaks no secret, mutates no state, is amplitude-bounded by RF
bitrate, and established sessions bypass the cache entirely; pinned by the
install precedence assertions in the guard-ordering tests (Section 13).

Resume. Current source order verifies the request MAC FIRST: the session
lookup, local-role validation, PSK retrieval, and MAC computation run inside
one borrow block (`resume/gateway.rs` — `sessions.get` ⇒ `UnknownSession`;
stored role not gateway-side ⇒ `WrongRole`; then `resume_request_mac` over
the durable PSK), followed by the same-peer pending guard and finally the
cooldown, which performs its own session lookup to read the stored request
stamp. Revision 3 declared exactly one intentional delta, marked †: those two
guards advance ahead of the MAC verify. Revision 4 completes the contract:
the session-existence and role rows are placed exactly — they precede the MAC
verify in today's source ALREADY, because the PSK needed to compute the MAC
lives in the session record — their combined precedence with the moved guards
is pinned end-to-end, and every state distinguishable before the MAC is
enumerated below.

| # | Step | Cache effect |
|---|---|---|
| 1 | Lifetime validate; direction/parse checks | none |
| 2 | Session existence (`UnknownSession`) + local-role validation (`WrongRole`: stored role must be gateway-side here; the symmetric `SessionRole::Sensor` requirement sits on the initiating sensor's `start_resume`). Pre-MAC in current source; position unchanged by this design | none |
| 3 † | Same-peer pending guard (unchanged check, advanced position) | none |
| 4 † | Per-peer resume cooldown, 15 s (`RateLimited`) (advanced position; reads the same session record) | none |
| 5 | Prefix purge (strictly-expired only — Section 4 proof) + exact lookup (Resume); hit ⇒ `HandshakeReplay` | pops expired prefix only |
| 6 | Capacity pre-check; full ⇒ `ReplayCacheFull`, zero crypto — BEFORE the MAC verify (saturation note below) | none |
| 7 | Request-MAC verification over durable PSK — before SE-ECDH (mandatory, preserved) | none |
| 8 | Static↔static ECDH — the STORED session-record peer key enters `SecureElement::ecdh` directly (no ECDSA gate exists for stored keys on this path, so a malformed stored peer point surfaces exactly here; Section 13), wrapped in the constant-time null-output gate; RNG nonce, HKDF-class derivations, challenge-MAC/body build, output buffer; any failure ⇒ cache untouched | none |
| 9 | Pending insert (fail-atomic) | none |
| 10 | `mark_resume_request` cooldown stamp (existing position: after insert) | none |
| 11 | Cache insert — success-only, final step before Transmit | push_back |

Combined cheap-guard precedence, pinned exactly: lifetime/parse errors, then
`UnknownSession`, then `WrongRole`, then `PendingAlreadyExists` (†), then
`RateLimited` (†), then `HandshakeReplay`, then `ReplayCacheFull`, then bad-MAC
`VerificationFailed`. The install chain is pinned identically end-to-end:
lifetime/parse errors, then `PendingAlreadyExists`, then `SessionTableFull`,
then `PendingTableFull`, then `RateLimited`, then `AdmissionTableFull`, then
`HandshakeReplay`, then `ReplayCacheFull` — asserted to fire BEFORE signature
authentication — then the certificate/signature verification failures.
Active-session boundary stated truthfully against
source: the request handler contains NO active-key rejection step today and
none is added; `SessionAlreadyActive` arises solely from the host-facing
`clear_expired_key` API when a live, non-expired key is presented for
clearing during pre-flight cleanup, and `start_resume` tolerates an active or
soft-expired key while the handshake pends. Established-session peers are
therefore structurally unaffected by saturation: their Data traffic follows
the AEAD path where this cache does not exist, and no in-handler step denies
them because their key is still live.

Saturation exposure for resume, precisely: because the capacity pre-check
sits at step 6, BEFORE the MAC verify, a legitimate fresh Resume delivered
into a saturated cache receives `ReplayCacheFull` without its request MAC
being computed, compared, or verified — zero SE calls, zero HKDF calls, no
pending mutation. That refusal exposes GLOBAL cache-saturation state to any
sender whose frame clears steps 1–5 (enrolled peer, right role, nothing
pending, outside cooldown); senders stopped at steps 1–2 (unknown peer, wrong
role) never observe saturation. Everything else is unchanged under
saturation: established Data sessions bypass the cache entirely, and
recorded-pair suppression keeps working.

Contract C — precise reason for the resume lookup position: it sits BETWEEN
the cooldown check and the request-MAC verification because (i) it must
follow both cheap guards so in-cooldown duplicates keep returning
`RateLimited` (never `HandshakeReplay` inside the cached-retransmission
recovery window) and peers stuck in pending keep their specific guard error;
and (ii) it must precede the MAC verify so a hit performs zero cryptography —
the PSK-keyed request MAC is real software crypto, so avoiding SE-ECDH alone
would not make hits free. Request-MAC-before-ECDH is preserved.

Documented consequences of the intentional delta (vs today's MAC-first
source): frames failing BOTH the MAC and a moved guard now return the guard
error instead of `VerificationFailed`; and an unauthenticated sender without
PSK knowledge can distinguish more than the two bits revision 3 named — per
peer, pending-occupied and in-cooldown states (the original two), plus,
introduced by this design, a cache-hit verdict for a triple it replays
(`HandshakeReplay`) and GLOBAL cache saturation (`ReplayCacheFull`);
session-existence and role verdicts were already observable before the MAC in
today's source and are unchanged by the delta. All are binary metadata
states: no key material, no oracle into the MAC, no cache mutation (inserts
stay success-only), amplitude bounded by RF bitrate. Pinned by named tests
(Section 13); the sensor side is out of scope for this cache.

## 11. Interaction with existing guards and the host budget

Filter chain in order: (1) host global budget + allowlist (firmware-side),
(2) cheap guards per Section 10, (3) purge + lookup, (4) capacity pre-check,
(5) authentication onward, (6) success-only insert. Enforced relationship:
up to N distinct authenticated completions are tolerated per horizon window;
the (N+1)-th concurrent live triple is refused, never evicted. Sizing rule:
pick N above expected distinct pairing/resume starts per hour plus headroom
(RAM table in Section 5). Established sessions and reserved pending capacity
are unaffected; unauthenticated traffic fills none of these structures;
in-cooldown duplicates still return `RateLimited`; recovery flows through
cached retransmission; no rejection mutates pending state.

## 12. Reboot behavior and residual risks

RAM-only cache; it starts cold after reboot — a pre-reboot recording replayed
in the first minutes is not library-suppressed until cooldown and
repopulation take effect. Residuals:

* Post-reboot first-window replay remains possible; amplitude bounded by the
  host global budget; a durable freshness token needs a wire change — out of
  scope by the forward-secrecy decision.
* Sustained authenticated churn above capacity denies NEW handshakes with
  `ReplayCacheFull` for exactly as long as the churn sustains occupancy —
  potentially indefinitely under a dedicated attacker. This is the accepted,
  owner-visible trade-off of Section 5, not a transient glitch; host
  mitigations are the global admission budget, allowlist hygiene, and a
  larger `N`. Established Data sessions and recorded-pair suppression never
  degrade.
* Recordings older than the horizon pass once before re-suppression (once
  per horizon per recording, by design).
* Breaking the clock contract: large backward clock steps mass-expire entries
  and briefly reopen the stale residual; observation gaps approaching a full
  counter period alias ancient entries to fresh (fail-closed suppression).
  Both are documented host obligations (Section 6).

## 13. Test plan for the implementation task

Beside the owning module per crate test architecture. Downstream-failure
matrix first — every injectable fallible site after authentication, one test
per reachable class, each asserting the error propagates, the cache is
byte-identical (NO insertion), and the identical retry eventually succeeds
(install: at the cooldown boundary; resume: immediately); demonstrably
equivalent sites share one test. The suite counts exactly 28 named tests,
one function per numbered entry: thirteen downstream-failure retries
(items 1–13) and fifteen core adversarial tests (items 14–28):

1. `install_downstream_ecdh_failure_retry_not_replay` — ECDH error injected
   after the admission stamp; retry at the boundary succeeds.
2. `install_downstream_rng_failure_retry_not_replay` — `fill_bytes` error.
3. `install_downstream_provider_failure_retry_not_replay` — grouped retrieval
   sites (`get_static_pubkey` / `get_factory_cert` / metadata).
4. `install_downstream_signing_failure_retry_not_replay` — `sign_ecdsa`
   error.
5. `install_downstream_output_buffer_failure_retry_not_replay` — undersized
   MSG generic ⇒ `OutputBufferTooSmall`.
6. `resume_downstream_ecdh_failure_retry_not_replay` — SE-ECDH fails after
   the MAC verifies; immediate identical retry succeeds (no stamp written).
7. `resume_downstream_rng_failure_retry_not_replay` — mirror.
8. `resume_downstream_pending_insert_failure_retry_not_replay` — pending
   table filled by OTHER peers ⇒ `PendingTableFull`; also asserts no cooldown
   stamp; freeing a slot makes the immediate retry succeed.
9. `resume_downstream_output_buffer_failure_retry_not_replay` — MSG too
   small; immediate retry.
10. `install_downstream_malformed_local_pubkey_rejected_retry_not_replay` —
    after authentication the provider returns `Ok` from `get_static_pubkey`
    with a malformed (non-`0x02`/`0x03`) gateway-local key; the encoding
    validation that runs immediately after retrieval rejects it — post-stamp,
    pre-ECDH, exactly at row 11 of the install table. Error propagates, cache
    byte-identical, cooldown live ⇒ retry at the boundary succeeds. The
    sensor start path validates its own local key symmetrically at request
    build time (outside this cached handler window). Reachability note: a
    wire-supplied PEER point can never reach ECDH on either install role —
    the same key must first clear `verify_ecdsa`, whose trait contract
    mandates rejecting off-curve/infinity verifying keys before signature
    verification — so peer-point-at-ECDH is classified honestly as
    defense-in-depth under an intentionally contract-violating provider mock;
    it remains a documented subcase of this class, not a separate function.
11. `resume_downstream_invalid_peer_point_rejected_retry_not_replay` — same
    defect class, different trait surface, documented exactly: the peer
    static key comes from the durable session record and resume performs no
    ECDSA on stored keys, so it flows straight into `SecureElement::ecdh`
    (row 8 of the resume table), where the provider rejects the
    corrupt/off-curve stored point; immediate identical retry succeeds.
12. `install_downstream_null_ecdh_output_rejected_retry_not_replay` —
    provider returns `Ok([0u8; 32])`; the constant-time null-output gate
    wrapping every ECDH call site rejects it (`EcdhFailed`); cache untouched;
    retry at the cooldown boundary succeeds.
13. `resume_downstream_null_ecdh_output_rejected_retry_not_replay` — mirror.

The malformed-key classes differ by path and are documented as such: install
surfaces its reachable variant through `get_static_pubkey` plus immediate
encoding validation of the LOCAL key (item 10), resume through
`SecureElement::ecdh` on STORED key material (item 11; the sensor side of
resume mirrors it with its stored copy of the gateway key); the null-ECDH
gate wraps every ECDH call site on both paths (items 12–13). All are
reachable through the injectable provider boundary and none carries an
unreachability statement; they are named tests like every other reachable
class.

Structurally unreachable at the cached step — stated, not invented:

* Install pending-insert failure: the pre-authentication slot-available guard
  plus single-threaded execution make failure impossible at that site (the
  only intervening mutation frees a slot).
* Session-table-full on both paths: unreachable inside the request handlers —
  install pre-checks table fullness before SE work, resume inserts no session
  at this step. `SessionTableFull` occurs at CONFIRM-time commit, after the
  legitimate cache insert; recovery retries the Confirm step, and a genuinely
  replayed Request stays correctly suppressed.
* HKDF-class failures (info builders, directional keys, resume-PSK and
  challenge-MAC derivations, body/frame builders): fixed-shape helpers whose
  only failure input is length; the largest OKM (72 B) sits far below the
  SHA-256 expand ceiling (~8 KB), so no failure value exists for the shipped
  constants. One grouped infallible class, no test.
* AEAD encrypt failure on challenge build: no AEAD participates in either
  challenge — InstallChallenge is ECDSA-signed clear text, ResumeChallenge
  carries a keyed MAC over clear fields; AEAD belongs to Data/Renew/Confirm
  frames outside this cache's scope.
* `stamp_install_request` and the whole stamp-to-insert segment: no additional
  named failure test is required after the install admission stamp because the
  segment is fully partitioned. What runs between the stamp (row 10) and the
  cache insert (row 13) is exactly: provider retrievals (`get_static_pubkey`
  plus its immediate encoding validation — item 10; `get_factory_cert`;
  `get_factory_cert_metadata` — item 3), RNG nonce fill (item 2), wrapped
  static ECDH through the constant-time null gate (items 1, 10, 12), HKDF-class
  fixed-shape derivations and challenge sign-message/frame builders (infallible
  class above), staged-state construction (pure moves, no fallible operation),
  and the fail-atomic pending insert (unreachable, first bullet). The stamp
  itself cannot fail at this site: this handler's single-scan `admit_install`
  decide phase already purged expired cooldown entries and reserved this
  peer's slot in the same invocation, execution holds exclusive `&mut`
  stores with no concurrent mutation possible in this single-threaded crate,
  and no intervening admission-store mutation exists between decide and
  stamp — the intervening code performs verification crypto only. The stamp's
  error return is a fail-closed backstop for future callers, not an injectable
  handler-site class; no test is invented for it.

Core adversarial suite (zero added SE/HKDF calls asserted wherever promised):

14. `install_same_peer_replay_rejected_before_se` — replay ⇒
    `HandshakeReplay`, SE count unchanged.
15. `resume_same_peer_replay_rejected_before_mac_and_se` — hit precedes PSK-MAC
    computation; zero crypto units.
16. `install_multi_peer_replay_bounded` — many install identities rejected on
    second delivery; sessions unaffected.
17. `resume_multi_peer_replay_bounded` — mirror for resume identities.
18. `handshake_kinds_are_disjoint_cache_keys` — install acceptance never
    suppresses resume delivery, and vice versa.
19. `churn_beyond_capacity_never_resurrects_recorded_pairs` — exactly the
    first N fresh initiators authenticate, complete, and enter the cache; the
    (N+1)-th is refused `ReplayCacheFull` BEFORE authentication (zero crypto
    asserted); then EVERY earlier recording replays in-horizon ⇒
    `HandshakeReplay`; no eviction is ever observed.
20. `saturation_fail_closed_then_expiry_recovers` — full live cache refuses
    fresh pairs with zero crypto; once pressure stops, expiry restores
    capacity and handshakes (Section 5 semantics, not time-healing-under-load).
21. `forged_frames_cannot_insert_evict_or_influence` — forged victim frames
    leave every LIVE entry byte-identical: no insert, no eviction, no stamp
    refresh, no reorder; the only permitted effect is reclamation of entries
    already strictly beyond the horizon by the shared pre-auth purge
    (Section 4 proof), asserted bounded to the expired prefix; the victim
    handshake succeeds.
22. `wrap_boundary_exact_expiry` — stamps near `u32::MAX` crossed tick-by-tick
    around the computed instant; plus the long-idle aliasing case pinned
    fail-closed (stale recording suppressed, never accepted).
23. `resume_guard_error_precedence_pinned` — pins the full cheap-guard chain:
    unknown peer ⇒ `UnknownSession`; wrong role ⇒ `WrongRole`; bad-MAC frame
    during victim cooldown ⇒ `RateLimited` (not `VerificationFailed`); while
    pending occupied ⇒ `PendingAlreadyExists`; saturated cache with clean
    guards ⇒ `ReplayCacheFull` before any MAC work; guards clear ⇒
    `VerificationFailed`.
24. `error_precedence_cooldown_pending_before_cache` — in-cooldown duplicate
    returns `RateLimited` on BOTH paths; rejections leave pending untouched;
    the install chain additionally asserts `ReplayCacheFull` fires before
    signature authentication when the cheap guards are clean and the cache
    is saturated (the accepted occupancy-oracle disclosure, Section 10).
25. `cached_retransmission_preserved` — lost-challenge recovery works while
    the triple is cached.
26. `stale_replay_beyond_horizon_passes_once` — documents the residual.
27. `reboot_cold_cache_residual` — fresh manager accepts a pre-reboot
    recording once, suppresses afterwards.
28. `wire_constants_sensor_layout_and_size_bounds_regression` — protocol
    version and frame constants unchanged; the cache is absent from the
    sensor-only manager layout; `size_of::<ReplayCacheEntry>() == 40` and the
    per-N totals stay within the approved target bounds (extends
    `type_size_bounds`).

## 14. Resolved decisions and remaining open items

Resolved by revision 3: the sustained-churn failure mode is an explicit,
owner-visible availability trade-off (Section 5) with the host budget as
outer defense and capacity `N` as the operator lever; wrap expiry is the
exact cross-wrap comparison under a half-range observation contract
(Contract A); insertion is strictly post-commit with per-path retry truth
(Contract B); resume lookup sits between cooldown and MAC verify with the
delta documented and pinned (Contract C); the downstream-failure matrix names
one test per reachable class and states the unreachable ones; the RAM budget
includes the deque control block. Resolved by revision 4: the
pre-authentication purge keeps its position behind a written side-effect
proof (live-entry immutability; strictly-expired-prefix reclamation only;
relocation rejected for breaking automatic expiry recovery at the capacity
check); the resume ordering contract places session existence and role
validation exactly, pins the combined guard precedence, documents the true
active-session boundary (`clear_expired_key` host API, none in-handler),
specifies saturation exposure precisely (`ReplayCacheFull` before MAC
verification, zero crypto; earlier-stopped senders never see it; established
sessions unaffected), and corrects the observable-state enumeration beyond
the former two bits; the downstream matrix adds named malformed-provider-key
and null-ECDH-output retry tests on both paths. Resolved by revision 5: the
install malformed-provider-key test targets the actual reachable failure
site (local-key encoding validation immediately after retrieval;
peer-point-at-ECDH classified defense-in-depth behind the `verify_ecdsa`
trait contract; resume keeps its distinct at-ECDH stored-peer-key test); the
stamp-to-insert segment carries an explicit no-additional-test rationale
partitioning it into named injectable sites, fixed-shape infallible helpers,
the structurally-impossible pending insert, and the unable-to-fail admission
stamp; and install cache occupancy (exactly one slot per accepted handshake,
horizon-bounded persistence) plus its pre-authentication saturation-exposure
oracle are disclosed, explicitly accepted, and pinned in precedence tests,
with the suite renumbered to 28 one-function-per-entry named tests.
Open, non-blocking: optional
`tick(now)` early reclamation; host telemetry should alert on both new
variants and on sustained `ReplayCacheFull` rates.

## 15. Appendix — replay discipline of the usbserial link tier (cross-reference)

The cache of Sections 1–14 defends the LoRa clear-text Install/Resume
initiators. The opt-in `usbserial` tier — the PSK-secured
ChaCha20-Poly1305 channel between the gateway host and the SAMD21 radio
head — is a separate trust boundary with its own, independent replay
defense: no shared state, no shared key material, no shared horizon, and
neither mechanism bounds or excuses the other. This appendix documents that
defense so this document remains the single replay reference.

Attack class closed: HELLO (type `0x06`) travels clear by design, and a
recorded HELLO replayed into an ESTABLISHED channel once re-derived the
active keys identically (the local HELLO nonce never rotated) while
resetting both directional counters to zero — after which a stale sealed
frame's tag verified again and its clear counter passed the ordering check:
stale-frame injection without any PSK knowledge. The shipped design makes
that replay structurally impossible rather than detectable.

Defense as implemented (staged rekey): the HELLO body is exactly
`nonce[16] ‖ kind[1]` — `0x00` INIT, `0x01` RESP; any other kind value and
any body not exactly 17 bytes is dropped with no state mutation beyond the
drop counter (the tier's trust boundary for unauthenticated input). A fresh
channel derives directly from a peer HELLO of either kind — there is no
established state to protect — counters restart at zero, and only an INIT
is answered. A HELLO received while ESTABLISHED never replaces active keys
or counters: the endpoint rotates its local nonce (interpreted as
`boot_base[8] ‖ counter_be[8]`, counter half incremented on every answered
INIT and every rekey INIT), stages candidate keys derived from the fresh
nonce pair in a SINGLE overwriteable slot, and activates them only when an
inbound sealed frame's tag verifies under them — a PSK-possession proof a
PSK-less attacker cannot forge. A replayed current-epoch INIT therefore
stages a candidate that never equals the active keys (inert), and a
replayed old-epoch INIT plus its old sealed frame fails under both key
sets: the monotonic rotation closes same-epoch replay and cross-epoch
resurrection alike. Hostile HELLO floods consume no irreversible resource —
the slot is overwritten, never accumulated, so there is no capacity to
poison — and the dialogue INIT → RESP → consume-or-drop is acyclic (a RESP
is never answered; a RESP with no outstanding initiation is a terminal
drop), which excludes HELLO ping-pong. Rekey initiation is host-only:
`begin_rekey` returns `UsbserialError::WrongRole` on a head (the head
rekeys solely by rebooting, which is the fresh-channel link-open INIT).
Once the initiator has consumed the peer RESP it seals on the STAGED half;
if that staged epoch is dead at the peer, the sender sees transient TX
unavailability with no automatic ACTIVE fallback (the sender cannot know
the peer dropped its frames), and recovery is one host-timed `begin_rekey`
retry — RX keeps accepting old-epoch traffic throughout, because the active
receive half is tried first and the staged candidate only on its failure.

Per-frame ordering and counter discipline: every sealed frame passes the
CRC (cheap pre-filter), then AEAD tag verification, and only then the
receive watermark check and advance — the watermark moves only after the
tag verified, under both key halves. Acceptance is the bounded gap window
mirroring `core::aead`: `counter.checked_sub(recv_last)` must fall in
`1..=RX_COUNTER_MAX_GAP` (256), computed subtraction-based so the
comparison cannot overflow near `u64::MAX`; the effective window truncates
as the watermark approaches the counter ceiling, and once the watermark
reaches `u64::MAX` reception is exhausted until a re-HELLO/rekey — never a
wrap. On the transmit side, the active and staged send counters use
identical last-sent semantics, refuse deterministically at `u64::MAX`
(`UsbserialError::CounterExhausted`), and commit only on the success path —
a failed seal advances nothing and the next attempt reuses the same
candidate counter safely, so nonce reuse is impossible by construction.

Independence: this tier's defense is cache-free by construction; it neither
uses nor alters the gateway initiator cache of Sections 1–14, and its
residual risk statement (no forward secrecy, symmetric PSK compromise
domain) is documented in the module's own header, not here.
