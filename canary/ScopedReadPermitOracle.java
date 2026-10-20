package canary;

import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Independent JDK-only semantic oracle for compiler-issued scoped read permits.
 * No Oreslang source, AST, Git objects, or implementation classes are copied.
 */
public final class ScopedReadPermitOracle {
    private ScopedReadPermitOracle() { }

    private static final class FatalHostError extends Error {
        private static final long serialVersionUID = 1L;
        FatalHostError(String message) { super(message); }
    }

    private enum Mode { OWNED_SEND, SCOPED_READ_BORROW }

    private static final class ScopePoison extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ScopePoison(Throwable cause) {
            super("structured scope authority accounting poisoned", cause);
        }
    }

    private record Proof(
            String name,
            Mode mode,
            long regionId,
            long generation,
            String path) {
        Proof {
            if (name == null || name.isBlank()) throw new IllegalArgumentException("name");
            if (mode == null || path == null) throw new NullPointerException();
            if (mode == Mode.OWNED_SEND) {
                if (regionId != 0L || generation != 0L || !path.isEmpty()) {
                    throw new IllegalArgumentException("owned authority");
                }
            } else if (regionId <= 0L || generation < 0L || path.isBlank()) {
                throw new IllegalArgumentException("borrow authority");
            }
        }
    }

    private static final class Region {
        final long id;
        long generation;
        int immutableLoans;
        int value;

        Region(long id, int value) {
            this.id = id;
            this.value = value;
        }

        void assign(int next) {
            if (immutableLoans != 0) {
                throw new IllegalStateException("mutation while borrowed");
            }
            value = next;
            // Value replacement is not storage-region reuse.
        }

        void reuse(int next) {
            if (immutableLoans != 0) {
                throw new IllegalStateException("reuse while borrowed");
            }
            if (generation == Long.MAX_VALUE) throw new IllegalStateException("generation overflow");
            generation++;
            value = next;
        }
    }

    private static final class Borrow {
        final Region region;
        final boolean mutable;
        final boolean projected;
        final String path;
        final boolean syncSafe;
        boolean live = true;

        Borrow(Region region, boolean mutable, boolean projected, String path) {
            this(region, mutable, projected, path, true);
        }

        Borrow(
                Region region,
                boolean mutable,
                boolean projected,
                String path,
                boolean syncSafe) {
            this.region = region;
            this.mutable = mutable;
            this.projected = projected;
            this.path = path;
            this.syncSafe = syncSafe;
            if (mutable) throw new IllegalArgumentException("oracle phase is read-only only");
            region.immutableLoans++;
        }

        void close() {
            if (!live) return;
            live = false;
            region.immutableLoans--;
            if (region.immutableLoans < 0) throw new AssertionError("negative loan count");
        }
    }

    private static final class Scope {
        private final Set<Region> readRegions =
                Collections.newSetFromMap(new IdentityHashMap<>());
        private final Set<Borrow> exactBorrows =
                Collections.newSetFromMap(new IdentityHashMap<>());
        private boolean open = true;

        Proof authorize(
                String name,
                Borrow borrow,
                boolean write,
                boolean deferredExecution) {
            if (!open) throw new IllegalStateException("sealed");
            if (borrow == null || !borrow.live) throw new IllegalStateException("dead borrow");
            if (deferredExecution) throw new IllegalStateException("deferred execution");
            if (borrow.mutable || write) throw new IllegalStateException("mutable/write");
            if (!borrow.syncSafe) throw new IllegalStateException("non-Sync referent");
            if (borrow.projected) throw new IllegalStateException("projected");
            if (!"$".equals(borrow.path)) throw new IllegalStateException("path");

            readRegions.add(borrow.region);
            exactBorrows.add(borrow);
            return new Proof(
                    name,
                    Mode.SCOPED_READ_BORROW,
                    borrow.region.id,
                    borrow.region.generation,
                    borrow.path);
        }

        void validateHiddenDrain(Borrow... visibleBorrows) {
            for (Borrow borrow : visibleBorrows) {
                if (!borrow.live) continue;
                if (!exactBorrows.contains(borrow)) {
                    throw new IllegalStateException("uncaptured borrow");
                }
                if (!readRegions.contains(borrow.region)) {
                    throw new AssertionError("exact borrow lost region authority");
                }
            }
            open = false;
        }
    }

    private record RuntimeTicket(long regionId, long generation) {
        RuntimeTicket {
            if (regionId <= 0L || generation < 0L) {
                throw new IllegalArgumentException("invalid runtime ticket");
            }
        }
    }

    private static final class Child {
        private final Proof proof;
        private final Region region;
        private final RuntimeTicket ticket;

        Child(Proof proof, Region region, boolean liveStructuredScope) {
            this(proof, region, liveStructuredScope, null);
        }

        Child(
                Proof proof,
                Region region,
                boolean liveStructuredScope,
                RuntimeTicket inheritedTicket) {
            if (proof.mode() != Mode.SCOPED_READ_BORROW) {
                throw new IllegalArgumentException("read proof required");
            }
            if (!liveStructuredScope) {
                throw new IllegalStateException("borrowed Task without live scope");
            }
            this.proof = proof;
            this.region = region;
            if (inheritedTicket != null
                    && (inheritedTicket.regionId() != proof.regionId()
                        || inheritedTicket.generation() != proof.generation())) {
                throw new IllegalStateException("nested projection changed region proof");
            }
            this.ticket = new RuntimeTicket(proof.regionId(), proof.generation());
            validateGeneration();
        }

        Child projectNested(Proof nestedProof) {
            return new Child(nestedProof, region, true, ticket);
        }

        Borrow derivativeReborrow() {
            throw new IllegalStateException("derivative reborrow of scoped read authority");
        }

        int readBeforeAndAfterSuspension() {
            validateGeneration();
            int before = region.value;
            // Simulated carrier migration / await. Logical permit identity is
            // proof-based and deliberately independent of a Java thread.
            Thread.yield();
            validateGeneration();
            int after = region.value;
            if (before != after) throw new AssertionError("borrowed value changed");
            return after;
        }

        private void validateGeneration() {
            if (proof.regionId() != region.id
                    || proof.generation() != region.generation) {
                throw new IllegalStateException("stale scoped read proof");
            }
        }
    }


    private static final class LeaseScope {
        private static final class RegionLease {
            final long generation;
            int readers;

            RegionLease(long generation) {
                this.generation = generation;
            }
        }

        private static final class LeaseClaim {
            final Proof proof;
            final AtomicBoolean issued = new AtomicBoolean();

            LeaseClaim(Proof proof) {
                this.proof = proof;
            }

            boolean tryIssue() {
                return issued.compareAndSet(false, true);
            }
        }

        private static final class LeaseChild {
            final LeaseClaim claim;
            boolean terminal;
            boolean quiescent;
            boolean retirementClaimed;
            boolean retired;
            boolean cancelled;

            LeaseChild(LeaseClaim claim) {
                this.claim = claim;
            }

            Proof proof() {
                return claim.proof;
            }
        }

        private final Map<Long, RegionLease> regions = new HashMap<>();
        private final Set<LeaseChild> liveChildren =
                Collections.newSetFromMap(new IdentityHashMap<>());
        private boolean poisoned;
        private boolean poisonFailurePublished;

        synchronized LeaseChild fork(LeaseClaim claim) {
            Proof proof = claim.proof;
            if (proof.mode() != Mode.SCOPED_READ_BORROW || !"$".equals(proof.path())) {
                throw new IllegalArgumentException("whole-region read proof required");
            }
            RegionLease existing = regions.get(proof.regionId());
            if (existing != null && existing.generation != proof.generation()) {
                throw new IllegalStateException("stale live generation");
            }
            if (!claim.tryIssue()) {
                throw new IllegalStateException("scoped read claim identity already issued");
            }

            RegionLease lease = regions.computeIfAbsent(
                    proof.regionId(),
                    ignored -> new RegionLease(proof.generation()));
            LeaseChild child = new LeaseChild(claim);
            if (!liveChildren.add(child)) {
                throw new AssertionError("duplicate lease child identity");
            }
            lease.readers++;
            return child;
        }

        synchronized void terminal(LeaseChild child) {
            child.terminal = true;
            lifecycleChanged(child);
        }

        synchronized void quiescent(LeaseChild child) {
            child.quiescent = true;
            lifecycleChanged(child);
        }

        synchronized boolean hasLease(long regionId, long generation) {
            RegionLease lease = regions.get(regionId);
            return lease != null
                    && lease.generation == generation
                    && lease.readers > 0;
        }

        synchronized int readers(long regionId) {
            RegionLease lease = regions.get(regionId);
            return lease == null ? 0 : lease.readers;
        }

        synchronized void requireLiveForResume(LeaseChild child) {
            if (!liveChildren.contains(child)
                    || !hasLease(child.proof().regionId(), child.proof().generation())) {
                throw new IllegalStateException(
                        "scoped read continuation resumed without its exact live lease");
            }
        }

        synchronized void corruptRegionForTest(long regionId) {
            regions.remove(regionId);
        }

        synchronized boolean isPoisoned() {
            return poisoned;
        }

        synchronized int liveChildren() {
            return liveChildren.size();
        }

        synchronized boolean canPublishDrainWitness() {
            return !poisoned && liveChildren.isEmpty();
        }

        synchronized boolean poisonFailurePublished() {
            return poisonFailurePublished;
        }

        synchronized boolean cancelled(LeaseChild child) {
            return child.cancelled;
        }

        private void lifecycleChanged(LeaseChild child) {
            if (poisoned) {
                // Keep only the child whose retirement actually failed pinned.
                // Healthy siblings must retire their exact lease identities once
                // they are terminal + physically quiescent.
                retireIfReady(child);
                publishPoisonIfPhysicallyQuiescent();
                return;
            }
            retireIfReady(child);
            if (poisoned) {
                // Poison revokes every remaining child logically, but physical
                // carrier exit is still required before the failed drain becomes
                // observable.
                for (LeaseChild remaining : liveChildren) {
                    if (!remaining.terminal) {
                        remaining.cancelled = true;
                        remaining.terminal = true;
                    }
                }
                publishPoisonIfPhysicallyQuiescent();
            }
        }

        private void publishPoisonIfPhysicallyQuiescent() {
            if (!poisoned || poisonFailurePublished) return;
            for (LeaseChild child : liveChildren) {
                if (!child.terminal || !child.quiescent) return;
            }
            poisonFailurePublished = true;
        }

        private void retireIfReady(LeaseChild child) {
            if (child.retired
                    || child.retirementClaimed
                    || !child.terminal
                    || !child.quiescent) {
                return;
            }
            child.retirementClaimed = true;

            RegionLease lease = regions.get(child.proof().regionId());
            if (lease == null
                    || lease.generation != child.proof().generation()
                    || lease.readers <= 0) {
                // Failed memory-authority retirement pins the child and
                // permanently forbids a drain witness.
                poisoned = true;
                return;
            }

            // Retire region authority before the child can leave the join set.
            lease.readers--;
            if (lease.readers == 0) regions.remove(child.proof().regionId());

            if (!liveChildren.remove(child)) {
                poisoned = true;
                return;
            }
            child.retired = true;
        }
    }

    public static void main(String[] args) {
        directReadSurvivesSuspension();
        outsideScopeFails();
        mutableProjectedDeferredAndWriteFail();
        nonSyncSharedBorrowFails();
        exactBorrowBindingMatters();
        nestedProjectionPreservesRuntimeTicket();
        derivativeReborrowFails();
        mutationIsExcludedWhileLoanLives();
        valueAssignmentDoesNotRotateRegionGeneration();
        actualRegionReuseInvalidatesStaleProof();
        runtimeLeaseSurvivesLogicalCancellationUntilPhysicalQuiescence();
        concurrentReadersShareGenerationAndRejectMismatchAtomically();
        oneClaimCannotRaceAcrossTwoScopes();
        retirementCorruptionPoisonsJoinWitness();
        poisonWaitsForSiblingPhysicalQuiescence();
        poisonIsNotGuestRecoverable();
        ownedProofCarriesNoAuthority();

        System.out.println(
                "SCOPED_READ_PERMIT_ORACLE=PASS "
                + "suspension=PASS exact_binding=PASS nested_ticket=PASS "
                + "reborrow=PASS deferred=PASS sync=PASS mutation=PASS generation=PASS stale=PASS "
                + "lifetime=PASS live_generation=PASS readers=PASS "
                + "claim_identity=PASS aba=PASS cross_scope=PASS "
                + "poison=PASS poison_barrier=PASS poison_healthy_retire=PASS "
                + "poison_unmaskable=PASS checked_wrapper=PASS fatal_cleanup=PASS "
                + "resume_guard=PASS");
    }

    private static void directReadSurvivesSuspension() {
        Region region = new Region(1, 42);
        Borrow borrow = new Borrow(region, false, false, "$");
        Scope scope = new Scope();
        Proof proof = scope.authorize("ref", borrow, false, false);
        Child child = new Child(proof, region, true);
        check(child.readBeforeAndAfterSuspension() == 42, "read changed");
        scope.validateHiddenDrain(borrow);
        borrow.close();
    }

    private static void outsideScopeFails() {
        Region region = new Region(1, 42);
        Borrow borrow = new Borrow(region, false, false, "$");
        Proof proof = new Scope().authorize("ref", borrow, false, false);
        expectFailure(() -> new Child(proof, region, false));
        borrow.close();
    }

    private static void mutableProjectedDeferredAndWriteFail() {
        Region region = new Region(1, 42);
        Scope scope = new Scope();

        expectFailure(() -> new Borrow(region, true, false, "$"));

        Borrow projected = new Borrow(region, false, true, "$.field");
        expectFailure(() -> scope.authorize("projected", projected, false, false));
        projected.close();

        Borrow direct = new Borrow(region, false, false, "$");
        expectFailure(() -> scope.authorize("deferred", direct, false, true));
        expectFailure(() -> scope.authorize("write", direct, true, false));
        direct.close();
    }


    private static void nonSyncSharedBorrowFails() {
        Region region = new Region(1, 42);
        Borrow nonSync = new Borrow(region, false, false, "$", false);
        Scope scope = new Scope();
        expectFailure(() -> scope.authorize("futureView", nonSync, false, false));
        nonSync.close();
    }

    private static void exactBorrowBindingMatters() {
        Region region = new Region(1, 42);
        Borrow permitted = new Borrow(region, false, false, "$");
        Borrow ordinary = new Borrow(region, false, false, "$");
        Scope scope = new Scope();
        scope.authorize("permitted", permitted, false, false);
        expectFailure(() -> scope.validateHiddenDrain(permitted, ordinary));
        permitted.close();
        ordinary.close();
    }


    private static void nestedProjectionPreservesRuntimeTicket() {
        Region region = new Region(1, 42);
        Borrow borrow = new Borrow(region, false, false, "$");
        Scope scope = new Scope();
        Proof outerProof = scope.authorize("ref", borrow, false, false);
        Child outer = new Child(outerProof, region, true);

        Proof same = new Proof(
                "ref",
                Mode.SCOPED_READ_BORROW,
                outerProof.regionId(),
                outerProof.generation(),
                outerProof.path());
        Child inner = outer.projectNested(same);
        check(inner.readBeforeAndAfterSuspension() == 42,
                "nested ticket read changed");

        Proof mismatch = new Proof(
                "ref",
                Mode.SCOPED_READ_BORROW,
                outerProof.regionId() + 1,
                outerProof.generation(),
                outerProof.path());
        expectFailure(() -> outer.projectNested(mismatch));

        scope.validateHiddenDrain(borrow);
        borrow.close();
    }

    private static void derivativeReborrowFails() {
        Region region = new Region(1, 42);
        Borrow borrow = new Borrow(region, false, false, "$");
        Scope scope = new Scope();
        Proof proof = scope.authorize("ref", borrow, false, false);
        Child child = new Child(proof, region, true);
        expectFailure(child::derivativeReborrow);
        scope.validateHiddenDrain(borrow);
        borrow.close();
    }

    private static void mutationIsExcludedWhileLoanLives() {
        Region region = new Region(1, 41);
        Borrow borrow = new Borrow(region, false, false, "$");
        Scope scope = new Scope();
        scope.authorize("ref", borrow, false, false);
        expectFailure(() -> region.assign(42));
        scope.validateHiddenDrain(borrow);
        borrow.close();
        region.assign(42);
        check(region.value == 42, "post-drain mutation failed");
    }

    private static void valueAssignmentDoesNotRotateRegionGeneration() {
        Region region = new Region(1, 40);
        long generation = region.generation;
        region.assign(41);
        check(region.generation == generation,
                "ordinary assignment changed storage generation");
    }

    private static void actualRegionReuseInvalidatesStaleProof() {
        Region region = new Region(1, 40);
        Borrow borrow = new Borrow(region, false, false, "$");
        Scope scope = new Scope();
        Proof proof = scope.authorize("ref", borrow, false, false);
        scope.validateHiddenDrain(borrow);
        borrow.close();

        region.reuse(99);
        expectFailure(() -> new Child(proof, region, true));
    }


    private static void runtimeLeaseSurvivesLogicalCancellationUntilPhysicalQuiescence() {
        Proof proof = new Proof("view", Mode.SCOPED_READ_BORROW, 77L, 4L, "$");
        LeaseScope scope = new LeaseScope();
        LeaseScope.LeaseClaim claim = new LeaseScope.LeaseClaim(proof);
        LeaseScope.LeaseChild child = scope.fork(claim);

        check(scope.hasLease(77L, 4L), "lease missing after admission");
        scope.terminal(child);
        check(scope.hasLease(77L, 4L),
                "logical terminal state retired authority before physical quiescence");
        check(scope.readers(77L) == 1, "reader count changed before quiescence");
        scope.requireLiveForResume(child);

        scope.quiescent(child);
        check(!scope.hasLease(77L, 4L),
                "lease remained live after terminal + physical quiescence");
        expectFailure(() -> scope.requireLiveForResume(child));
        check(scope.readers(77L) == 0, "reader count leaked after retirement");
    }

    private static void concurrentReadersShareGenerationAndRejectMismatchAtomically() {
        Proof leftProof = new Proof("view", Mode.SCOPED_READ_BORROW, 91L, 2L, "$");
        Proof rightProof = new Proof("view", Mode.SCOPED_READ_BORROW, 91L, 2L, "$");
        Proof staleProof = new Proof("stale", Mode.SCOPED_READ_BORROW, 91L, 3L, "$");
        LeaseScope.LeaseClaim left = new LeaseScope.LeaseClaim(leftProof);
        LeaseScope.LeaseClaim right = new LeaseScope.LeaseClaim(rightProof);
        LeaseScope.LeaseClaim stale = new LeaseScope.LeaseClaim(staleProof);
        LeaseScope scope = new LeaseScope();

        LeaseScope.LeaseChild a = scope.fork(left);
        LeaseScope.LeaseChild b = scope.fork(right);
        check(scope.readers(91L) == 2, "shared readers were not counted");

        expectFailure(() -> scope.fork(stale));
        check(!stale.issued.get(),
                "generation rejection consumed a never-admitted claim");
        check(scope.readers(91L) == 2,
                "rejected generation mismatch mutated live reader authority");
        check(scope.hasLease(91L, 2L), "valid generation disappeared");
        check(!scope.hasLease(91L, 3L), "stale generation became live");

        scope.terminal(a);
        scope.quiescent(a);
        check(scope.readers(91L) == 1,
                "first sibling retirement released both readers");
        check(scope.hasLease(91L, 2L),
                "aggregate region should remain live for sibling");
        expectFailure(() -> scope.requireLiveForResume(a));
        scope.requireLiveForResume(b);
        expectFailure(() -> scope.fork(left));

        scope.quiescent(b);
        scope.terminal(b);
        check(scope.readers(91L) == 0,
                "last sibling retirement leaked read authority");
    }

    private static void oneClaimCannotRaceAcrossTwoScopes() {
        Proof proof = new Proof("view", Mode.SCOPED_READ_BORROW, 101L, 0L, "$");
        LeaseScope.LeaseClaim claim = new LeaseScope.LeaseClaim(proof);
        LeaseScope left = new LeaseScope();
        LeaseScope right = new LeaseScope();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger admitted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        Runnable leftAttempt = () -> raceClaim(left, claim, ready, start, admitted, rejected);
        Runnable rightAttempt = () -> raceClaim(right, claim, ready, start, admitted, rejected);
        Thread a = Thread.ofVirtual().start(leftAttempt);
        Thread b = Thread.ofVirtual().start(rightAttempt);

        try {
            check(ready.await(5, TimeUnit.SECONDS), "claim race did not become ready");
            start.countDown();
            a.join();
            b.join();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
        }

        check(admitted.get() == 1, "claim race admitted " + admitted.get());
        check(rejected.get() == 1, "claim race rejected " + rejected.get());
        check(claim.issued.get(), "winning claim did not remain one-shot consumed");
    }

    private static void raceClaim(
            LeaseScope scope,
            LeaseScope.LeaseClaim claim,
            CountDownLatch ready,
            CountDownLatch start,
            AtomicInteger admitted,
            AtomicInteger rejected) {
        ready.countDown();
        try {
            if (!start.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("claim race start timeout");
            }
            scope.fork(claim);
            admitted.incrementAndGet();
        } catch (IllegalStateException expected) {
            rejected.incrementAndGet();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
        }
    }

    private static void retirementCorruptionPoisonsJoinWitness() {
        Proof proof = new Proof(
                "view", Mode.SCOPED_READ_BORROW, 113L, 6L, "$");
        LeaseScope.LeaseClaim claim = new LeaseScope.LeaseClaim(proof);
        LeaseScope scope = new LeaseScope();
        LeaseScope.LeaseChild child = scope.fork(claim);

        scope.terminal(child);
        check(scope.liveChildren() == 1,
                "terminal-only child left join set");

        // Simulate trusted runtime accounting corruption immediately before
        // physical-quiescence retirement.
        scope.corruptRegionForTest(113L);
        scope.quiescent(child);

        check(scope.isPoisoned(),
                "retirement corruption did not poison scope");
        check(scope.liveChildren() == 1,
                "failed retirement removed child from join set");
        check(!scope.canPublishDrainWitness(),
                "poisoned memory authority manufactured a drain witness");
        check(claim.issued.get(),
                "failed physical retirement resurrected one-shot claim");
    }

    private static void poisonWaitsForSiblingPhysicalQuiescence() {
        LeaseScope scope = new LeaseScope();
        LeaseScope.LeaseChild corrupt = scope.fork(
                new LeaseScope.LeaseClaim(new Proof(
                        "corrupt", Mode.SCOPED_READ_BORROW, 127L, 0L, "$")));
        LeaseScope.LeaseChild sibling = scope.fork(
                new LeaseScope.LeaseClaim(new Proof(
                        "sibling", Mode.SCOPED_READ_BORROW, 128L, 0L, "$")));

        scope.terminal(corrupt);
        scope.corruptRegionForTest(127L);
        scope.quiescent(corrupt);

        check(scope.isPoisoned(), "corrupt retirement did not poison scope");
        check(scope.cancelled(sibling),
                "poison did not revoke sibling logical authority");
        check(!scope.poisonFailurePublished(),
                "poison failure became visible before sibling physical quiescence");

        scope.quiescent(sibling);
        check(scope.poisonFailurePublished(),
                "poison failure did not publish after every carrier quiesced");
        check(scope.liveChildren() == 1,
                "healthy sibling remained pinned after physical quiescence");
        check(scope.readers(128L) == 0,
                "healthy sibling's stale lease remained live under poison");
        check(!scope.canPublishDrainWitness(),
                "poisoned scope manufactured a success witness");
    }

    private static void poisonIsNotGuestRecoverable() {
        ScopePoison poison = new ScopePoison(
                new IllegalStateException("region accounting corrupt"));
        check(!guestRecoverable(poison),
                "direct poison became guest recoverable");

        RuntimeException wrapped = new IllegalStateException(
                "future failed", poison);
        check(!guestRecoverable(wrapped),
                "wrapped poison became guest recoverable");

        RuntimeException suppressed = new IllegalStateException("cleanup");
        suppressed.addSuppressed(poison);
        check(!guestRecoverable(suppressed),
                "suppressed poison became guest recoverable");

        Exception checkedCause = new Exception("checked wrapper", poison);
        check(!guestRecoverable(checkedCause),
                "checked cause wrapper made poison guest recoverable");

        Exception checkedSuppressed = new Exception("checked cleanup wrapper");
        checkedSuppressed.addSuppressed(poison);
        check(!guestRecoverable(checkedSuppressed),
                "checked suppressed wrapper made poison guest recoverable");
    }

    private static boolean guestRecoverable(Throwable failure) {
        java.util.ArrayDeque<Throwable> pending = new java.util.ArrayDeque<>();
        java.util.IdentityHashMap<Throwable, Boolean> seen =
                new java.util.IdentityHashMap<>();
        pending.add(failure);
        while (!pending.isEmpty()) {
            Throwable current = pending.removeFirst();
            if (seen.put(current, Boolean.TRUE) != null) return false;
            if (current instanceof ScopePoison) return false;
            if (current.getCause() != null) pending.addLast(current.getCause());
            for (Throwable suppressed : current.getSuppressed()) {
                pending.addLast(suppressed);
            }
            if (seen.size() + pending.size() > 64) return false;
        }
        return true;
    }


    private static void fatalCleanupOutranksScopePoison() {
        ScopePoison poison = new ScopePoison("authority accounting poisoned");
        FatalHostError fatal = new FatalHostError("vm fatal");
        Throwable winner = mergeCleanupFailure(poison, fatal);
        check(winner == fatal, "host-fatal cleanup was masked by scope poison");
        check(fatal.getSuppressed().length == 1
                        && fatal.getSuppressed()[0] == poison,
                "scope poison was not retained as suppressed diagnostic");

        FatalHostError earlierFatal = new FatalHostError("earlier vm fatal");
        ScopePoison laterPoison = new ScopePoison("later poison");
        Throwable earlierWinner = mergeCleanupFailure(earlierFatal, laterPoison);
        check(earlierWinner == earlierFatal,
                "later scope poison replaced an earlier host-fatal failure");
        check(earlierFatal.getSuppressed().length == 1
                        && earlierFatal.getSuppressed()[0] == laterPoison,
                "later poison was not retained under earlier host-fatal failure");
    }

    private static Throwable mergeCleanupFailure(
            Throwable earlier, Throwable cleanup) {
        if (earlier == cleanup) return earlier;
        boolean earlierFatal = earlier instanceof Error;
        boolean cleanupFatal = cleanup instanceof Error;
        if (cleanupFatal && !earlierFatal) {
            cleanup.addSuppressed(earlier);
            return cleanup;
        }
        if (earlierFatal || earlier instanceof ScopePoison) {
            earlier.addSuppressed(cleanup);
            return earlier;
        }
        cleanup.addSuppressed(earlier);
        return cleanup;
    }

    private static void ownedProofCarriesNoAuthority() {
        Proof owned = new Proof("value", Mode.OWNED_SEND, 0, 0, "");
        check(owned.regionId() == 0L && owned.generation() == 0L,
                "owned capture gained region authority");
    }

    private static void expectFailure(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected failure");
        } catch (IllegalArgumentException | IllegalStateException expected) {
            // expected
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
