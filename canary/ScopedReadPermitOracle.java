package canary;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Independent JDK-only semantic oracle for compiler-issued scoped read permits.
 * No Oreslang source, AST, Git objects, or implementation classes are copied.
 */
public final class ScopedReadPermitOracle {
    private ScopedReadPermitOracle() { }

    private enum Mode { OWNED_SEND, SCOPED_READ_BORROW }

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
        boolean live = true;

        Borrow(Region region, boolean mutable, boolean projected, String path) {
            this.region = region;
            this.mutable = mutable;
            this.projected = projected;
            this.path = path;
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

    public static void main(String[] args) {
        directReadSurvivesSuspension();
        outsideScopeFails();
        mutableProjectedDeferredAndWriteFail();
        exactBorrowBindingMatters();
        nestedProjectionPreservesRuntimeTicket();
        derivativeReborrowFails();
        mutationIsExcludedWhileLoanLives();
        valueAssignmentDoesNotRotateRegionGeneration();
        actualRegionReuseInvalidatesStaleProof();
        ownedProofCarriesNoAuthority();

        System.out.println(
                "SCOPED_READ_PERMIT_ORACLE=PASS "
                + "suspension=PASS exact_binding=PASS nested_ticket=PASS "
                + "reborrow=PASS deferred=PASS mutation=PASS generation=PASS stale=PASS");
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
