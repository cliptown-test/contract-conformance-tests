package canary;

import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class TaskProofIdentityOracle {
    private TaskProofIdentityOracle() { }

    private static final class ProofLedger {
        private final IdentityHashMap<Object, List<String>> proofs = new IdentityHashMap<>();
        private boolean sealed;

        void record(Object boundary, List<String> entries) {
            if (sealed) throw new IllegalStateException("sealed");
            Objects.requireNonNull(boundary, "boundary");
            if (proofs.containsKey(boundary)) {
                throw new IllegalStateException("duplicate exact boundary");
            }
            proofs.put(boundary, List.copyOf(entries));
        }

        void seal() { sealed = true; }

        List<String> lookup(Object boundary) {
            Objects.requireNonNull(boundary, "boundary");
            if (!sealed) throw new IllegalStateException("proof ledger must be sealed");
            if (!proofs.containsKey(boundary)) {
                throw new IllegalArgumentException("no proof for exact AST boundary");
            }
            return proofs.get(boundary);
        }
    }

    private static final class ScopeEpoch { }

    private static final class Ticket {
        private final ScopeEpoch epoch;
        private final long id;

        Ticket(ScopeEpoch epoch, long id) {
            this.epoch = Objects.requireNonNull(epoch, "epoch");
            this.id = id;
        }
    }

    private static final class Verifier {
        private final ScopeEpoch epoch = new ScopeEpoch();
        private final Map<Ticket, String> live = new IdentityHashMap<>();
        private long nextId = 1;

        Ticket admit() {
            Ticket ticket = new Ticket(epoch, nextId++);
            live.put(ticket, "live");
            return ticket;
        }

        void retire(Ticket ticket) {
            if (ticket.epoch != epoch) {
                throw new IllegalArgumentException("foreign Task scope epoch");
            }
            if (live.remove(ticket) == null) {
                throw new IllegalArgumentException("stale Task ticket");
            }
        }
    }

    private static final class Scope { }
    private static final class Child { }

    private interface RetirementHook {
        void retireNeverStarted(Scope scope);
        void retireAfterPhysicalQuiescence(Scope scope, Child child);
    }

    public static void main(String[] args) {
        exactBoundaryLookupFailsClosed();
        scopeEpochRejectsForeignAndStaleTickets();
        retirementSeparatesNeverStartedFromExactPhysicalChild();
        System.out.println(
                "TASK_PROOF_IDENTITY_ORACLE=PASS exact_boundary=PASS scope_epoch=PASS exact_child=PASS");
    }

    private static void exactBoundaryLookupFailsClosed() {
        Object exact = new Object();
        Object lookalike = new Object();
        ProofLedger ledger = new ProofLedger();
        ledger.record(exact, List.of());
        ledger.seal();

        check(ledger.lookup(exact).isEmpty(),
                "valid zero-transfer proof must remain representable");
        expect(IllegalArgumentException.class,
                () -> ledger.lookup(lookalike),
                "lookalike/missing proof must not look like valid empty proof");
    }

    private static void scopeEpochRejectsForeignAndStaleTickets() {
        Verifier one = new Verifier();
        Verifier two = new Verifier();
        Ticket ticket = one.admit();

        expect(IllegalArgumentException.class,
                () -> two.retire(ticket),
                "foreign verifier must reject ticket before map lookup");
        one.retire(ticket);
        expect(IllegalArgumentException.class,
                () -> one.retire(ticket),
                "retired ticket must be stale");
        check(ticket.id == 1L, "ticket identity sanity");
    }

    private static void retirementSeparatesNeverStartedFromExactPhysicalChild() {
        Scope exactScope = new Scope();
        Child exactChild = new Child();
        int[] neverStarted = {0};
        int[] physical = {0};

        RetirementHook hook = new RetirementHook() {
            @Override
            public void retireNeverStarted(Scope scope) {
                check(scope == exactScope, "never-started scope identity mismatch");
                neverStarted[0]++;
            }

            @Override
            public void retireAfterPhysicalQuiescence(Scope scope, Child child) {
                check(scope == exactScope, "physical scope identity mismatch");
                check(child == exactChild, "physical child identity mismatch");
                physical[0]++;
            }
        };

        hook.retireNeverStarted(exactScope);
        check(neverStarted[0] == 1 && physical[0] == 0,
                "never-started path must not imply physical quiescence");

        hook.retireAfterPhysicalQuiescence(exactScope, exactChild);
        check(physical[0] == 1, "exact child physical retirement missing");

        expect(AssertionError.class,
                () -> hook.retireAfterPhysicalQuiescence(exactScope, new Child()),
                "lookalike child must not retire exact-child authority");
    }

    private static <T extends Throwable> void expect(
            Class<T> type, Runnable action, String message) {
        try {
            action.run();
        } catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError(message + ": wrong failure " + failure, failure);
        }
        throw new AssertionError(message + ": no failure");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
