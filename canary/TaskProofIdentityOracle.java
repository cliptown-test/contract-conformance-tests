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

    private static final class Scope {
        private final Object epoch = new Object();
        private boolean poisoned;
        private boolean drainDone;

        void poison() {
            poisoned = true;
        }

        void completeDrain() {
            if (poisoned) {
                throw new IllegalStateException(
                        "poisoned scope must not publish a drain witness");
            }
            drainDone = true;
        }
    }

    private static final class Child { }

    private static final class Permit {
        private long generation;
        private boolean live = true;

        Permit(long generation) {
            this.generation = generation;
        }

        void rotate(long nextGeneration) {
            if (!live) throw new IllegalStateException("consumed permit");
            if (nextGeneration <= generation) {
                throw new IllegalArgumentException("generation must advance");
            }
            live = false;
            generation = nextGeneration;
        }
    }

    private interface RetirementHook {
        void retireNeverStarted(Permit permit);
        void retireAfterPhysicalQuiescence(Permit permit);
    }

    private static final class LoanReservation {
        private enum State {
            PREPARED,
            BOUND,
            RETIRING,
            RETIRED,
            FAILED
        }

        private final Scope scope;
        private final Object epoch;
        private final Permit permit;
        private final long generation;
        private final RetirementHook hook;
        private Child child;
        private State state = State.PREPARED;

        LoanReservation(Scope scope, Permit permit, RetirementHook hook) {
            this.scope = Objects.requireNonNull(scope, "scope");
            this.epoch = scope.epoch;
            this.permit = Objects.requireNonNull(permit, "permit");
            this.generation = permit.generation;
            this.hook = Objects.requireNonNull(hook, "hook");
            requirePermitLive();
        }

        void bind(Scope actualScope, Child actualChild) {
            requireExactScope(actualScope);
            Objects.requireNonNull(actualChild, "child");
            if (state != State.PREPARED) {
                throw new IllegalStateException("bind from " + state);
            }
            requirePermitLive();
            child = actualChild;
            state = State.BOUND;
        }

        void retireNeverStarted(Scope actualScope) {
            requireExactScope(actualScope);
            if (state != State.PREPARED) {
                throw new IllegalStateException("never-started requires prepared");
            }
            retire(true);
        }

        void retirePhysical(Scope actualScope, Child actualChild) {
            requireExactScope(actualScope);
            Objects.requireNonNull(actualChild, "child");
            if (state != State.BOUND) {
                throw new IllegalStateException("physical retirement requires bound");
            }
            if (actualChild != child) {
                throw new IllegalArgumentException("child identity mismatch");
            }
            retire(false);
        }

        boolean retired() {
            return state == State.RETIRED;
        }

        private void retire(boolean neverStarted) {
            state = State.RETIRING;
            try {
                requirePermitLive();
                if (neverStarted) {
                    hook.retireNeverStarted(permit);
                } else {
                    hook.retireAfterPhysicalQuiescence(permit);
                }
                state = State.RETIRED;
            } catch (RuntimeException | Error failure) {
                state = State.FAILED;
                throw failure;
            }
        }

        private void requireExactScope(Scope actualScope) {
            if (actualScope != scope || actualScope.epoch != epoch) {
                throw new IllegalArgumentException("scope epoch mismatch");
            }
        }

        private void requirePermitLive() {
            if (!permit.live || permit.generation != generation) {
                throw new IllegalStateException("stale permit generation");
            }
        }
    }

    private static final class FailedAuthorityScope {
        private final IdentityHashMap<Object, Throwable> failed =
                new IdentityHashMap<>();

        void failBeforeDispatch(
                Object loanAuthority,
                Runnable retireLoan,
                Object resourceAuthority,
                Runnable releaseResource) {
            try {
                retireLoan.run();
            } catch (RuntimeException | Error failure) {
                failed.put(loanAuthority, failure);
                return;
            }
            try {
                releaseResource.run();
            } catch (RuntimeException | Error failure) {
                failed.put(resourceAuthority, failure);
            }
        }

        boolean retains(Object exactAuthority) {
            return failed.containsKey(exactAuthority);
        }

        boolean physicallyQuiescent() {
            return failed.isEmpty();
        }
    }

    public static void main(String[] args) {
        exactBoundaryLookupFailsClosed();
        scopeEpochRejectsForeignAndStaleTickets();
        reservationBindsExactScopeChildAndLifecycle();
        staleGenerationFailsBeforeRetirementHook();
        retirementFailureCannotPublishDrainWitness();
        preDispatchRetirementFailureRetainsExactAuthority();
        partialScopeBindingFailureRetainsExactAuthority();
        System.out.println(
                "TASK_PROOF_IDENTITY_ORACLE=PASS exact_boundary=PASS scope_epoch=PASS "
                + "reservation=PASS exact_child=PASS generation=PASS poison=PASS "
                + "pre_dispatch_poison=PASS partial_bind_poison=PASS");
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

    private static void reservationBindsExactScopeChildAndLifecycle() {
        Scope exactScope = new Scope();
        Scope foreignScope = new Scope();
        Child exactChild = new Child();
        Child lookalikeChild = new Child();
        Permit permit = new Permit(7);
        int[] neverStarted = {0};
        int[] physical = {0};

        LoanReservation reservation = new LoanReservation(
                exactScope,
                permit,
                new RetirementHook() {
                    @Override
                    public void retireNeverStarted(Permit actual) {
                        check(actual == permit, "never-started permit identity mismatch");
                        neverStarted[0]++;
                    }

                    @Override
                    public void retireAfterPhysicalQuiescence(Permit actual) {
                        check(actual == permit, "physical permit identity mismatch");
                        physical[0]++;
                    }
                });

        expect(IllegalArgumentException.class,
                () -> reservation.bind(foreignScope, exactChild),
                "foreign scope must not bind reservation");

        reservation.bind(exactScope, exactChild);

        expect(IllegalArgumentException.class,
                () -> reservation.retirePhysical(exactScope, lookalikeChild),
                "lookalike child must not retire exact-child authority");
        check(!reservation.retired(), "failed lookalike attempt retired reservation");

        reservation.retirePhysical(exactScope, exactChild);
        check(reservation.retired(), "exact physical retirement missing");
        check(neverStarted[0] == 0 && physical[0] == 1,
                "physical path must remain distinct from never-started path");

        expect(IllegalStateException.class,
                () -> reservation.retirePhysical(exactScope, exactChild),
                "retirement must be exactly once");

        Permit neverPermit = new Permit(8);
        LoanReservation never = new LoanReservation(
                exactScope,
                neverPermit,
                new RetirementHook() {
                    @Override
                    public void retireNeverStarted(Permit actual) {
                        neverStarted[0]++;
                    }

                    @Override
                    public void retireAfterPhysicalQuiescence(Permit actual) {
                        throw new AssertionError(
                                "never-started reservation reached physical path");
                    }
                });
        never.retireNeverStarted(exactScope);
        check(never.retired(), "never-started reservation did not retire");
        check(neverStarted[0] == 1,
                "never-started hook must run exactly once");
    }

    private static void staleGenerationFailsBeforeRetirementHook() {
        Scope scope = new Scope();
        Child child = new Child();
        Permit permit = new Permit(11);
        int[] callbacks = {0};

        LoanReservation reservation = new LoanReservation(
                scope,
                permit,
                new RetirementHook() {
                    @Override
                    public void retireNeverStarted(Permit actual) {
                        callbacks[0]++;
                    }

                    @Override
                    public void retireAfterPhysicalQuiescence(Permit actual) {
                        callbacks[0]++;
                    }
                });
        reservation.bind(scope, child);
        permit.rotate(12);

        expect(IllegalStateException.class,
                () -> reservation.retirePhysical(scope, child),
                "stale generation must fail before release callback");
        check(callbacks[0] == 0,
                "stale capability reached retirement callback");
        check(!reservation.retired(),
                "stale capability manufactured retired reservation");
    }

    private static void retirementFailureCannotPublishDrainWitness() {
        Scope scope = new Scope();
        Child child = new Child();
        Permit permit = new Permit(5);
        RuntimeException failure = new RuntimeException("retirement failed");

        LoanReservation reservation = new LoanReservation(
                scope,
                permit,
                new RetirementHook() {
                    @Override
                    public void retireNeverStarted(Permit actual) {
                        throw new AssertionError("wrong retirement path");
                    }

                    @Override
                    public void retireAfterPhysicalQuiescence(Permit actual) {
                        throw failure;
                    }
                });
        reservation.bind(scope, child);

        RuntimeException observed = expectAndReturn(
                RuntimeException.class,
                () -> reservation.retirePhysical(scope, child),
                "retirement failure must propagate to trusted scope machinery");
        check(observed == failure, "retirement failure identity changed");

        scope.poison();
        expect(IllegalStateException.class,
                scope::completeDrain,
                "poisoned memory authority must never publish scope drain");
        check(!scope.drainDone,
                "poisoned scope manufactured reclamation witness");
    }

    private static void preDispatchRetirementFailureRetainsExactAuthority() {
        Object loan = new Object();
        Object resource = new Object();
        RuntimeException loanFailure =
                new RuntimeException("never-started loan retirement failed");
        boolean[] resourceReleased = {false};
        FailedAuthorityScope failedLoan = new FailedAuthorityScope();

        failedLoan.failBeforeDispatch(
                loan,
                () -> { throw loanFailure; },
                resource,
                () -> resourceReleased[0] = true);

        check(failedLoan.retains(loan),
                "failed never-started loan authority was not retained by identity");
        check(!failedLoan.retains(new Object()),
                "lookalike authority matched identity poison");
        check(!resourceReleased[0],
                "dependent resource release ran after loan retirement failed");
        check(!failedLoan.physicallyQuiescent(),
                "failed never-started loan manufactured physical quiescence");

        Object loan2 = new Object();
        Object resource2 = new Object();
        RuntimeException resourceFailure =
                new RuntimeException("resource release failed");
        FailedAuthorityScope failedResource = new FailedAuthorityScope();

        failedResource.failBeforeDispatch(
                loan2,
                () -> { },
                resource2,
                () -> { throw resourceFailure; });

        check(failedResource.retains(resource2),
                "failed physical-resource authority was not retained by identity");
        check(!failedResource.physicallyQuiescent(),
                "failed resource release manufactured physical quiescence");
    }

    private static void partialScopeBindingFailureRetainsExactAuthority() {
        Object exactLoan = new Object();
        Object acceptedEpoch = new Object();
        Object[] boundEpoch = {null};
        FailedAuthorityScope scope = new FailedAuthorityScope();
        RuntimeException failure =
                new RuntimeException("scope binding failed after accepting epoch");

        Runnable partialBind = () -> {
            boundEpoch[0] = acceptedEpoch;
            throw failure;
        };

        RuntimeException observed = expectAndReturn(
                RuntimeException.class,
                partialBind,
                "partial scope binding must fail");
        check(observed == failure, "partial binding failure identity changed");
        check(boundEpoch[0] == acceptedEpoch,
                "oracle did not model partial epoch acceptance");

        // Once a trusted lifecycle object has partially accepted an epoch,
        // exact identity must be retained even though no runtime child exists.
        scope.failBeforeDispatch(
                exactLoan,
                () -> { throw failure; },
                new Object(),
                () -> { });
        check(scope.retains(exactLoan),
                "partially bound exact loan was not retained");
        check(!scope.physicallyQuiescent(),
                "partial scope binding manufactured physical quiescence");
    }

    private static <T extends Throwable> void expect(
            Class<T> type, Runnable action, String message) {
        expectAndReturn(type, action, message);
    }

    private static <T extends Throwable> T expectAndReturn(
            Class<T> type, Runnable action, String message) {
        try {
            action.run();
        } catch (Throwable failure) {
            if (type.isInstance(failure)) return type.cast(failure);
            throw new AssertionError(message + ": wrong failure " + failure, failure);
        }
        throw new AssertionError(message + ": no failure");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
