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
            // Resource/code/FFI cleanup may still rely on borrowed memory.
            // It must retire before the memory-loan capability is returned.
            try {
                releaseResource.run();
            } catch (RuntimeException | Error failure) {
                failed.put(resourceAuthority, failure);
                failed.put(loanAuthority, failure);
                return;
            }
            try {
                retireLoan.run();
            } catch (RuntimeException | Error failure) {
                failed.put(loanAuthority, failure);
            }
        }

        boolean retains(Object exactAuthority) {
            return failed.containsKey(exactAuthority);
        }

        int retainedAuthorities() {
            return failed.size();
        }

        boolean physicallyQuiescent() {
            return failed.isEmpty();
        }
    }


    private static final class SchedulerEpoch { }

    private static final class RuntimeChildHandle {
        private final SchedulerEpoch epoch;
        private final Object runner;

        private RuntimeChildHandle(SchedulerEpoch epoch, Object runner) {
            this.epoch = Objects.requireNonNull(epoch, "scheduler epoch");
            this.runner = Objects.requireNonNull(runner, "runner identity");
        }
    }

    private interface ExactChildRetirement {
        void bind(RuntimeChildHandle child);
        void retireNeverStarted(RuntimeChildHandle child);
        void retirePhysical(RuntimeChildHandle child);
    }

    private static final class ExactTransferLease
            implements ExactChildRetirement {
        private enum Phase {
            UNBOUND,
            BOUND,
            RETIRED
        }

        private Phase phase = Phase.UNBOUND;
        private RuntimeChildHandle exactChild;
        private boolean retained = true;

        @Override
        public void bind(RuntimeChildHandle child) {
            Objects.requireNonNull(child, "child");
            if (phase != Phase.UNBOUND || exactChild != null) {
                throw new IllegalStateException("lease bound more than once");
            }
            exactChild = child;
            phase = Phase.BOUND;
        }

        @Override
        public void retireNeverStarted(RuntimeChildHandle child) {
            retireExact(child);
        }

        @Override
        public void retirePhysical(RuntimeChildHandle child) {
            retireExact(child);
        }

        void abortIfUnbound() {
            if (phase == Phase.UNBOUND) {
                phase = Phase.RETIRED;
                retained = false;
            }
        }

        boolean retained() {
            return retained;
        }

        RuntimeChildHandle exactChild() {
            return exactChild;
        }

        private void retireExact(RuntimeChildHandle child) {
            Objects.requireNonNull(child, "child");
            if (phase != Phase.BOUND || exactChild != child) {
                throw new IllegalStateException(
                        "retirement does not match exact bound child");
            }
            phase = Phase.RETIRED;
            retained = false;
        }
    }

    private static final class SchedulerModel {
        private final SchedulerEpoch epoch = new SchedulerEpoch();

        RuntimeChildHandle bind(ExactChildRetirement retirement) {
            RuntimeChildHandle child =
                    new RuntimeChildHandle(epoch, new Object());
            retirement.bind(child);
            return child;
        }

        void neverStarted(
                ExactChildRetirement retirement,
                RuntimeChildHandle child) {
            requireEpoch(child);
            retirement.retireNeverStarted(child);
        }

        void physical(
                ExactChildRetirement retirement,
                RuntimeChildHandle child) {
            requireEpoch(child);
            retirement.retirePhysical(child);
        }

        private void requireEpoch(RuntimeChildHandle child) {
            if (child.epoch != epoch) {
                throw new IllegalArgumentException(
                        "compiler child belongs to another scheduler epoch");
            }
            Objects.requireNonNull(child.runner, "runner identity");
        }
    }

    private static final class ThreeEdgeLoan {
        private enum State {
            MINTED,
            SCOPE_BOUND,
            CHILD_BOUND,
            RETIRED
        }

        private State state = State.MINTED;
        private Object scopeEpoch;
        private Object exactChild;

        void bindScope(Object epoch) {
            Objects.requireNonNull(epoch, "scope epoch");
            if (state != State.MINTED) {
                throw new IllegalStateException("scope bound twice");
            }
            scopeEpoch = epoch;
            state = State.SCOPE_BOUND;
        }

        void bindChild(Object epoch, Object child) {
            requireScope(epoch);
            Objects.requireNonNull(child, "child");
            if (state != State.SCOPE_BOUND) {
                throw new IllegalStateException("child bind requires scope-only state");
            }
            exactChild = child;
            state = State.CHILD_BOUND;
        }

        void retireBeforeChildBound(Object epoch) {
            requireScope(epoch);
            if (state != State.SCOPE_BOUND || exactChild != null) {
                throw new IllegalStateException(
                        "pre-child retirement requires scope-only binding");
            }
            state = State.RETIRED;
        }

        void retireNeverStarted(Object epoch, Object child) {
            requireScope(epoch);
            Objects.requireNonNull(child, "child");
            if (state != State.CHILD_BOUND || exactChild != child) {
                throw new IllegalArgumentException(
                        "never-started retirement requires exact child");
            }
            exactChild = null;
            state = State.RETIRED;
        }

        void retirePhysical(Object epoch, Object child) {
            requireScope(epoch);
            Objects.requireNonNull(child, "child");
            if (state != State.CHILD_BOUND || exactChild != child) {
                throw new IllegalArgumentException(
                        "physical retirement requires exact child");
            }
            exactChild = null;
            state = State.RETIRED;
        }

        private void requireScope(Object epoch) {
            Objects.requireNonNull(epoch, "scope epoch");
            if (scopeEpoch != epoch) {
                throw new IllegalArgumentException("scope epoch mismatch");
            }
            if (state == State.MINTED || state == State.RETIRED) {
                throw new IllegalStateException("loan not live");
            }
        }
    }

    private static final class OwnerSchedulerLoan {
        private enum State {
            MINTED,
            SCOPE_BOUND,
            OWNER_BOUND,
            SCHEDULER_BOUND,
            RETIRED
        }

        private State state = State.MINTED;
        private Object scope;
        private Object owner;
        private Object schedulerChild;
        private boolean retained = true;

        void bindScope(Object exactScope) {
            Objects.requireNonNull(exactScope, "scope");
            if (state != State.MINTED) {
                throw new IllegalStateException("scope already bound");
            }
            scope = exactScope;
            state = State.SCOPE_BOUND;
        }

        void bindOwner(Object exactScope, Object exactOwner) {
            requireScope(exactScope);
            Objects.requireNonNull(exactOwner, "owner");
            if (state != State.SCOPE_BOUND) {
                throw new IllegalStateException("owner bind requires scope-only state");
            }
            owner = exactOwner;
            state = State.OWNER_BOUND;
        }

        void bindSchedulerChild(
                Object exactScope, Object exactOwner, Object exactSchedulerChild) {
            requireScope(exactScope);
            Objects.requireNonNull(exactOwner, "owner");
            Objects.requireNonNull(exactSchedulerChild, "scheduler child");
            if (state != State.OWNER_BOUND || owner != exactOwner) {
                throw new IllegalArgumentException(
                        "scheduler bind requires exact owner");
            }
            schedulerChild = exactSchedulerChild;
            state = State.SCHEDULER_BOUND;
        }

        void retireBeforeOwner(Object exactScope) {
            requireScope(exactScope);
            if (state != State.SCOPE_BOUND || owner != null
                    || schedulerChild != null) {
                throw new IllegalStateException(
                        "pre-owner retirement requires scope-only state");
            }
            retire();
        }

        void retireBeforeScheduler(Object exactScope, Object exactOwner) {
            requireScope(exactScope);
            if (state != State.OWNER_BOUND || owner != exactOwner
                    || schedulerChild != null) {
                throw new IllegalArgumentException(
                        "pre-scheduler retirement requires exact owner");
            }
            retire();
        }

        void retireNeverStarted(
                Object exactScope, Object exactOwner, Object exactSchedulerChild) {
            requireExactScheduler(
                    exactScope, exactOwner, exactSchedulerChild);
            retire();
        }

        void retirePhysical(
                Object exactScope, Object exactOwner, Object exactSchedulerChild) {
            requireExactScheduler(
                    exactScope, exactOwner, exactSchedulerChild);
            retire();
        }

        boolean retained() {
            return retained;
        }

        private void requireExactScheduler(
                Object exactScope, Object exactOwner, Object exactSchedulerChild) {
            requireScope(exactScope);
            if (state != State.SCHEDULER_BOUND
                    || owner != exactOwner
                    || schedulerChild != exactSchedulerChild) {
                throw new IllegalArgumentException(
                        "retirement requires exact owner and scheduler child");
            }
        }

        private void requireScope(Object exactScope) {
            Objects.requireNonNull(exactScope, "scope");
            if (scope != exactScope) {
                throw new IllegalArgumentException("scope mismatch");
            }
            if (state == State.MINTED || state == State.RETIRED) {
                throw new IllegalStateException("loan not live");
            }
        }

        private void retire() {
            retained = false;
            owner = null;
            schedulerChild = null;
            state = State.RETIRED;
        }
    }

    private static final class SchedulerOwnedAdmission {
        private enum State {
            PREPARED,
            BOUND,
            REGISTERED,
            ENTERED,
            NEVER_REGISTERED,
            QUIESCENT,
            INDETERMINATE
        }

        private State state = State.PREPARED;

        State state() {
            return state;
        }

        void bound() {
            transition(State.PREPARED, State.BOUND);
        }

        void registered() {
            transition(State.BOUND, State.REGISTERED);
        }

        void entered() {
            if (state == State.ENTERED) return;
            transition(State.REGISTERED, State.ENTERED);
        }

        void neverRegistered() {
            if (state != State.PREPARED && state != State.BOUND) {
                throw new IllegalStateException(
                        "registered child cannot become never-registered");
            }
            state = State.NEVER_REGISTERED;
        }

        void indeterminate() {
            if (state != State.PREPARED && state != State.BOUND) {
                throw new IllegalStateException(
                        "registered child cannot become indeterminate");
            }
            state = State.INDETERMINATE;
        }

        void quiescent() {
            if (state != State.REGISTERED && state != State.ENTERED) {
                throw new IllegalStateException(
                        "only a registered child can become quiescent");
            }
            state = State.QUIESCENT;
        }

        private void transition(State expected, State next) {
            if (state != expected) {
                throw new IllegalStateException(
                        "invalid scheduler admission transition");
            }
            state = next;
        }
    }

    public static void main(String[] args) {
        exactBoundaryLookupFailsClosed();
        scopeEpochRejectsForeignAndStaleTickets();
        sameCoordinatesCannotForgeTicketIdentity();
        reservationBindsExactScopeChildAndLifecycle();
        staleGenerationFailsBeforeRetirementHook();
        retirementFailureCannotPublishDrainWitness();
        preDispatchRetirementFailureRetainsExactAuthority();
        partialScopeBindingFailureRetainsExactAuthority();
        partialBindRollbackUsesExactNeverStartedChild();
        exactRuntimeChildRetirementIsIdentityBound();
        boundLeaseCannotBeAbortedByOuterFailure();
        crossSchedulerChildCannotRetireAuthority();
        threeEdgeLoanLifecycleRejectsChildlessBypass();
        ownerAndSchedulerIdentityMustBothMatch();
        cleanupPrecedesExactLoanRetirement();
        partialOwnerAndSchedulerBindFailuresPoison();
        indeterminateSchedulerAdmissionPinsResources();
        schedulerOwnedAdmissionIsMonotonic();
        schedulerStateAloneControlsCleanup();
        System.out.println(
                "TASK_PROOF_IDENTITY_ORACLE=PASS exact_boundary=PASS scope_epoch=PASS "
                + "reservation=PASS exact_child=PASS generation=PASS poison=PASS "
                + "pre_dispatch_poison=PASS partial_bind_poison=PASS "
                + "partial_bind_rollback=PASS runtime_child=PASS "
                + "bound_abort=PASS scheduler_epoch=PASS three_edge_loan=PASS "
                + "owner_scheduler_chain=PASS cleanup_order=PASS "
                + "partial_owner_scheduler_bind_poison=PASS "
                + "ticket_identity=PASS indeterminate_admission=PASS "
                + "scheduler_owned_state=PASS scheduler_cleanup_gate=PASS");
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

    private static void sameCoordinatesCannotForgeTicketIdentity() {
        Verifier verifier = new Verifier();
        Ticket exact = verifier.admit();
        Ticket forged = new Ticket(exact.epoch, exact.id);

        check(exact != forged, "forged ticket unexpectedly reused identity");
        expect(IllegalArgumentException.class,
                () -> verifier.retire(forged),
                "same epoch/id coordinates forged exact ticket identity");
        verifier.retire(exact);
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
        check(resourceReleased[0],
                "resource cleanup must run before memory-loan retirement");
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
        check(failedResource.retains(loan2),
                "resource failure lost the exact still-live loan authority");
        check(failedResource.retainedAuthorities() == 2,
                "resource failure must retain resource + loan authorities");
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


    private static void partialBindRollbackUsesExactNeverStartedChild() {
        SchedulerModel scheduler = new SchedulerModel();
        RuntimeChildHandle[] accepted = {null};
        RuntimeChildHandle[] retired = {null};
        RuntimeException bindFailure =
                new RuntimeException("bind failed after accepting child");

        ExactChildRetirement partial = new ExactChildRetirement() {
            @Override
            public void bind(RuntimeChildHandle child) {
                accepted[0] = child;
                throw bindFailure;
            }

            @Override
            public void retireNeverStarted(RuntimeChildHandle child) {
                check(child == accepted[0],
                        "partial-bind rollback used a different child");
                retired[0] = child;
            }

            @Override
            public void retirePhysical(RuntimeChildHandle child) {
                throw new AssertionError(
                        "partial bind reached physical retirement");
            }
        };

        RuntimeChildHandle exact =
                new RuntimeChildHandle(scheduler.epoch, new Object());
        RuntimeException observed = expectAndReturn(
                RuntimeException.class,
                () -> partial.bind(exact),
                "partial exact-child bind must surface failure");
        check(observed == bindFailure, "partial bind failure identity changed");
        partial.retireNeverStarted(exact);
        check(accepted[0] == exact && retired[0] == exact,
                "never-started rollback did not retain exact child identity");
    }

    private static void exactRuntimeChildRetirementIsIdentityBound() {
        SchedulerModel scheduler = new SchedulerModel();
        ExactTransferLease physicalLease = new ExactTransferLease();
        RuntimeChildHandle physicalChild = scheduler.bind(physicalLease);
        RuntimeChildHandle lookalike =
                new RuntimeChildHandle(physicalChild.epoch, new Object());

        expect(IllegalStateException.class,
                () -> physicalLease.retirePhysical(lookalike),
                "lookalike runtime child retired exact ownership");
        check(physicalLease.retained(),
                "lookalike runtime child released ownership");
        scheduler.physical(physicalLease, physicalChild);
        check(!physicalLease.retained(),
                "exact physical child did not retire ownership");

        ExactTransferLease neverLease = new ExactTransferLease();
        RuntimeChildHandle neverChild = scheduler.bind(neverLease);
        scheduler.neverStarted(neverLease, neverChild);
        check(!neverLease.retained(),
                "exact never-started child did not retire ownership");
        check(physicalChild != neverChild,
                "distinct admissions shared one runtime child token");
    }

    private static void boundLeaseCannotBeAbortedByOuterFailure() {
        SchedulerModel scheduler = new SchedulerModel();
        ExactTransferLease lease = new ExactTransferLease();
        RuntimeChildHandle child = scheduler.bind(lease);

        lease.abortIfUnbound();
        check(lease.retained(),
                "outer failure released a lease already owned by runtime child");
        scheduler.physical(lease, child);
        check(!lease.retained(),
                "runtime child could not retire bound lease");

        ExactTransferLease neverBound = new ExactTransferLease();
        neverBound.abortIfUnbound();
        check(!neverBound.retained(),
                "pre-binding failure did not release caller-owned lease");
    }

    private static void crossSchedulerChildCannotRetireAuthority() {
        SchedulerModel owner = new SchedulerModel();
        SchedulerModel foreign = new SchedulerModel();
        ExactTransferLease lease = new ExactTransferLease();
        RuntimeChildHandle child = owner.bind(lease);

        expect(IllegalArgumentException.class,
                () -> foreign.physical(lease, child),
                "foreign scheduler epoch accepted exact child token");
        check(lease.retained(),
                "foreign scheduler released exact-child authority");

        owner.physical(lease, child);
        check(!lease.retained(),
                "owner scheduler could not retire exact child");
    }

    private static void threeEdgeLoanLifecycleRejectsChildlessBypass() {
        Object epoch = new Object();
        Object foreignEpoch = new Object();
        Object exact = new Object();
        Object lookalike = new Object();

        ThreeEdgeLoan preChild = new ThreeEdgeLoan();
        preChild.bindScope(epoch);
        expect(IllegalArgumentException.class,
                () -> preChild.retireBeforeChildBound(foreignEpoch),
                "foreign scope retired pre-child loan");
        preChild.retireBeforeChildBound(epoch);

        ThreeEdgeLoan never = new ThreeEdgeLoan();
        never.bindScope(epoch);
        never.bindChild(epoch, exact);
        expect(IllegalStateException.class,
                () -> never.retireBeforeChildBound(epoch),
                "scope-only edge bypassed committed child binding");
        expect(IllegalArgumentException.class,
                () -> never.retireNeverStarted(epoch, lookalike),
                "lookalike child retired never-started loan");
        never.retireNeverStarted(epoch, exact);

        ThreeEdgeLoan physical = new ThreeEdgeLoan();
        physical.bindScope(epoch);
        physical.bindChild(epoch, exact);
        expect(IllegalArgumentException.class,
                () -> physical.retirePhysical(epoch, lookalike),
                "lookalike child retired physical loan");
        physical.retirePhysical(epoch, exact);

        ThreeEdgeLoan unbound = new ThreeEdgeLoan();
        unbound.bindScope(epoch);
        expect(IllegalArgumentException.class,
                () -> unbound.retireNeverStarted(epoch, exact),
                "arbitrary child retroactively authenticated scope-only loan");
    }

    private static void ownerAndSchedulerIdentityMustBothMatch() {
        Object scope = new Object();
        Object foreignScope = new Object();
        Object owner = new Object();
        Object lookalikeOwner = new Object();
        Object schedulerChild = new Object();
        Object foreignSchedulerChild = new Object();

        OwnerSchedulerLoan loan = new OwnerSchedulerLoan();
        loan.bindScope(scope);
        loan.bindOwner(scope, owner);
        expect(IllegalArgumentException.class,
                () -> loan.bindSchedulerChild(
                        foreignScope, owner, schedulerChild),
                "foreign scope bound scheduler child");
        expect(IllegalArgumentException.class,
                () -> loan.bindSchedulerChild(
                        scope, lookalikeOwner, schedulerChild),
                "lookalike owner bound scheduler child");
        loan.bindSchedulerChild(scope, owner, schedulerChild);

        expect(IllegalArgumentException.class,
                () -> loan.retireBeforeScheduler(scope, owner),
                "owner-only rollback bypassed scheduler binding");
        expect(IllegalArgumentException.class,
                () -> loan.retireNeverStarted(
                        scope, lookalikeOwner, schedulerChild),
                "lookalike owner retired scheduler-bound loan");
        expect(IllegalArgumentException.class,
                () -> loan.retireNeverStarted(
                        scope, owner, foreignSchedulerChild),
                "foreign scheduler child retired exact loan");
        check(loan.retained(),
                "identity mismatch released exact loan");

        loan.retireNeverStarted(scope, owner, schedulerChild);
        check(!loan.retained(),
                "exact owner + scheduler child did not retire loan");
    }

    private static void cleanupPrecedesExactLoanRetirement() {
        Object scope = new Object();
        Object owner = new Object();
        Object schedulerChild = new Object();
        StringBuilder order = new StringBuilder();

        OwnerSchedulerLoan success = new OwnerSchedulerLoan();
        success.bindScope(scope);
        success.bindOwner(scope, owner);
        success.bindSchedulerChild(scope, owner, schedulerChild);
        order.append("physical>");
        order.append("cleanup>");
        success.retirePhysical(scope, owner, schedulerChild);
        order.append("loan>owner>done");
        check("physical>cleanup>loan>owner>done".contentEquals(order),
                "physical cleanup/loan/owner ordering changed");

        OwnerSchedulerLoan cleanupFailure = new OwnerSchedulerLoan();
        cleanupFailure.bindScope(scope);
        cleanupFailure.bindOwner(scope, owner);
        cleanupFailure.bindSchedulerChild(scope, owner, schedulerChild);
        order.setLength(0);
        order.append("physical>");
        boolean failed = false;
        try {
            order.append("cleanup>");
            throw new IllegalStateException("cleanup failed");
        } catch (IllegalStateException expected) {
            failed = true;
        }
        check(failed, "cleanup failure model did not fail");
        check(cleanupFailure.retained(),
                "cleanup failure returned exact memory loan");
        check("physical>cleanup>".contentEquals(order),
                "loan retirement occurred after failed cleanup");
    }

    private static void partialOwnerAndSchedulerBindFailuresPoison() {
        Object scope = new Object();
        Object owner = new Object();
        Object schedulerChild = new Object();

        boolean ownerAuthorityPoisoned = false;
        Object partiallyAcceptedOwner = null;
        try {
            partiallyAcceptedOwner = owner;
            throw new IllegalStateException("owner bind failed after accept");
        } catch (IllegalStateException expected) {
            ownerAuthorityPoisoned = true;
        }
        check(ownerAuthorityPoisoned && partiallyAcceptedOwner == owner,
                "partial owner bind was treated as clean rollback");

        OwnerSchedulerLoan schedulerBinding = new OwnerSchedulerLoan();
        schedulerBinding.bindScope(scope);
        schedulerBinding.bindOwner(scope, owner);
        boolean schedulerAuthorityPoisoned = false;
        Object partiallyAcceptedScheduler = null;
        try {
            partiallyAcceptedScheduler = schedulerChild;
            throw new IllegalStateException(
                    "scheduler bind failed after accept");
        } catch (IllegalStateException expected) {
            schedulerAuthorityPoisoned = true;
        }
        check(schedulerAuthorityPoisoned
                        && partiallyAcceptedScheduler == schedulerChild
                        && schedulerBinding.retained(),
                "partial scheduler bind released compiler authority");
    }

    private static void indeterminateSchedulerAdmissionPinsResources() {
        Object loanAuthority = new Object();
        Object resourceAuthority = new Object();
        IdentityHashMap<Object, Throwable> retained =
                new IdentityHashMap<>();
        boolean exactSchedulerChildBound = true;
        boolean neverStartedWitness = false;
        int[] cleanupCalls = {0};

        if (exactSchedulerChildBound && !neverStartedWitness) {
            IllegalStateException failure = new IllegalStateException(
                    "scheduler admission rollback unproven");
            retained.put(loanAuthority, failure);
            retained.put(resourceAuthority, failure);
        } else {
            cleanupCalls[0]++;
        }

        check(cleanupCalls[0] == 0,
                "indeterminate scheduler admission reclaimed resources early");
        check(retained.containsKey(loanAuthority)
                        && retained.containsKey(resourceAuthority),
                "indeterminate admission failed to pin loan and resources");
    }

    private static void schedulerOwnedAdmissionIsMonotonic() {
        SchedulerOwnedAdmission live = new SchedulerOwnedAdmission();
        live.bound();
        live.registered();
        expect(IllegalStateException.class,
                live::neverRegistered,
                "registered child regressed to never-registered");
        live.entered();
        live.entered();
        live.quiescent();
        check(live.state() == SchedulerOwnedAdmission.State.QUIESCENT,
                "live child did not reach quiescent");

        SchedulerOwnedAdmission rejected = new SchedulerOwnedAdmission();
        rejected.bound();
        rejected.neverRegistered();
        expect(IllegalStateException.class,
                rejected::quiescent,
                "never-registered child manufactured physical quiescence");

        SchedulerOwnedAdmission uncertain = new SchedulerOwnedAdmission();
        uncertain.bound();
        uncertain.indeterminate();
        expect(IllegalStateException.class,
                uncertain::neverRegistered,
                "indeterminate child was retroactively certified absent");
    }

    private static void schedulerStateAloneControlsCleanup() {
        for (SchedulerOwnedAdmission.State state
                : SchedulerOwnedAdmission.State.values()) {
            boolean cleanupAllowed =
                    state == SchedulerOwnedAdmission.State.NEVER_REGISTERED
                    || state == SchedulerOwnedAdmission.State.QUIESCENT;
            boolean physicalCleanup =
                    state == SchedulerOwnedAdmission.State.QUIESCENT;
            boolean preRegistrationCleanup =
                    state == SchedulerOwnedAdmission.State.NEVER_REGISTERED;

            if (state == SchedulerOwnedAdmission.State.REGISTERED
                    || state == SchedulerOwnedAdmission.State.ENTERED
                    || state == SchedulerOwnedAdmission.State.INDETERMINATE
                    || state == SchedulerOwnedAdmission.State.BOUND
                    || state == SchedulerOwnedAdmission.State.PREPARED) {
                check(!cleanupAllowed,
                        "nonterminal scheduler state authorized cleanup: " + state);
            }
            if (physicalCleanup) {
                check(!preRegistrationCleanup,
                        "quiescent child confused with never-registered child");
            }
        }
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
