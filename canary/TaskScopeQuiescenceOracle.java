package canary;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Independent JDK-only oracle for structured-task cancellation/quiescence.
 * No Oreslang implementation source is copied into this repository.
 */
public final class TaskScopeQuiescenceOracle {
    private TaskScopeQuiescenceOracle() { }

    private static final class ScopePoison extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ScopePoison(Throwable cause) {
            super("structured scope owner finalization poisoned", cause);
        }
    }

    private enum State { PENDING, CANCELLED, SUCCESS }

    private static final class SplitFuture {
        private final AtomicReference<State> state = new AtomicReference<>(State.PENDING);
        private final AtomicBoolean revoked = new AtomicBoolean();
        private final AtomicBoolean published = new AtomicBoolean();
        private final List<Runnable> subscribers = new ArrayList<>();
        private final Runnable revoker;
        private final Runnable terminalReady;

        SplitFuture(Runnable revoker, Runnable terminalReady) {
            this.revoker = Objects.requireNonNull(revoker);
            this.terminalReady = Objects.requireNonNull(terminalReady);
        }

        synchronized void subscribe(Runnable callback) {
            subscribers.add(Objects.requireNonNull(callback));
        }

        Claim claimCancellation() {
            if (!state.compareAndSet(State.PENDING, State.CANCELLED)) return null;
            return new Claim(this);
        }

        boolean completeSuccess() {
            if (!state.compareAndSet(State.PENDING, State.SUCCESS)) return false;
            terminalReady.run();
            publish();
            return true;
        }

        boolean isCancelled() { return state.get() == State.CANCELLED; }
        boolean isRevoked() { return revoked.get(); }

        private void revoke() {
            if (revoked.compareAndSet(false, true)) {
                revoker.run();
                terminalReady.run();
            }
        }

        private void publish() {
            if (!published.compareAndSet(false, true)) return;
            final List<Runnable> copy;
            synchronized (this) {
                copy = List.copyOf(subscribers);
            }
            for (Runnable subscriber : copy) subscriber.run();
        }

        private static final class Claim {
            private final SplitFuture owner;
            private boolean revoked;
            private boolean published;

            Claim(SplitFuture owner) { this.owner = owner; }

            void revoke() {
                if (revoked) return;
                owner.revoke();
                revoked = true;
            }

            void publish() {
                if (!revoked) throw new IllegalStateException("publish before revoke");
                if (published) return;
                owner.publish();
                published = true;
            }
        }
    }

    private static final class Child {
        private final SplitFuture future;
        private boolean quiescent;
        private boolean terminal;

        Child(SplitFuture future) { this.future = future; }
    }

    private static final class Scope {
        private final Object lock = new Object();
        private final List<Child> children = new ArrayList<>();
        private final CountDownLatch drained = new CountDownLatch(1);
        private final AtomicBoolean drainSettled = new AtomicBoolean();
        private final AtomicReference<Throwable> drainFailure = new AtomicReference<>();
        private final Runnable onClosed;
        private boolean sealed;

        Scope() {
            this(() -> { });
        }

        Scope(Runnable onClosed) {
            this.onClosed = Objects.requireNonNull(onClosed);
        }

        Child addChild() {
            return addChild(() -> { });
        }

        Child addChild(Runnable revoker) {
            final Child[] holder = new Child[1];
            SplitFuture future = new SplitFuture(revoker, () -> markTerminal(holder[0]));
            Child child = new Child(future);
            holder[0] = child;
            synchronized (lock) {
                if (sealed) throw new IllegalStateException("sealed");
                children.add(child);
            }
            return child;
        }

        void quiesce() {
            boolean done;
            synchronized (lock) {
                sealed = true;
                done = children.isEmpty();
            }
            if (done) completeDrain();
        }

        void cancelAndQuiesce() {
            final List<SplitFuture> snapshot;
            synchronized (lock) {
                sealed = true;
                snapshot = children.stream().map(c -> c.future).toList();
            }

            ArrayList<SplitFuture.Claim> claims = new ArrayList<>();
            for (SplitFuture future : snapshot) {
                SplitFuture.Claim claim = future.claimCancellation();
                if (claim != null) claims.add(claim);
            }
            for (SplitFuture.Claim claim : claims) claim.revoke();
            for (SplitFuture.Claim claim : claims) {
                Thread.ofVirtual().start(claim::publish);
            }

            synchronized (lock) {
                if (children.isEmpty()) completeDrain();
            }
        }

        void markQuiescent(Child child) {
            boolean done;
            synchronized (lock) {
                child.quiescent = true;
                done = retireIfReady(child);
            }
            if (done) completeDrain();
        }

        private void markTerminal(Child child) {
            boolean done;
            synchronized (lock) {
                child.terminal = true;
                done = retireIfReady(child);
            }
            if (done) completeDrain();
        }

        private boolean retireIfReady(Child child) {
            if (!child.quiescent || !child.terminal) return false;
            children.remove(child);
            return sealed && children.isEmpty();
        }

        boolean awaitDrain(long timeout, TimeUnit unit) throws InterruptedException {
            return drained.await(timeout, unit);
        }

        boolean drainSucceeded() {
            return drainSettled.get() && drainFailure.get() == null;
        }

        Throwable drainFailure() {
            return drainFailure.get();
        }

        private void completeDrain() {
            if (!drainSettled.compareAndSet(false, true)) return;
            try {
                onClosed.run();
            } catch (RuntimeException | Error failure) {
                drainFailure.set(new ScopePoison(failure));
            } finally {
                drained.countDown();
            }
        }

        int activeChildren() {
            synchronized (lock) { return children.size(); }
        }
    }

    public static void main(String[] args) throws Exception {
        twoPhaseRevokesAllBeforeBlockingSubscribers();
        terminalReadyBeatsBlockingSubscriber();
        physicalQuiescenceRemainsRequired();
        nestedCancellationIsTransitive();
        ownerFinalizationFailurePoisonsDrain();
        raceStress();
        System.out.println("TASK_SCOPE_ORACLE=PASS races=50000 blocked_subscribers=3 independent_publish=PASS nested=PASS owner_failure=PASS owner_poison=PASS");
    }

    private static void twoPhaseRevokesAllBeforeBlockingSubscribers() throws Exception {
        Scope scope = new Scope();
        List<Child> children = List.of(scope.addChild(), scope.addChild(), scope.addChild());
        CountDownLatch subscriberEntered = new CountDownLatch(3);
        CountDownLatch releaseSubscribers = new CountDownLatch(1);

        for (Child child : children) {
            child.future.subscribe(() -> {
                subscriberEntered.countDown();
                awaitUninterruptibly(releaseSubscribers);
            });
        }

        Thread canceller = Thread.ofPlatform().start(scope::cancelAndQuiesce);
        check(subscriberEntered.await(5, TimeUnit.SECONDS),
                "all child subscriber paths must begin independently");

        for (Child child : children) {
            check(child.future.isCancelled(), "not every cancellation claim won first");
            check(child.future.isRevoked(), "not every revocation completed first");
        }

        canceller.join(5000);
        check(!canceller.isAlive(),
                "scope cancellation caller was pinned behind ordinary subscribers");
        releaseSubscribers.countDown();
    }

    private static void terminalReadyBeatsBlockingSubscriber() throws Exception {
        Scope scope = new Scope();
        Child child = scope.addChild();
        CountDownLatch subscriberEntered = new CountDownLatch(1);
        CountDownLatch releaseSubscriber = new CountDownLatch(1);

        child.future.subscribe(() -> {
            subscriberEntered.countDown();
            awaitUninterruptibly(releaseSubscriber);
        });

        scope.quiesce();
        scope.markQuiescent(child);
        Thread completer = Thread.ofPlatform().start(child.future::completeSuccess);

        check(subscriberEntered.await(5, TimeUnit.SECONDS), "success subscriber did not block");
        check(scope.awaitDrain(100, TimeUnit.MILLISECONDS),
                "scope accounting was queued behind ordinary subscriber");

        releaseSubscriber.countDown();
        completer.join(5000);
        check(!completer.isAlive(), "success publisher stuck");
    }

    private static void physicalQuiescenceRemainsRequired() throws Exception {
        Scope scope = new Scope();
        Child child = scope.addChild();

        Thread canceller = Thread.ofPlatform().start(scope::cancelAndQuiesce);
        canceller.join(5000);
        check(child.future.isCancelled(), "cancellation claim missing");
        check(child.future.isRevoked(), "cancellation revocation missing");
        check(!scope.awaitDrain(50, TimeUnit.MILLISECONDS),
                "logical cancellation released scope before physical quiescence");

        scope.markQuiescent(child);
        check(scope.awaitDrain(5, TimeUnit.SECONDS),
                "physically quiescent cancelled child did not drain");
    }

    private static void nestedCancellationIsTransitive() throws Exception {
        Scope outer = new Scope();
        Scope inner = new Scope();
        Child grandchild = inner.addChild();
        Child child = outer.addChild(inner::cancelAndQuiesce);

        outer.cancelAndQuiesce();

        check(child.future.isCancelled(), "outer child was not cancelled");
        check(child.future.isRevoked(), "outer child was not revoked");
        check(grandchild.future.isCancelled(), "nested grandchild was not cancelled");
        check(grandchild.future.isRevoked(), "nested grandchild was not revoked");
        check(!outer.awaitDrain(50, TimeUnit.MILLISECONDS),
                "outer scope drained before nested physical quiescence");

        inner.markQuiescent(grandchild);
        check(inner.awaitDrain(5, TimeUnit.SECONDS), "inner scope failed to drain");
        outer.markQuiescent(child);
        check(outer.awaitDrain(5, TimeUnit.SECONDS), "outer scope failed to drain after inner scope");
    }


    private static void ownerFinalizationFailurePoisonsDrain() throws Exception {
        RuntimeException expected = new RuntimeException("owner finalization failed");
        Scope scope = new Scope(() -> { throw expected; });

        scope.quiesce();

        check(scope.awaitDrain(5, TimeUnit.SECONDS),
                "failed owner finalization did not settle drain barrier");
        check(!scope.drainSucceeded(),
                "owner finalization failure incorrectly reported successful drain");
        check(scope.drainFailure() instanceof ScopePoison,
                "owner finalization failure was not promoted to scope poison");
        check(scope.drainFailure().getCause() == expected,
                "scope poison lost owner finalization failure identity");
    }

    private static void raceStress() throws Exception {
        final int rounds = 50_000;
        AtomicInteger completed = new AtomicInteger();
        try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
            for (int i = 0; i < rounds; i++) {
                Scope scope = new Scope();
                Child child = scope.addChild();
                pool.submit(scope::cancelAndQuiesce);
                pool.submit(() -> {
                    scope.markQuiescent(child);
                    completed.incrementAndGet();
                });
                check(scope.awaitDrain(5, TimeUnit.SECONDS), "race did not drain: " + i);
                check(scope.activeChildren() == 0, "race leaked child: " + i);
            }
        }
        check(completed.get() == rounds, "not all quiescence tasks completed");
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        for (;;) {
            try {
                latch.await();
                break;
            } catch (InterruptedException ignored) {
                interrupted = true;
            }
        }
        if (interrupted) Thread.currentThread().interrupt();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
