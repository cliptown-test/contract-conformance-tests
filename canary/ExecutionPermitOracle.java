package canary;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Independent semantic oracle for linear region execution permits.
 * This does not contain or import Oreslang implementation source.
 */
public final class ExecutionPermitOracle {
    private ExecutionPermitOracle() { }

    private record Access(BitSet bits) {
        Access {
            bits = (BitSet) bits.clone();
        }

        static Access of(int... keys) {
            BitSet bits = new BitSet();
            for (int key : keys) bits.set(key);
            return new Access(bits);
        }

        boolean overlaps(Access other) {
            BitSet copy = (BitSet) bits.clone();
            copy.and(other.bits);
            return !copy.isEmpty();
        }

        Access union(Access other) {
            BitSet copy = (BitSet) bits.clone();
            copy.or(other.bits);
            return new Access(copy);
        }

        boolean same(Access other) {
            return bits.equals(other.bits);
        }
    }

    private static final class Root {
        long generation;
        Root(long generation) { this.generation = generation; }
    }

    private static final class Group {
        final Root root;
        final long generation;
        final Access parentAccess;
        final Group returnGroup;
        final int returnIndex;
        final int count;
        boolean rejoined;

        Group(Root root, long generation, Access parentAccess,
                Group returnGroup, int returnIndex, int count) {
            this.root = root;
            this.generation = generation;
            this.parentAccess = parentAccess;
            this.returnGroup = returnGroup;
            this.returnIndex = returnIndex;
            this.count = count;
        }
    }

    private static final class Permit {
        final Root root;
        final long generation;
        final Access access;
        final Group parent;
        final int index;
        final AtomicBoolean live = new AtomicBoolean(true);

        Permit(Root root, long generation, Access access, Group parent, int index) {
            this.root = root;
            this.generation = generation;
            this.access = access;
            this.parent = parent;
            this.index = index;
        }

        static Permit root(long generation, Access access) {
            Root root = new Root(generation);
            return new Permit(root, generation, access, null, -1);
        }

        boolean isLive() {
            synchronized (root) {
                return live.get() && root.generation == generation;
            }
        }

        List<Permit> split(List<Access> parts) {
            if (parts.isEmpty()) throw new IllegalArgumentException("empty");
            List<Access> copy = List.copyOf(parts);
            Access covered = null;
            for (int i = 0; i < copy.size(); i++) {
                Access part = Objects.requireNonNull(copy.get(i));
                for (int j = 0; j < i; j++) {
                    Access prior = copy.get(j);
                    if (part.overlaps(prior) || prior.overlaps(part)) {
                        throw new IllegalArgumentException("overlap");
                    }
                }
                covered = covered == null ? part : covered.union(part);
            }
            if (!covered.same(access) || !access.same(covered)) {
                throw new IllegalArgumentException("coverage");
            }

            synchronized (root) {
                requireLive();
                live.set(false);
                Group group = new Group(
                        root, generation, access, parent, index, copy.size());
                ArrayList<Permit> children = new ArrayList<>();
                for (int i = 0; i < copy.size(); i++) {
                    children.add(new Permit(root, generation, copy.get(i), group, i));
                }
                return List.copyOf(children);
            }
        }

        static Permit rejoin(List<Permit> siblings) {
            if (siblings.isEmpty()) throw new IllegalArgumentException("empty");
            List<Permit> copy = List.copyOf(siblings);
            Permit first = copy.getFirst();
            Group group = first.parent;
            if (group == null) throw new IllegalArgumentException("root");

            synchronized (group) {
                synchronized (group.root) {
                    if (group.rejoined) throw new IllegalStateException("rejoined");
                    if (copy.size() != group.count) throw new IllegalArgumentException("incomplete");

                    Set<Integer> indexes = new HashSet<>();
                    for (Permit child : copy) {
                        if (child.parent != group
                                || child.root != group.root
                                || child.generation != group.generation) {
                            throw new IllegalArgumentException("lineage");
                        }
                        if (!indexes.add(child.index)) {
                            throw new IllegalArgumentException("duplicate");
                        }
                        child.requireLive();
                    }
                    for (int i = 0; i < group.count; i++) {
                        if (!indexes.contains(i)) throw new IllegalArgumentException("missing");
                    }

                    for (Permit child : copy) child.live.set(false);
                    group.rejoined = true;
                    return new Permit(
                            group.root,
                            group.generation,
                            group.parentAccess,
                            group.returnGroup,
                            group.returnIndex);
                }
            }
        }

        Permit rotate(long next, Access nextAccess) {
            if (!access.same(nextAccess) || !nextAccess.same(access)) {
                throw new IllegalArgumentException("authority");
            }
            synchronized (root) {
                requireLive();
                if (parent != null) throw new IllegalStateException("not root");
                if (next <= generation) throw new IllegalArgumentException("generation");
                live.set(false);
                root.generation = next;
                return new Permit(root, next, nextAccess, null, -1);
            }
        }

        private void requireLive() {
            if (!live.get()) throw new IllegalStateException("consumed");
            if (root.generation != generation) throw new IllegalStateException("stale");
        }
    }

    public static void main(String[] args) throws Exception {
        deterministicContracts();
        nestedLineage();
        concurrentRejoinVsResplit();
        System.out.println(
                "EXECUTION_PERMIT_ORACLE=PASS arbitration_rounds=20000 nested=PASS generation=PASS authority=PASS");
    }

    private static void deterministicContracts() {
        Permit root = Permit.root(4, Access.of(1, 2, 3, 4));
        expectFailure(() -> root.split(List.of(Access.of(1, 2), Access.of(2, 3, 4))));
        check(root.isLive(), "overlap consumed root");
        expectFailure(() -> root.split(List.of(Access.of(1), Access.of(2))));
        check(root.isLive(), "incomplete split consumed root");

        List<Permit> children = root.split(List.of(Access.of(1, 2), Access.of(3, 4)));
        expectFailure(() -> Permit.rejoin(List.of(children.getFirst())));
        check(children.getFirst().isLive(), "failed rejoin consumed child 0");
        check(children.get(1).isLive(), "failed rejoin consumed child 1");

        Permit restored = Permit.rejoin(children);
        expectFailure(() -> restored.rotate(5, Access.of(1, 2, 3, 4, 5)));
        check(restored.isLive(), "rejected authority widening consumed root");
        Permit next = restored.rotate(5, Access.of(1, 2, 3, 4));
        check(!restored.isLive(), "rotated permit remained live");
        check(next.isLive(), "next generation is not live");
        expectFailure(() -> restored.split(List.of(Access.of(1, 2), Access.of(3, 4))));
    }

    private static void nestedLineage() {
        Permit root = Permit.root(9, Access.of(1, 2, 3, 4));
        List<Permit> outer = root.split(List.of(Access.of(1, 2), Access.of(3, 4)));
        List<Permit> inner = outer.getFirst().split(List.of(Access.of(1), Access.of(2)));
        Permit restoredFirst = Permit.rejoin(inner);
        Permit restoredRoot = Permit.rejoin(List.of(restoredFirst, outer.get(1)));
        check(restoredRoot.isLive(), "nested rejoin did not restore root");
    }

    private static void concurrentRejoinVsResplit() throws Exception {
        final int rounds = 20_000;
        AtomicInteger rejoinWins = new AtomicInteger();
        AtomicInteger splitWins = new AtomicInteger();

        try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
            for (int round = 0; round < rounds; round++) {
                Permit root = Permit.root(1, Access.of(1, 2, 3, 4));
                List<Permit> outer = root.split(List.of(Access.of(1, 2), Access.of(3, 4)));
                Permit first = outer.getFirst();
                Permit second = outer.get(1);

                CountDownLatch start = new CountDownLatch(1);
                var rejoined = new java.util.concurrent.atomic.AtomicReference<Permit>();
                var nested = new java.util.concurrent.atomic.AtomicReference<List<Permit>>();

                var a = pool.submit(() -> {
                    await(start);
                    try {
                        rejoined.set(Permit.rejoin(List.of(first, second)));
                        rejoinWins.incrementAndGet();
                    } catch (IllegalStateException ignored) {
                        // child split won
                    }
                });
                var b = pool.submit(() -> {
                    await(start);
                    try {
                        nested.set(first.split(List.of(Access.of(1), Access.of(2))));
                        splitWins.incrementAndGet();
                    } catch (IllegalStateException ignored) {
                        // outer rejoin won
                    }
                });

                start.countDown();
                a.get(5, TimeUnit.SECONDS);
                b.get(5, TimeUnit.SECONDS);

                check((rejoined.get() != null) != (nested.get() != null),
                        "exactly one arbitration path must win");

                if (nested.get() != null) {
                    check(second.isLive(),
                            "failed outer rejoin partially consumed sibling");
                    Permit restoredFirst = Permit.rejoin(nested.get());
                    Permit restored = Permit.rejoin(List.of(restoredFirst, second));
                    check(restored.isLive(), "split-win recovery failed");
                } else {
                    check(rejoined.get().isLive(), "rejoin-win root not live");
                }
            }
        }

        check(rejoinWins.get() > 0, "rejoin never won arbitration");
        check(splitWins.get() > 0, "split never won arbitration");
        check(rejoinWins.get() + splitWins.get() == rounds,
                "arbitration round count mismatch");
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(interrupted);
        }
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
