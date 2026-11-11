package com.securityanalyst.gateway.live;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.common.ApiException;

/** The live feed's rules, without a server: a fake sink stands in for the browser's connection. */
class LiveUpdatesTest {

    /** At most 2 feeds per user, 3 in total, 5 changes queued per feed. */
    private final LiveUpdates live = new LiveUpdates(new LiveProperties(2, 3, Duration.ofSeconds(25), 5));

    /** Records what it was sent. It can be told to stall (a slow browser) or fail (a vanished one). */
    static final class FakeSink implements LiveUpdates.Sink {

        final List<String> sent = new CopyOnWriteArrayList<>();
        final AtomicInteger closes = new AtomicInteger();
        volatile CountDownLatch stall = new CountDownLatch(0);
        volatile boolean broken;

        @Override
        public void ready() throws IOException {
            write("ready");
        }

        @Override
        public void changed(long incidentId) throws IOException {
            write("incident " + incidentId);
        }

        @Override
        public void heartbeat() throws IOException {
            write(": keep-alive");
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }

        private void write(String message) throws IOException {
            writersAtOnce.accumulateAndGet(writing.incrementAndGet(), Math::max);
            try {
                stall.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                writing.decrementAndGet();
            }
            if (broken) {
                throw new IOException("connection reset");
            }
            sent.add(message);
        }

        /** Writes in progress now, and the most there have ever been at the same time. */
        final AtomicInteger writing = new AtomicInteger();
        final AtomicInteger writersAtOnce = new AtomicInteger();
    }

    private static void changed(LiveUpdates live, Long incidentId) {
        live.onRecorded(new AuditLog.Recorded("incident.status", incidentId));
    }

    private static void eventually(BooleanSupplier condition) throws InterruptedException {
        Instant giveUp = Instant.now().plusSeconds(5);
        while (!condition.getAsBoolean()) {
            assertThat(Instant.now()).as("waited 5 s for the feed").isBefore(giveUp);
            Thread.sleep(10);
        }
    }

    @Test
    void aNewFeedIsGreetedThenToldWhichIncidentsChanged() throws Exception {
        FakeSink sink = new FakeSink();
        live.subscribe(1L, "203.0.113.1", sink);

        changed(live, 58L);
        changed(live, 59L);

        eventually(() -> sink.sent.size() == 3);
        assertThat(sink.sent).containsExactly("ready", "incident 58", "incident 59");
    }

    @Test
    void entriesThatAreNotAboutAnIncidentAreNotSent() throws Exception {
        FakeSink sink = new FakeSink();
        live.subscribe(1L, "203.0.113.1", sink);

        live.onRecorded(new AuditLog.Recorded("auth.login", null));
        changed(live, 58L);

        eventually(() -> sink.sent.size() == 2);
        assertThat(sink.sent).containsExactly("ready", "incident 58");
    }

    @Test
    void repeatedChangesInABurstAreSentOnce() throws Exception {
        FakeSink sink = new FakeSink();
        sink.stall = new CountDownLatch(1);
        live.subscribe(1L, "203.0.113.1", sink);
        eventually(() -> sink.writing.get() == 1);   // the greeting is stuck in a slow browser

        // While the browser is busy, incident 58 changes three times and 59 once.
        changed(live, 58L);
        changed(live, 58L);
        changed(live, 59L);
        changed(live, 58L);
        sink.stall.countDown();

        eventually(() -> sink.sent.size() == 3);
        Thread.sleep(100);
        assertThat(sink.sent).containsExactly("ready", "incident 58", "incident 59");
    }

    @Test
    void oneFeedIsNeverWrittenByTwoThreadsAtOnce() throws Exception {
        // Two writers on one connection could interleave or reorder messages.
        FakeSink sink = new FakeSink();
        sink.stall = new CountDownLatch(1);
        live.subscribe(1L, "203.0.113.1", sink);
        eventually(() -> sink.writing.get() == 1);   // the greeting is stuck in a slow browser

        changed(live, 58L);
        changed(live, 59L);
        Thread.sleep(100);
        sink.stall.countDown();

        eventually(() -> sink.sent.size() == 3);
        assertThat(sink.writersAtOnce).hasValue(1);
        assertThat(sink.sent).containsExactly("ready", "incident 58", "incident 59");
    }

    @Test
    void aSlowBrowserNeverHoldsUpTheCodeThatMadeTheChange() {
        FakeSink slow = new FakeSink();
        slow.stall = new CountDownLatch(1);   // never released during the test
        live.subscribe(1L, "203.0.113.1", slow);

        // The investigation (or a request) commits and announces; it must return at once.
        assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
            for (long id = 1; id <= 4; id++) {
                changed(live, id);
            }
        });
        slow.stall.countDown();
    }

    @Test
    void aFeedThatFallsTooFarBehindIsClosedSoTheDashboardReloadsInstead() throws Exception {
        FakeSink slow = new FakeSink();
        slow.stall = new CountDownLatch(1);
        live.subscribe(1L, "203.0.113.1", slow);

        for (long id = 1; id <= 6; id++) {   // one more than the 5 that may wait
            changed(live, id);
        }
        slow.stall.countDown();

        eventually(() -> slow.closes.get() == 1);
        assertThat(slow.sent).doesNotContain("incident 1", "incident 6");
        assertThat(live.openCount()).isZero();
    }

    @Test
    void aStalledFeedDoesNotDelayTheOthers() throws Exception {
        FakeSink stalled = new FakeSink();
        stalled.stall = new CountDownLatch(1);
        FakeSink quick = new FakeSink();
        live.subscribe(1L, "203.0.113.1", stalled);
        live.subscribe(2L, "203.0.113.1", quick);
        eventually(() -> quick.sent.size() == 1);

        changed(live, 58L);

        eventually(() -> quick.sent.size() == 2);
        assertThat(quick.sent).containsExactly("ready", "incident 58");
        assertThat(stalled.sent).isEmpty();
        stalled.stall.countDown();
    }

    @Test
    void aBrokenConnectionIsForgottenWithoutWritingToItAgain() throws Exception {
        FakeSink sink = new FakeSink();
        live.subscribe(1L, "203.0.113.1", sink);
        eventually(() -> sink.sent.size() == 1);

        sink.broken = true;
        changed(live, 58L);

        eventually(() -> live.openCount() == 0);
        // Closing would write to a connection the server already knows is broken.
        assertThat(sink.closes).hasValue(0);
        changed(live, 59L);
        Thread.sleep(50);
        assertThat(sink.sent).containsExactly("ready");
    }

    @Test
    void aHeartbeatIsSentWhenThereIsNothingElse() throws Exception {
        FakeSink sink = new FakeSink();
        live.subscribe(1L, "203.0.113.1", sink);
        eventually(() -> sink.sent.size() == 1);

        live.heartbeat();

        eventually(() -> sink.sent.size() == 2);
        assertThat(sink.sent).containsExactly("ready", ": keep-alive");
    }

    @Test
    void oneUserMayOnlyHaveSoManyFeeds() {
        live.subscribe(1L, "203.0.113.1", new FakeSink());
        LiveUpdates.Subscriber second = live.subscribe(1L, "203.0.113.1", new FakeSink());

        assertThatThrownBy(() -> live.subscribe(1L, "203.0.113.1", new FakeSink()))
                .isInstanceOfSatisfying(ApiException.class,
                        e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
        // Someone else is not affected, and closing a feed frees its place.
        live.subscribe(2L, "203.0.113.1", new FakeSink());
        second.close();
        assertThat(live.openCount()).isEqualTo(2);
        live.subscribe(1L, "203.0.113.1", new FakeSink());
    }

    @Test
    void thereIsALimitForEveryoneTogether() {
        live.subscribe(1L, "203.0.113.1", new FakeSink());
        live.subscribe(2L, "203.0.113.1", new FakeSink());
        live.subscribe(3L, "203.0.113.1", new FakeSink());

        assertThatThrownBy(() -> live.subscribe(4L, "203.0.113.1", new FakeSink()))
                .isInstanceOfSatisfying(ApiException.class,
                        e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        assertThat(live.openCount()).isEqualTo(3);
    }

    @Test
    void closingTwiceClosesTheConnectionOnce() throws Exception {
        FakeSink sink = new FakeSink();
        LiveUpdates.Subscriber subscriber = live.subscribe(1L, "203.0.113.1", sink);

        subscriber.close();
        subscriber.close();

        assertThat(sink.closes).hasValue(1);
        assertThat(live.openCount()).isZero();
        changed(live, 58L);
        TimeUnit.MILLISECONDS.sleep(50);
        assertThat(sink.sent).doesNotContain("incident 58");
    }

    @Test
    void eachVisitorAddressHasItsOwnPerUserLimitButTheTotalStillHolds() throws Exception {
        // Settings here: 2 feeds per user and address, 3 in total. Everyone is the same (demo) user.
        live.subscribe(7L, "203.0.113.1", new FakeSink());
        live.subscribe(7L, "203.0.113.1", new FakeSink());
        assertThatThrownBy(() -> live.subscribe(7L, "203.0.113.1", new FakeSink()))
                .isInstanceOf(ApiException.class).hasMessageContaining("Too many dashboard tabs");

        // Another visitor on the same account still gets one.
        live.subscribe(7L, "203.0.113.2", new FakeSink());
        assertThat(live.openCount()).isEqualTo(3);

        // The total limit protects the server whoever asks.
        assertThatThrownBy(() -> live.subscribe(7L, "203.0.113.3", new FakeSink()))
                .isInstanceOf(ApiException.class).hasMessageContaining("busy");
    }
}
