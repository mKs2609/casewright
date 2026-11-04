package com.securityanalyst.gateway.live;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.common.ApiException;

/**
 * The live feed (ADR-49): tells every open dashboard which incident changed, once the change is
 * committed. It sends incident numbers only, never content. The dashboard fetches the incident
 * through the ordinary API, so attacker-written text has no second way to the page, and a missed
 * message costs nothing more than a reload.
 *
 * Every change to an incident writes an audit entry in the same transaction (ADR-46), so listening
 * to the audit log catches every kind of change, including ones added later.
 */
@Component
@EnableConfigurationProperties(LiveProperties.class)
public class LiveUpdates {

    /** Where one feed's messages go: the open response in production, a list in tests. */
    public interface Sink {

        void ready() throws IOException;

        void changed(long incidentId) throws IOException;

        void heartbeat() throws IOException;

        void close();
    }

    private final LiveProperties settings;
    private final Set<Subscriber> open = ConcurrentHashMap.newKeySet();

    public LiveUpdates(LiveProperties settings) {
        this.settings = settings;
    }

    /** Opens a feed for this user, or refuses if they (or everyone together) already have too many. */
    public Subscriber subscribe(Long userId, Sink sink) {
        Subscriber subscriber;
        // One at a time, so two requests arriving together cannot both take the last place.
        synchronized (open) {
            if (open.size() >= settings.maxConnections()) {
                throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "Live updates are busy. Use Refresh for now.");
            }
            if (open.stream().filter(s -> s.userId.equals(userId)).count() >= settings.maxConnectionsPerUser()) {
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS,
                        "Too many dashboard tabs have live updates. Close one, or use Refresh.");
            }
            subscriber = new Subscriber(userId, sink);
            open.add(subscriber);
        }
        subscriber.wake();
        return subscriber;
    }

    /**
     * AFTER_COMMIT: a change that was rolled back is never announced, and a dashboard that reloads
     * at once is sure to see it. This runs on the thread that committed, so it only queues.
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    void onRecorded(AuditLog.Recorded entry) {
        if (entry.incidentId() != null) {
            open.forEach(subscriber -> subscriber.changed(entry.incidentId()));
        }
    }

    @Scheduled(fixedDelayString = "${live.heartbeat-interval}")
    void heartbeat() {
        open.forEach(Subscriber::heartbeatDue);
    }

    int openCount() {
        return open.size();
    }

    /**
     * One open feed. Changes queue up here and are written by a thread of its own, so a slow or
     * vanished browser never holds up the investigation or the request that made the change.
     * Repeats are merged: ten changes to incident 58 in a burst become one message.
     */
    public final class Subscriber {

        private final Long userId;
        private final Sink sink;

        // All guarded by "this".
        private final Set<Long> pending = new LinkedHashSet<>();
        private boolean greetingDue = true;
        private boolean heartbeatDue;
        private boolean overloaded;
        private boolean writing;
        private boolean closed;

        private Subscriber(Long userId, Sink sink) {
            this.userId = userId;
            this.sink = sink;
        }

        void changed(Long incidentId) {
            synchronized (this) {
                if (closed) {
                    return;
                }
                pending.add(incidentId);
                // Further behind than this, it is quicker for the dashboard to reconnect and reload.
                overloaded |= pending.size() > settings.maxPendingChanges();
            }
            wake();
        }

        void heartbeatDue() {
            synchronized (this) {
                heartbeatDue = true;
            }
            wake();
        }

        /** Starts the writer unless it is already running: there is never more than one per feed. */
        private void wake() {
            synchronized (this) {
                if (writing || closed) {
                    return;
                }
                writing = true;
            }
            Thread.ofVirtual().name("live-feed").start(this::write);
        }

        private void write() {
            while (true) {
                List<Long> changes;
                boolean greet;
                boolean ping;
                synchronized (this) {
                    if (closed || overloaded) {
                        writing = false;
                        break;
                    }
                    changes = List.copyOf(pending);
                    pending.clear();
                    greet = greetingDue;
                    ping = heartbeatDue && changes.isEmpty() && !greet;
                    greetingDue = false;
                    heartbeatDue = false;
                    if (changes.isEmpty() && !greet && !ping) {
                        writing = false;
                        return;
                    }
                }
                try {
                    if (greet) {
                        sink.ready();
                    }
                    for (Long incidentId : changes) {
                        sink.changed(incidentId);
                    }
                    if (ping) {
                        sink.heartbeat();
                    }
                } catch (IOException | RuntimeException e) {
                    // The browser has gone, or the connection broke. The server already knows, so there is
                    // nothing to close: the feed is only forgotten. A browser still there reconnects.
                    end(false);
                    return;
                }
            }
            close();
        }

        /** Ends the feed. Safe to call more than once, from any thread. */
        public void close() {
            end(true);
        }

        private void end(boolean closeConnection) {
            synchronized (this) {
                if (closed) {
                    return;
                }
                closed = true;
                pending.clear();
            }
            open.remove(this);
            if (closeConnection) {
                sink.close();
            }
        }
    }
}
