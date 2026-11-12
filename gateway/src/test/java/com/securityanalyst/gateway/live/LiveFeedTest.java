package com.securityanalyst.gateway.live;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.TestCertificate;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.JwtService;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.incident.IncidentService;

/**
 * The live feed on the real HTTPS server, read the way the dashboard reads it. No agent runs
 * (PostgresIntegrationTest points it at a closed port), so a submitted incident goes
 * queued -> investigating -> error, which is three changes to watch for.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class LiveFeedTest extends PostgresIntegrationTest {

    private static final TestCertificate CERTIFICATE = new TestCertificate();
    private static final String ANALYST = "lena.live";
    private static final String VIEWER = "lena.viewer";

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        CERTIFICATE.register(registry);
        // Often, so a browser that has gone is noticed within the test.
        registry.add("live.heartbeat-interval", () -> "200ms");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private LiveUpdates live;

    @Autowired
    private JwtService jwt;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private IncidentService incidents;

    @Autowired
    private TransactionTemplate transaction;

    @Autowired
    private JdbcTemplate jdbc;

    private final HttpClient client = CERTIFICATE.trustingClient();
    private final List<Feed> feeds = new ArrayList<>();
    private User analyst;

    @BeforeEach
    void createUsers() throws Exception {
        deleteWhatThisClassSaved();
        analyst = users.save(new User(ANALYST, passwordEncoder.encode("correct horse battery staple"), Role.ANALYST));
    }

    @AfterEach
    void closeFeedsAndClean() throws Exception {
        feeds.forEach(Feed::close);
        eventually(() -> live.openCount() == 0);
        deleteWhatThisClassSaved();
    }

    private void deleteWhatThisClassSaved() {
        jdbc.update("DELETE FROM incidents WHERE created_by IN (SELECT id FROM app_users WHERE username IN (?, ?))",
                ANALYST, VIEWER);
        jdbc.update("DELETE FROM app_users WHERE username IN (?, ?)", ANALYST, VIEWER);
    }

    // ------------------------------------------------------------------ helpers

    private URI url(String path) {
        return URI.create("https://localhost:" + port + path);
    }

    private HttpRequest.Builder feedRequest(String token) {
        HttpRequest.Builder request = HttpRequest.newBuilder(url("/api/incidents/events"))
                .header("Accept", "text/event-stream");
        return token == null ? request : request.header("Cookie", AuthCookies.ACCESS_TOKEN + "=" + token);
    }

    /** One open feed. Its lines are collected in the background, as they arrive. */
    private final class Feed {

        final HttpResponse<Stream<String>> response;
        final BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        final CompletableFuture<Void> ended;

        Feed(String token) throws Exception {
            response = client.send(feedRequest(token).build(), HttpResponse.BodyHandlers.ofLines());
            ended = CompletableFuture.runAsync(() -> {
                try {
                    response.body().forEach(lines::add);
                } catch (RuntimeException e) {
                    // Closed by the test.
                }
            });
            feeds.add(this);
        }

        /** The incident numbers announced, up to and including the wanted one. */
        List<Long> incidentsUntil(long wanted) throws InterruptedException {
            List<Long> seen = new ArrayList<>();
            String event = null;
            Instant giveUp = Instant.now().plusSeconds(10);
            while (!seen.contains(wanted)) {
                String line = lines.poll(Duration.between(Instant.now(), giveUp).toMillis(), TimeUnit.MILLISECONDS);
                assertThat(line).as("incident %s announced within 10 s; saw %s", wanted, seen).isNotNull();
                if (line.startsWith("event:")) {
                    event = line.substring(6).trim();
                } else if (line.startsWith("data:") && "incident".equals(event)) {
                    seen.add(Long.parseLong(line.substring(5).trim()));
                }
            }
            return seen;
        }

        void awaitReady() throws InterruptedException {
            String line;
            do {
                line = lines.poll(5, TimeUnit.SECONDS);
                assertThat(line).as("the feed said it was ready").isNotNull();
            } while (!line.replace(" ", "").equals("event:ready"));
        }

        /** The whole answer of a refusal, which ends at once. Never used on an open feed. */
        String text() throws Exception {
            ended.get(5, TimeUnit.SECONDS);
            return String.join("\n", lines);
        }

        void close() {
            response.body().close();
        }
    }

    private static void eventually(BooleanSupplier condition) throws InterruptedException {
        Instant giveUp = Instant.now().plusSeconds(10);
        while (!condition.getAsBoolean()) {
            assertThat(Instant.now()).as("waited 10 s").isBefore(giveUp);
            Thread.sleep(25);
        }
    }

    private long submitIncident() throws Exception {
        HttpResponse<String> created = client.send(HttpRequest.newBuilder(url("/api/incidents"))
                .header("Cookie", AuthCookies.ACCESS_TOKEN + "=" + jwt.issue(analyst))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("""
                        {"kind": "email", "subjectIdentity": "priya.sharma", "sender": "security@paypa1.example",
                         "subject": "Account locked", "body": "Verify your password"}
                        """))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(created.statusCode()).isEqualTo(202);
        return ((Number) JsonPath.read(created.body(), "$.id")).longValue();
    }

    private void awaitSettled(long incidentId) throws InterruptedException {
        eventually(() -> "error".equals(
                jdbc.queryForObject("SELECT status FROM incidents WHERE id = ?", String.class, incidentId)));
    }

    /** An access token for this user that expires after the given time, signed with the test run's key. */
    private String tokenExpiringIn(User user, Duration lifetime) {
        var key = new SecretKeySpec(Base64.getDecoder().decode(TEST_JWT_KEY), "HmacSHA256");
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder().subject(String.valueOf(user.getId()))
                .claim("username", user.getUsername()).claim("role", user.getRole().name())
                .issuedAt(now.minusSeconds(60)).expiresAt(now.plus(lifetime)).build();
        return new NimbusJwtEncoder(new ImmutableSecret<>(key))
                .encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    /** The gateway's own error lines (the embedded database prints the word ERROR when it starts). */
    private static void assertNothingWentWrong(CapturedOutput output) {
        assertThat(output.getAll()).doesNotContain(" ERROR [trace=").doesNotContain("AccessDenied")
                .doesNotContain("AuthorizationDenied");
    }

    // ------------------------------------------------------------------ tests

    @Test
    void theFeedNeedsALogin() throws Exception {
        Feed refused = new Feed(null);

        assertThat(refused.response.statusCode()).isEqualTo(401);
        assertThat(refused.text()).contains("Authentication required");
        assertThat(live.openCount()).isZero();
    }

    @Test
    void aForgedTokenIsRefused() throws Exception {
        String token = jwt.issue(analyst);
        String forged = token.substring(0, token.length() - 4) + (token.endsWith("AAAA") ? "BBBB" : "AAAA");

        assertThat(new Feed(forged).response.statusCode()).isEqualTo(401);
    }

    @Test
    void anyLoggedInUserIsToldWhenAnIncidentChanges(CapturedOutput output) throws Exception {
        User viewer = users.save(new User(VIEWER, passwordEncoder.encode("correct horse battery staple"), Role.VIEWER));
        Feed feed = new Feed(jwt.issue(viewer));
        assertThat(feed.response.statusCode()).isEqualTo(200);
        assertThat(feed.response.headers().firstValue("Content-Type")).hasValueSatisfying(
                type -> assertThat(type).startsWith("text/event-stream"));
        assertThat(feed.response.headers().firstValue("X-Content-Type-Options")).hasValue("nosniff");
        feed.awaitReady();

        long id = submitIncident();

        assertThat(feed.incidentsUntil(id)).containsOnly(id);
        awaitSettled(id);
        assertNothingWentWrong(output);
    }

    @Test
    void aChangeThatIsRolledBackIsNeverAnnounced() throws Exception {
        long undone = submitIncident();
        long kept = submitIncident();
        awaitSettled(undone);
        awaitSettled(kept);
        Feed feed = new Feed(jwt.issue(analyst));
        feed.awaitReady();

        transaction.executeWithoutResult(status -> {
            incidents.updateStatus(undone, "needs_review");
            status.setRollbackOnly();
        });
        transaction.executeWithoutResult(status -> incidents.updateStatus(kept, "needs_review"));

        // Announcements keep their order, so had the first been sent it would come before the second.
        assertThat(feed.incidentsUntil(kept)).containsExactly(kept);
    }

    @Test
    void aChangeIsAnnouncedOnlyOnceItIsCommitted() throws Exception {
        long id = submitIncident();
        awaitSettled(id);
        List<String> sent = new java.util.concurrent.CopyOnWriteArrayList<>();
        LiveUpdates.Subscriber subscriber = live.subscribe(-1L, "203.0.113.1", new LiveUpdates.Sink() {
            @Override
            public void ready() {
            }

            @Override
            public void changed(long incidentId) {
                sent.add("incident " + incidentId);
            }

            @Override
            public void heartbeat() {
            }

            @Override
            public void close() {
            }
        });
        try {
            transaction.executeWithoutResult(status -> {
                incidents.updateStatus(id, "needs_review");
                try {
                    Thread.sleep(200);   // time for a premature announcement to show up
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                assertThat(sent).as("nothing announced before the commit").isEmpty();
            });
            eventually(() -> sent.contains("incident " + id));
        } finally {
            subscriber.close();
        }
    }

    @Test
    void theFeedEndsWhenTheLoginBehindItExpires(CapturedOutput output) throws Exception {
        String token = tokenExpiringIn(analyst, Duration.ofSeconds(2));
        // Tokens store their expiry in whole seconds, so this is 1 to 2 seconds away: read the real moment.
        Instant expiry = jwt.expiryOf(token).orElseThrow();
        Feed feed = new Feed(token);
        assertThat(feed.response.statusCode()).isEqualTo(200);
        feed.awaitReady();

        feed.ended.get(10, TimeUnit.SECONDS);

        // Not before the token expired (allowing for timer rounding), and not long after.
        assertThat(Instant.now()).isBetween(expiry.minusMillis(100), expiry.plusSeconds(3));
        eventually(() -> live.openCount() == 0);
        // Reconnecting with the same, now expired, token is refused.
        assertThat(new Feed(tokenExpiringIn(analyst, Duration.ofSeconds(-1))).response.statusCode()).isEqualTo(401);
        assertNothingWentWrong(output);
    }

    @Test
    void oneUserMayOnlyHaveThreeFeeds() throws Exception {
        String token = jwt.issue(analyst);
        for (int i = 0; i < 3; i++) {
            new Feed(token).awaitReady();
        }

        // Opened as a feed, so that if it were wrongly let through, the test fails at once instead of
        // waiting for a body that never ends.
        Feed fourth = new Feed(token);

        assertThat(fourth.response.statusCode()).isEqualTo(429);
        assertThat(fourth.text()).contains("Too many dashboard tabs");
        assertThat(live.openCount()).isEqualTo(3);
    }

    @Test
    void aBrowserThatLeavesIsForgotten(CapturedOutput output) throws Exception {
        Feed feed = new Feed(jwt.issue(analyst));
        feed.awaitReady();
        assertThat(live.openCount()).isEqualTo(1);

        feed.close();

        // The next keep-alive write fails, and the feed is closed and forgotten.
        eventually(() -> live.openCount() == 0);
        Thread.sleep(500);
        assertNothingWentWrong(output);
    }
}
