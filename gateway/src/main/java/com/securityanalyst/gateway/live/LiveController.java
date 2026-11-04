package com.securityanalyst.gateway.live;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.auth.JwtService;
import com.securityanalyst.gateway.common.ApiException;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The live feed as Server-Sent Events (ADR-48, ADR-49). Any logged-in user may read incidents,
 * so any logged-in user may follow them. The messages:
 *
 *   event: ready          the feed is open; reload what is on screen, in case something changed meanwhile
 *   event: incident       data is an incident number; that incident changed
 *   : keep-alive          nothing to report (a comment line, which browsers ignore)
 */
@RestController
public class LiveController {

    private final LiveUpdates live;
    private final JwtService jwt;
    private final AuthCookies cookies;

    public LiveController(LiveUpdates live, JwtService jwt, AuthCookies cookies) {
        this.live = live;
        this.jwt = jwt;
        this.cookies = cookies;
    }

    /**
     * The login is checked when the feed opens, and the feed ends when that login's access token
     * expires: an open connection must not outlive the proof it was opened with. The dashboard then
     * renews the session and reconnects, or shows the login screen.
     */
    @GetMapping("/api/incidents/events")
    public SseEmitter events(@AuthenticationPrincipal AuthenticatedUser user, HttpServletRequest request) {
        Instant expiry = jwt.expiryOf(cookies.readAccessToken(request))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required"));
        long remaining = Math.max(1, Duration.between(Instant.now(), expiry).toMillis());

        SseEmitter emitter = new SseEmitter(remaining);
        LiveUpdates.Subscriber subscriber = live.subscribe(user.id(), new EmitterSink(emitter));
        // However it ends (expiry, the browser leaving, a broken connection), it is closed and forgotten.
        emitter.onTimeout(subscriber::close);
        emitter.onCompletion(subscriber::close);
        emitter.onError(failure -> subscriber.close());
        return emitter;
    }

    private record EmitterSink(SseEmitter emitter) implements LiveUpdates.Sink {

        @Override
        public void ready() throws IOException {
            emitter.send(SseEmitter.event().name("ready").data(""));
        }

        @Override
        public void changed(long incidentId) throws IOException {
            emitter.send(SseEmitter.event().name("incident").data(Long.toString(incidentId)));
        }

        @Override
        public void heartbeat() throws IOException {
            emitter.send(SseEmitter.event().comment("keep-alive"));
        }

        @Override
        public void close() {
            emitter.complete();
        }
    }
}
