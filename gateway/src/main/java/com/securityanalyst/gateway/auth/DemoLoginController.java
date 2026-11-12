package com.securityanalyst.gateway.auth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.securityanalyst.gateway.common.ApiException;

import jakarta.servlet.http.HttpServletResponse;

/**
 * "Try the demo" (step 19b, ADR-55): starts a session as the shared demo account, with no password.
 * Exists only when demo.public-login.enabled is on; elsewhere the address answers 404.
 *
 * Same protections as a normal login: the per-address limit for credential requests, the
 * cross-site check (so another website cannot log a visitor in behind their back), an audit entry
 * (SessionService), and the tokens only in cookies.
 */
@RestController
@ConditionalOnProperty(name = "demo.public-login.enabled", havingValue = "true")
public class DemoLoginController {

    private final DemoAccount account;
    private final UserRepository users;
    private final SessionService sessionService;
    private final AuthCookies cookies;

    public DemoLoginController(DemoAccount account, UserRepository users, SessionService sessionService,
            AuthCookies cookies) {
        this.account = account;
        this.users = users;
        this.sessionService = sessionService;
        this.cookies = cookies;
    }

    @PostMapping("/api/auth/demo-login")
    public UserResponse demoLogin(HttpServletResponse response) {
        User user = users.findByUsername(account.username())
                .orElseThrow(() -> new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "The demo is not ready yet. Try again soon."));
        cookies.write(response, sessionService.start(user));
        return UserResponse.from(user);
    }
}
