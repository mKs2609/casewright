package com.securityanalyst.gateway.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

import com.securityanalyst.gateway.common.ApiException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

/**
 * The HTTP side of accounts and sessions. It only translates between HTTP and
 * the services; the rules live in AuthService and SessionService.
 * {@code @Valid} makes Spring check the request record's rules before our code runs.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;
    private final SessionService sessionService;
    private final AuthCookies cookies;

    public AuthController(AuthService authService, SessionService sessionService, AuthCookies cookies) {
        this.authService = authService;
        this.sessionService = sessionService;
        this.cookies = cookies;
    }

    @PostMapping("/auth/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse signup(@Valid @RequestBody SignupRequest request) {
        return UserResponse.from(authService.signup(request));
    }

    /** Checks the password, then starts a session. The tokens go in cookies, never in the response body. */
    @PostMapping("/auth/login")
    public UserResponse login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        User user = authService.login(request);
        cookies.write(response, sessionService.start(user));
        return UserResponse.from(user);
    }

    /** Swaps the refresh token for a fresh pair. Called by the browser when the access token expires. */
    @PostMapping("/auth/refresh")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void refresh(HttpServletRequest request, HttpServletResponse response) {
        try {
            cookies.write(response, sessionService.refresh(cookies.readRefreshToken(request)));
        } catch (ApiException e) {
            cookies.clear(response);
            throw e;
        }
    }

    /** Ends the session on the server AND removes the cookies from the browser. */
    @PostMapping("/auth/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        sessionService.end(cookies.readRefreshToken(request));
        cookies.clear(response);
    }

    /** Who am I? Only reachable with a valid access token. */
    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal AuthenticatedUser user) {
        return new UserResponse(user.username(), user.role());
    }
}
