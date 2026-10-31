package com.securityanalyst.gateway.auth;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.securityanalyst.gateway.audit.AuditLog;
import com.securityanalyst.gateway.common.ApiException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

/**
 * User management. SecurityConfig restricts everything under /api/admin to the
 * ADMIN role, so no method here needs its own role check.
 */
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final UserRepository users;
    private final SessionService sessionService;
    private final AuditLog audit;

    public AdminUserController(UserRepository users, SessionService sessionService, AuditLog audit) {
        this.users = users;
        this.sessionService = sessionService;
        this.audit = audit;
    }

    public record UserSummary(Long id, String username, Role role, Instant createdAt) {
        static UserSummary from(User user) {
            return new UserSummary(user.getId(), user.getUsername(), user.getRole(), user.getCreatedAt());
        }
    }

    /** A role that is not ADMIN, ANALYST or VIEWER fails JSON parsing and is rejected with 400. */
    public record ChangeRoleRequest(@NotNull(message = "is required") Role role) {
    }

    @GetMapping
    public List<UserSummary> list() {
        return users.findAll(Sort.by("id")).stream().map(UserSummary::from).toList();
    }

    @PutMapping("/{id}/role")
    @Transactional
    public UserSummary changeRole(@PathVariable Long id, @Valid @RequestBody ChangeRoleRequest request,
            @AuthenticationPrincipal AuthenticatedUser admin) {
        if (id.equals(admin.id())) {
            // Stops the last admin from accidentally removing their own access.
            throw new ApiException(HttpStatus.BAD_REQUEST, "You cannot change your own role");
        }
        User user = users.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        audit.record(admin.username(), "auth.role_changed", null, Map.of("user", user.getUsername(),
                "from", user.getRole().name(), "to", request.role().name()));
        user.setRole(request.role());
        // Their current sessions carry the old role, so end them: they must log in again.
        sessionService.endAllFor(user.getId());
        return UserSummary.from(user);
    }
}
