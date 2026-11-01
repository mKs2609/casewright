package com.securityanalyst.gateway.action;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.securityanalyst.gateway.auth.AuthenticatedUser;
import com.securityanalyst.gateway.common.ApiException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** Listing actions and deciding them. SecurityConfig limits deciding to analysts and admins. */
@RestController
@RequestMapping("/api/actions")
public class ActionController {

    private static final Set<String> STATUSES = Set.of("pending", "executed", "rejected", "expired");
    private static final int MAX_LISTED = 100;

    private final ActionService actions;

    public ActionController(ActionService actions) {
        this.actions = actions;
    }

    public record DecisionRequest(
            @NotNull(message = "is required")
            @Pattern(regexp = "^(approve|reject)$", message = "must be approve or reject")
            String decision) {
    }

    @GetMapping
    public List<ActionService.View> list(@RequestParam(defaultValue = "pending") String status) {
        if (!STATUSES.contains(status)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Unknown status");
        }
        return actions.withStatus(status, MAX_LISTED);
    }

    @PostMapping("/{id}/decision")
    public ActionService.View decide(@PathVariable Long id, @Valid @RequestBody DecisionRequest request,
            @AuthenticationPrincipal AuthenticatedUser user) {
        return actions.decide(id, "approve".equals(request.decision()), user);
    }
}
