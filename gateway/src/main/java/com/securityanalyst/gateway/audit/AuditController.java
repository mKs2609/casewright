package com.securityanalyst.gateway.audit;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.securityanalyst.gateway.common.ApiException;

/** Reading the audit log and checking its chain. Any logged-in user may do both; nobody can change it. */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private static final int MAX_ENTRIES = 500;

    private final AuditLog audit;

    public AuditController(AuditLog audit) {
        this.audit = audit;
    }

    @GetMapping
    public List<AuditLog.Entry> recent(@RequestParam(defaultValue = "100") int limit) {
        if (limit < 1 || limit > MAX_ENTRIES) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "limit must be between 1 and " + MAX_ENTRIES);
        }
        return audit.recent(limit);
    }

    @GetMapping("/verify")
    public AuditLog.Verification verify() {
        return audit.verify();
    }
}
