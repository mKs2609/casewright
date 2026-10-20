package com.securityanalyst.gateway.identity;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MonitoredIdentityRepository extends JpaRepository<MonitoredIdentity, String> {
}
