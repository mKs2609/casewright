package com.securityanalyst.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** If a request object is ever logged, the password must not come along. */
class RequestRecordsTest {

    @Test
    void signupRequestHidesThePasswordWhenPrinted() {
        String printed = new SignupRequest("asha.rao", "correct horse battery staple").toString();
        assertThat(printed).contains("asha.rao").doesNotContain("correct horse");
    }

    @Test
    void loginRequestHidesThePasswordWhenPrinted() {
        String printed = new LoginRequest("asha.rao", "correct horse battery staple").toString();
        assertThat(printed).contains("asha.rao").doesNotContain("correct horse");
    }
}
