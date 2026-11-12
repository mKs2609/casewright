package com.securityanalyst.gateway.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.DemoAccount;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;
import com.securityanalyst.gateway.incident.Incident;
import com.securityanalyst.gateway.incident.IncidentRepository;

import jakarta.servlet.http.Cookie;

/**
 * The public demo mode (step 19b, ADR-55), with the settings the public server uses: sign-up closed,
 * "Try the demo" on, incidents of one's own for admins only, and a daily ceiling on demo runs.
 *
 * The demo account itself is created when the application starts (DemoAccount), outside any test's
 * transaction, so it stays in this run's database; everything the tests do is rolled back.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class PublicDemoTest extends PostgresIntegrationTest {

    private static final int RUNS_PER_DAY = 3;
    private static final String PASSWORD = "correct horse battery staple";

    @DynamicPropertySource
    static void thePublicServersSettings(DynamicPropertyRegistry registry) {
        registry.add("security.signup-enabled", () -> false);
        registry.add("demo.public-login.enabled", () -> true);
        registry.add("security.incident-submitter-roles", () -> "ADMIN");
        registry.add("demo.max-runs-per-day", () -> RUNS_PER_DAY);
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private IncidentRepository incidents;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private DemoAccount demoAccount;

    private static final String EMAIL = """
            {"kind": "email", "subjectIdentity": "priya.sharma", "sender": "security@paypa1.example",
             "subject": "Account locked", "body": "Please confirm your password here."}
            """;

    private Cookie tryTheDemo() throws Exception {
        return mvc.perform(post("/api/auth/demo-login"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
    }

    @Test
    void theLoginPageIsToldWhatItMayOffer() throws Exception {
        mvc.perform(get("/api/auth/options"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signupOpen").value(false))
                .andExpect(jsonPath("$.demoLogin").value(true));
    }

    @Test
    void nobodyCanCreateAnAccount() throws Exception {
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"new.visitor\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Sign-up is closed on this site"));

        assertThat(users.existsByUsername("new.visitor")).isFalse();
    }

    @Test
    void tryTheDemoLogsInAsTheSharedAnalystWithNoPassword() throws Exception {
        mvc.perform(post("/api/auth/demo-login"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("demo"))
                .andExpect(jsonPath("$.role").value("ANALYST"))
                // The tokens are in cookies only, as for any login.
                .andExpect(jsonPath("$.accessToken").doesNotExist());

        mvc.perform(get("/api/me").cookie(tryTheDemo()))
                .andExpect(jsonPath("$.username").value("demo"))
                .andExpect(jsonPath("$.role").value("ANALYST"));
    }

    @Test
    void anotherWebsiteCannotLogAVisitorInAsTheDemo() throws Exception {
        mvc.perform(post("/api/auth/demo-login").header("Origin", "https://attacker.example"))
                .andExpect(status().isForbidden());
    }

    @Test
    void theDemoPasswordChangesAtEveryStartAndTheAccountStaysAnAnalyst() throws Exception {
        User account = users.findByUsername("demo").orElseThrow();
        String before = account.getPasswordHash();
        account.setRole(Role.ADMIN);   // as if someone had promoted it

        demoAccount.run(null);         // what every start of the gateway does

        User after = users.findByUsername("demo").orElseThrow();
        assertThat(after.getPasswordHash()).isNotEqualTo(before);
        assertThat(after.getRole()).isEqualTo(Role.ANALYST);
        // Logging in with a password is not a way in: nobody knows it.
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"demo\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theDemoAccountFiresScenariosButCannotSubmitTextOfItsOwn() throws Exception {
        Cookie demo = tryTheDemo();

        mvc.perform(post("/api/demo/phishing_email").cookie(demo)).andExpect(status().isAccepted());
        mvc.perform(post("/api/incidents").cookie(demo).contentType(MediaType.APPLICATION_JSON).content(EMAIL))
                .andExpect(status().isForbidden());
    }

    @Test
    void anAdminCanStillSubmitAnIncident() throws Exception {
        users.save(new User("ada.admin", passwordEncoder.encode(PASSWORD), Role.ADMIN));
        Cookie admin = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"ada.admin\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);

        mvc.perform(post("/api/incidents").cookie(admin).contentType(MediaType.APPLICATION_JSON).content(EMAIL))
                .andExpect(status().isAccepted());
    }

    @Test
    void theSiteStopsTakingDemoRunsAtTodaysCeiling() throws Exception {
        Cookie demo = tryTheDemo();
        Instant startOfToday = LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant();
        long alreadyToday = incidents.countBySourceInAndCreatedAtGreaterThanEqual(
                List.of(Incident.SOURCE_DEMO, Incident.SOURCE_RED_TEAM), startOfToday);

        for (long run = alreadyToday; run < RUNS_PER_DAY; run++) {
            mvc.perform(post(run % 2 == 0 ? "/api/demo/vishing_call" : "/api/red-team").cookie(demo))
                    .andExpect(status().isAccepted());
        }

        // Demo scenarios and red-team runs share the ceiling.
        for (String route : new String[] { "/api/demo/vishing_call", "/api/red-team" }) {
            mvc.perform(post(route).cookie(demo))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(header().exists("Retry-After"))
                    .andExpect(jsonPath("$.error").value("The demo has reached today's limit. Try again tomorrow."));
        }
    }
}
