package com.securityanalyst.gateway.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.PostgresIntegrationTest;
import com.securityanalyst.gateway.auth.AuthCookies;
import com.securityanalyst.gateway.auth.Role;
import com.securityanalyst.gateway.auth.User;
import com.securityanalyst.gateway.auth.UserRepository;

import jakarta.servlet.http.Cookie;

/** With demo.enabled=false the demo URLs do not exist at all, even for an admin. */
@SpringBootTest(properties = "demo.enabled=false")
@AutoConfigureMockMvc
@Transactional
class DemoDisabledTest extends PostgresIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ApplicationContext context;

    @Test
    void theDemoUrlsDoNotExist() throws Exception {
        users.save(new User("ada.demo.off", passwordEncoder.encode("correct horse battery staple"), Role.ADMIN));
        Cookie admin = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"ada.demo.off\",\"password\":\"correct horse battery staple\"}"))
                .andReturn().getResponse().getCookie(AuthCookies.ACCESS_TOKEN);

        mvc.perform(get("/api/demo/scenarios").cookie(admin)).andExpect(status().isNotFound());
        mvc.perform(post("/api/demo/credential_stuffing").cookie(admin)).andExpect(status().isNotFound());
        assertThat(context.getBeanNamesForType(DemoScenarios.class)).isEmpty();
    }
}
