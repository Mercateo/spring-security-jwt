/*
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt.security.config;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { JWTSecurityConfigurationITest.TestPathConfiguration.class,
        JWTSecurityConfigurationITest.TestController.class, JWTSecurityConfiguration.class })
@WebAppConfiguration
@EnableWebSecurity
public class JWTSecurityConfigurationITest {
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Before
    public void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    public void httpGETReturnsOk_whenAnonymousPathIsAccessed() throws Exception {
        mockMvc.perform(get("/anonymous")).andExpect(status().isOk());
    }

    @Test
    public void httpGETReturnsUnauthorized_whenAuthenticatedPathIsAccessed() throws Exception {
        mockMvc.perform(get("/authorized")).andExpect(status().isUnauthorized());
    }

    @Test
    public void httpPOSTReturnsUnauthorized_whenAuthenticatedPathIsAccessed() throws Exception {
        mockMvc.perform(post("/authorized")).andExpect(status().isUnauthorized());
    }

    @Test
    public void httpOPTIONSReturnsOk_whenAnonymousPathIsAccessed() throws Exception {
        mockMvc.perform(options("/anonymous")).andExpect(status().isOk());
    }

    @Test
    public void httpOPTIONSReturnsOk_whenAuthenticatedPathIsAccessed() throws Exception {
        mockMvc.perform(options("/authorized")).andExpect(status().isOk());
    }

    @Configuration
    static class TestPathConfiguration {
        @Bean
        public JWTSecurityConfig securityConfig() {
            return JWTSecurityConfig
                .builder()
                .addAnonymousPaths("/anonymous")
                .addAnonymousMethods(HttpMethod.OPTIONS)
                .build();
        }
    }

    @Controller
    static class TestController {
        @RequestMapping(value = "/anonymous", method = { RequestMethod.GET, RequestMethod.OPTIONS })
        public String anonymousAccess() {
            return "anonymousResponse";
        }

        @RequestMapping(value = "/authorized", method = { RequestMethod.GET, RequestMethod.POST,
                RequestMethod.OPTIONS })
        public String authorizedAccess() {
            return "authorizedResponse";
        }
    }
}