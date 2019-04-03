/**
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

import java.util.Collections;
import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.mercateo.spring.security.jwt.security.JWTAuthenticationEntryPoint;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationProvider;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationSuccessHandler;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationTokenFilter;
import com.mercateo.spring.security.jwt.token.extractor.ValidatingHierarchicalClaimsExtractor;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
@AllArgsConstructor
public class JWTSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static JWTSecurityConfig defaultConfig = JWTSecurityConfig.builder().build();

    private final Optional<JWTSecurityConfig> config;

    @Bean
    public JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JWTAuthenticationEntryPoint();
    }

    @Bean
    ValidatingHierarchicalClaimsExtractor hierarchicalJwtClaimsExtractor() {
        return new ValidatingHierarchicalClaimsExtractor(jwtSecurityConfig());
    }

    private JWTSecurityConfig jwtSecurityConfig() {
        return config.orElse(defaultConfig);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return new ProviderManager(Collections.singletonList(jwtAuthenticationProvider(
                hierarchicalJwtClaimsExtractor())));
    }

    public JWTAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        JWTAuthenticationTokenFilter authenticationTokenFilter = new JWTAuthenticationTokenFilter();
        authenticationTokenFilter.setAuthenticationManager(authenticationManager());
        authenticationTokenFilter.setAuthenticationSuccessHandler(new JWTAuthenticationSuccessHandler());
        jwtSecurityConfig().authenticationFailureHandler().forEach(
                authenticationTokenFilter::setAuthenticationFailureHandler);

        return authenticationTokenFilter;
    }

    @Bean
    public JWTAuthenticationProvider jwtAuthenticationProvider(
            ValidatingHierarchicalClaimsExtractor hierarchicalJWTClaimsExtractor) {
        return new JWTAuthenticationProvider(hierarchicalJWTClaimsExtractor);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {

        final String[] unauthenticatedPaths = getUnauthenticatedPaths();

        log.info("with unauthenticated paths: [{}]", String.join(", ", unauthenticatedPaths));

        httpSecurity
            // disable csrf
            .csrf()
            .disable()

            // allow
            .authorizeRequests()
            .antMatchers(unauthenticatedPaths)
            .permitAll()
            .and()
            // enable authorization
            .authorizeRequests()
            .anyRequest()
            .authenticated()
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(jwtAuthenticationEntryPoint())
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            // Custom JWT based security filter
            .and()
            .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class)

            // disable page caching
            .headers()
            .cacheControl();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(getUnauthenticatedPaths());

        config.ifPresent(config -> config.anonymousMethods().forEach(method -> web.ignoring().antMatchers(method)));
    }

    private String[] getUnauthenticatedPaths() {
        return config.map(JWTSecurityConfig::anonymousPaths).map(list -> list.toJavaArray(String[]::new)).orElse(
                new String[0]);
    }
}
