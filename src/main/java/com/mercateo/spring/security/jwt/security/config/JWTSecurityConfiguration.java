package com.mercateo.spring.security.jwt.security.config;

import java.util.Collections;
import java.util.Optional;

import com.mercateo.spring.security.jwt.security.verifier.JWTVerifierFactory;
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

import com.auth0.jwt.JWTVerifier;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationEntryPoint;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationProvider;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationSuccessHandler;
import com.mercateo.spring.security.jwt.security.JWTAuthenticationTokenFilter;
import com.mercateo.spring.security.jwt.token.extractor.WrappedJWTExtractor;

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
    WrappedJWTExtractor wrappedVerifier() {
        final Optional<JWTVerifier> jwtVerifier = config.map(JWTSecurityConfig::jwtKeyset).flatMap(jwks -> jwks
            .map(JWTVerifierFactory::new)
            .map(JWTVerifierFactory::create));
        return new WrappedJWTExtractor(jwtSecurityConfig());
    }

    private JWTSecurityConfig jwtSecurityConfig() {
        return config.orElse(defaultConfig);
    }

    private static IllegalStateException map(Throwable cause) {
        return new IllegalStateException(cause);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return new ProviderManager(Collections.singletonList(jwtAuthenticationProvider(wrappedVerifier())));
    }

    public JWTAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        JWTAuthenticationTokenFilter authenticationTokenFilter = new JWTAuthenticationTokenFilter(wrappedVerifier());
        authenticationTokenFilter.setAuthenticationManager(authenticationManager());
        authenticationTokenFilter.setAuthenticationSuccessHandler(new JWTAuthenticationSuccessHandler());
        return authenticationTokenFilter;
    }

    @Bean
    public JWTAuthenticationProvider jwtAuthenticationProvider(WrappedJWTExtractor wrappedJWTExtractor) {
        return new JWTAuthenticationProvider(wrappedJWTExtractor);
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
    }

    private String[] getUnauthenticatedPaths() {
        return config.map(JWTSecurityConfig::anonymousPaths).map(list -> list.stream().toArray(String[]::new)).orElse(
                new String[0]);
    }

}
