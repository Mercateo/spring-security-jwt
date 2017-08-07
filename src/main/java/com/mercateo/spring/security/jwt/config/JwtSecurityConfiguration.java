package com.mercateo.spring.security.jwt.config;

import java.util.Collections;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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

import com.mercateo.spring.security.jwt.JwtAuthenticationEntryPoint;
import com.mercateo.spring.security.jwt.JwtAuthenticationProvider;
import com.mercateo.spring.security.jwt.JwtAuthenticationSuccessHandler;
import com.mercateo.spring.security.jwt.JwtAuthenticationTokenFilter;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@AllArgsConstructor
@Slf4j
public class JwtSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    Optional<JwtSecurityConfig> config;

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    private JwtAuthenticationProvider authenticationProvider;

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return new ProviderManager(Collections.singletonList(authenticationProvider));
    }

    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        JwtAuthenticationTokenFilter authenticationTokenFilter = new JwtAuthenticationTokenFilter();
        authenticationTokenFilter.setAuthenticationManager(authenticationManager());
        authenticationTokenFilter.setAuthenticationSuccessHandler(new JwtAuthenticationSuccessHandler());
        return authenticationTokenFilter;
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {

        final String[] unauthenticatedPaths = getUnauthenticatedPaths();

        log.info("with unauthenticated paths: {}", unauthenticatedPaths);
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

    private String[] getUnauthenticatedPaths() {
        return config
                .map(JwtSecurityConfig::anonymousPaths)
                .map(list -> list.stream().toArray(String[]::new))
                .orElse(new String[0]);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(getUnauthenticatedPaths());
    }
}
