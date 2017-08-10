package com.mercateo.spring.security.jwt.security;

import java.util.Collection;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mercateo.spring.security.jwt.token.result.JWTClaim;

import io.vavr.collection.List;
import io.vavr.collection.Map;

public class Authenticated implements UserDetails {

    private final Long id;

    private final String username;

    private final String token;

    private final List<? extends GrantedAuthority> authorities;

    private final Map<String, JWTClaim> claims;

    public Authenticated(long id, String username, String token, List<? extends GrantedAuthority> authorities,
            Map<String, JWTClaim> claims) {
        this.id = Long.valueOf(id);
        this.username = username;
        this.token = token;
        this.authorities = authorities;
        this.claims = claims;
    }

    @JsonIgnore
    public Long getId() {
        return id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }

    public String getToken() {
        return token;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.toJavaList();
    }

    @Override
    public String getPassword() {
        return null;
    }

    public Optional<JWTClaim> getClaim(String key) {
        return claims.get(key).toJavaOptional();
    }

    public static Authenticated fromContext() {
        return (Authenticated) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
