package com.mercateo.spring.security.jwt.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;

import io.vavr.collection.List;
import io.vavr.collection.Map;
import io.vavr.control.Option;

public class JWTPrincipal implements UserDetails {

    private final Long id;

    private final String username;

    private final String token;

    private final List<? extends GrantedAuthority> authorities;

    private final Map<String, JWTClaim> claims;

    public JWTPrincipal(long id, String username, String token, List<? extends GrantedAuthority> authorities,
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

    public Option<JWTClaim> getClaim(String key) {
        return claims.get(key);
    }

    public static JWTPrincipal fromContext() {
        return (JWTPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
