package com.mercateo.spring.security.jwt;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class AuthenticatedUser<E extends Enum<E>> implements UserDetails {

    private final Long id;
    private final String username;
    private final String token;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Map<E, String> claims;

    public AuthenticatedUser(Long id, String username, String token, Collection<? extends GrantedAuthority> authorities, Map<E, String> claims) {
        this.id = id;
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
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    public String getClaim(E key) {
        return claims.get(key);
    }

    public static <E extends Enum<E>> AuthenticatedUser<E> fromContext() {
        return (AuthenticatedUser<E>) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
