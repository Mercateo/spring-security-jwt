package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.val;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import io.vavr.collection.HashSet;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationTokenFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    @Mock
    private AuthenticationManager authenticationManager;

    private JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.empty());

    SecurityContext context = new SecurityContextImpl();

    @Test
    public void throwsWithoutToken() throws Exception {

        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);
        verify(spy, never()).successfulAuthentication(eq(request), eq(response), eq(chain), any());

    }

    @Test
    public void returnsWrappedToken() throws Exception {
        val tokenString = "<token>";
        when(request.getHeader("authorization")).thenReturn("Bearer " + tokenString);
        uut.setAuthenticationManager(authenticationManager);
        val authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(new JWTAuthenticationToken(tokenString)))
                .thenReturn(authentication);

        val result = uut.attemptAuthentication(request, response);

        assertThat(result).isEqualTo(authentication);
    }

    @Test
    public void dontAttemptAuthenticationWithoutTokenWithAnonymousPath() throws Exception {

        JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.of("/api"));
        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);

    }

    @Test
    public void dontAttemptAuthenticationWithoutTokenWithAnonymousPathWildcard() throws Exception {

        JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.of("/api/*"));
        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api/foo");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);

    }

    @Test
    public void callsFilterChainWithoutTokenWithAnonymousPath() throws Exception {

        JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.of("/api"));
        when(request.getServletPath()).thenReturn("/api");

        uut.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);

    }

    @Test
    public void throwsWithoutTokenInSubdirectoryOfAnonymousPath() throws Exception {

        JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.of("/api"));
        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api/foo");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);
        verify(spy, never()).successfulAuthentication(eq(request), eq(response), eq(chain), any());

    }

    @Test
    public void callsFilterChainIfSuccessfulAuthentication() throws Exception {
        val authentication = mock(Authentication.class);
        uut.successfulAuthentication(request, response, chain, authentication);

        verify(chain).doFilter(request, response);
    }

    @Test
    public void returnNullWithoutToken() {
        Authentication result = uut.attemptAuthentication(request, response);

        assertThat(result).isNull();
    }

}