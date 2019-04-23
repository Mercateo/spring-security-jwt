package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.val;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import io.vavr.collection.HashSet;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationTokenFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthenticationManager authenticationManager;

    private JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.empty());

    @Test
    public void throwsWithoutToken() throws Exception {
        assertThatThrownBy(() -> uut.attemptAuthentication(request, response))
            .isInstanceOf(InvalidTokenException.class)
            .hasMessage("no token");
    }

    @Test
    public void returnsWrappedToken() throws Exception {
        val tokenString = "<token>";
        when(request.getHeader("authorization")).thenReturn("Bearer " + tokenString);
        uut.setAuthenticationManager(authenticationManager);
        val authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(new JWTAuthenticationToken(tokenString))).thenReturn(authentication);

        val result = uut.attemptAuthentication(request, response);

        assertThat(result).isEqualTo(authentication);
    }

    @Test
    public void returnsAnonymousToken() throws Exception {

        JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.of("/api"));
        when(request.getServletPath()).thenReturn("/api");

        val result = uut.attemptAuthentication(request, response);

        assertThat(result.getClass()).isEqualTo(AnonymousAuthenticationToken.class);
    }

    @Test
    public void returnsAnonymousTokenWildcardPath() throws Exception {

        JWTAuthenticationTokenFilter uut = new JWTAuthenticationTokenFilter(HashSet.of("/api/*"));
        when(request.getServletPath()).thenReturn("/api/foo");

        val result = uut.attemptAuthentication(request, response);

        assertThat(result.getClass()).isEqualTo(AnonymousAuthenticationToken.class);
    }

    @Test
    public void callsFilterChain() throws Exception {
        val filterChain = mock(FilterChain.class);
        val authentication = mock(Authentication.class);
        uut.successfulAuthentication(request, response, filterChain, authentication);

        verify(filterChain).doFilter(request, response);
    }
}