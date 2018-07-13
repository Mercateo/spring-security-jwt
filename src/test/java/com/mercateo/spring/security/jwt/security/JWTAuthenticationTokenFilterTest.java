package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.mercateo.spring.security.jwt.security.exception.InvalidTokenException;

import lombok.val;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationTokenFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private JWTAuthenticationTokenFilter uut;

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
    public void rethrowsJWTException() {
        val tokenString = "<token>";
        when(request.getHeader("authorization")).thenReturn("Bearer " + tokenString);
        final JWTDecodeException jwtDecodeException = new JWTDecodeException("invalid token");
        when(authenticationManager.authenticate(any())).thenThrow(jwtDecodeException);

        assertThatThrownBy(() -> uut.attemptAuthentication(request, response))
            .isInstanceOf(InvalidTokenException.class)
            .hasMessage("invalid token")
            .hasCause(jwtDecodeException);
    }

    @Test
    public void callsFilterChain() throws Exception {
        val filterChain = mock(FilterChain.class);
        val authentication = mock(Authentication.class);
        uut.successfulAuthentication(request, response, filterChain, authentication);

        verify(filterChain).doFilter(request, response);
    }
}