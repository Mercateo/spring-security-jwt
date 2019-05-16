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
package com.mercateo.spring.security.jwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import lombok.val;

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

    private JWTAuthenticationTokenFilter uut;

    @Before
    public void init() {
        uut = new JWTAuthenticationTokenFilter();
    }

    @Test
    public void throwsWithoutToken() throws Exception {

        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);
        verify(spy, never()).successfulAuthentication(eq(request), eq(response), eq(chain), any());

    }

    @Test
    public void returnsWrappedToken() {
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

        uut.addUnauthenticatedPaths(Collections.singleton("/api"));
        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);

    }

    @Test
    public void dontAttemptAuthenticationWithoutTokenWithAnonymousPathWildcard() throws Exception {

        uut.addUnauthenticatedPaths(Collections.singleton("/api/*"));
        JWTAuthenticationTokenFilter spy = Mockito.spy(uut);
        when(request.getServletPath()).thenReturn("/api/foo");

        spy.doFilter(request, response, chain);

        verify(spy, never()).attemptAuthentication(request, response);

    }

    @Test
    public void callsFilterChainWithoutTokenWithAnonymousPath() throws Exception {

        uut.addUnauthenticatedPaths(Collections.singleton("/api"));
        when(request.getServletPath()).thenReturn("/api");

        uut.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);

    }

    @Test
    public void callsFilterChainWithoutTokenWithoutAnonymousPath() throws Exception {

        final AuthenticationFailureHandler mockAuthenticationFailureHandler = mock(AuthenticationFailureHandler.class);
        doNothing().when(mockAuthenticationFailureHandler).onAuthenticationFailure(any(HttpServletRequest.class),
                any(HttpServletResponse.class), any(AuthenticationException.class));
        uut.setAuthenticationFailureHandler(mockAuthenticationFailureHandler);

        uut.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        verify(mockAuthenticationFailureHandler).onAuthenticationFailure(any(HttpServletRequest.class),
                        any(HttpServletResponse.class), any(AuthenticationException.class));
    }

    @Test
    public void throwsWithoutTokenInSubdirectoryOfAnonymousPath() throws Exception {

        uut.addUnauthenticatedPaths(Collections.singleton("/api"));
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
