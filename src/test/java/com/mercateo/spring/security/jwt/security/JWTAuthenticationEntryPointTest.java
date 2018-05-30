package com.mercateo.spring.security.jwt.security;

import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.AuthenticationException;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationEntryPointTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private JWTAuthenticationEntryPoint uut;

    @Test
    public void mapsToError() throws Exception {
        uut.commence(request, response, new TestException("message", new RuntimeException()));

        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }

    static class TestException extends AuthenticationException {

        public TestException(String msg, Throwable t) {
            super(msg, t);
        }
    }
}