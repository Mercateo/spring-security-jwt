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

        TestException(String msg, Throwable t) {
            super(msg, t);
        }
    }
}