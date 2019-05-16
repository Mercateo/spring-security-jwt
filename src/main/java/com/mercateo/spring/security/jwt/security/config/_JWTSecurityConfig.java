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
package com.mercateo.spring.security.jwt.security.config;

import org.immutables.value.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.mercateo.immutables.ValueStyle;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;

import io.vavr.collection.Set;
import io.vavr.control.Option;

@Value.Immutable
@ValueStyle
public interface _JWTSecurityConfig extends JWTConfig {

    /**
     * @return Paths with anonymous access
     */
    Set<String> anonymousPaths();

    /**
     * @return {@link HttpMethod} with anynomous access
     */
    Set<HttpMethod> anonymousMethods();

    Option<AuthenticationFailureHandler> authenticationFailureHandler();
}
