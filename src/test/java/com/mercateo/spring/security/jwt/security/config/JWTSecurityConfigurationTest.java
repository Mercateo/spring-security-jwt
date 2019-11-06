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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.mercateo.spring.security.jwt.token.extractor.ValidatingHierarchicalClaimsExtractor;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { JWTSecurityConfigurationTest.TestConfiguration.class,
        JWTSecurityConfiguration.class })
public class JWTSecurityConfigurationTest {

    @Autowired
    ValidatingHierarchicalClaimsExtractor extractor;

	@Autowired
	FilterChainProxy filterChain;

    @Test
    public void injectsJWTVerifier() {
        assertThat(extractor.hasJWTVerifier()).isTrue();
    }
    
	@Test
	public void testCors() {
		assertThat(filterChain.getFilters("CorsFilter")).extractingResultOf("getClass").contains(CorsFilter.class);
	}

    @Configuration
    static class TestConfiguration {
        @Bean
        public JWTSecurityConfig securityConfig() {
            return JWTSecurityConfig.builder().jwtKeyset(mock(JWTKeyset.class)).build();
        }
		
		@Bean
		public CorsFilter corsFilter() {
			final CorsConfiguration config = new CorsConfiguration();

			config.addAllowedOrigin("*");
			config.addAllowedHeader("*");
			config.addAllowedMethod("GET");
			config.addAllowedMethod("PUT");
			config.addAllowedMethod("POST");

			return new CorsFilter(new CorsConfigurationSource() {

				@Override
				public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
					return config;
				}
			});
		}
	}
}