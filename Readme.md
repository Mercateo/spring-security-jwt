[![Build Status](https://travis-ci.org/Mercateo/spring-security-jwt.svg?branch=master)](https://travis-ci.org/Mercateo/spring-security-jwt)
[![Coverage Status](https://coveralls.io/repos/github/Mercateo/spring-security-jwt/badge.svg?branch=master)](https://coveralls.io/github/Mercateo/spring-security-jwt?branch=master)

# com.mercateo.spring.spring-security-jwt

## Example usage
How to add JWT support to your project.

Import the config and add a configuration bean
```
@Configuration
@Import(JWTSecurityConfiguration.class)
public class MyConfiguration {

    @Bean
    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig
            .builder()
            .addAnonymousPaths("/admin/app_health")
            .jwtKeyset(mock(JWTKeyset.class))
            .addNamespaces("https://test.org/")
            .addRequiredClaims("scope", "hierarchicalClaimsCollector")
            .build();
    }
}
```

Access the principal object to get claims from the token:

```
        final JWTPrincipal principal = JWTPrincipal.fromContext();

        log.info("principal hierarchicalClaimsCollector {} with scopes '{}'",
              principal.getClaim("hierarchicalClaimsCollector"),
              principal.getClaim("scope"));
```

