[![Build Status](https://travis-ci.org/Mercateo/spring-security-jwt.svg?branch=master)](https://travis-ci.org/Mercateo/spring-security-jwt)
[![Coverage Status](https://coveralls.io/repos/github/Mercateo/spring-security-jwt/badge.svg?branch=master)](https://coveralls.io/github/Mercateo/spring-security-jwt?branch=master)
[![MavenCentral](https://img.shields.io/maven-central/v/com.mercateo.spring/spring-security-jwt.svg)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.mercateo.spring%22%20AND%20a%3A%22spring-security-jwt%22)

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
        JWTSecurityConfig
            .builder()
            .addAnonymousPaths("/admin/app_health")
            .addAnonymousMethods(HttpMethod.OPTIONS)
            .setValueJwtKeyset(mock(JWTKeyset.class))
            .addNamespaces("https://test.org/")
            .addRequiredClaims("foo")
            .addRequiredClaims("bar")
            .addTokenAudiences("https://test.org/api")
            .withTokenLeeway(300)
            .build();
    }
}
```

Access the principal object to get claims from the token:

```
        final JWTPrincipal principal = JWTPrincipal.fromContext();

        log.info("principal foo {} with scopes '{}'",
              principal.getClaim("foo"),
              principal.getAuthorities());
```

## Roles / scopes integration

The content of the scope claim is parsed into the list of granted authorities.
