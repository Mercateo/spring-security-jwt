[![Build Status](https://travis-ci.org/Mercateo/spring-security-jwt.svg?branch=master)](https://travis-ci.org/Mercateo/spring-security-jwt)
[![Coverage Status](https://coveralls.io/repos/github/Mercateo/spring-security-jwt/badge.svg?branch=master)](https://coveralls.io/github/Mercateo/spring-security-jwt?branch=master)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/2f1e375a4f624da59f0dd732e83c491f)](https://app.codacy.com/app/wuan/spring-security-jwt?utm_source=github.com&utm_medium=referral&utm_content=Mercateo/spring-security-jwt&utm_campaign=badger)
[![MavenCentral](https://img.shields.io/maven-central/v/com.mercateo.spring/spring-security-jwt.svg)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.mercateo.spring%22%20AND%20a%3A%22spring-security-jwt%22)

# com.mercateo.spring.spring-security-jwt

## Example usage
How to add JWT support to your project.

## Simple Example
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaHR0cHM6Ly90ZXN0Lm9yZy9mb28iOiJiYXIiLCJpYXQiOjE1MTYyMzkwMjJ9.Ujx0Lo-2PjRMXd3xBh1kyf7XEOmGK2LttJJPDL1A4J4
```
contains payload
```
{
  "sub": "1234567890",
  "https://test.org/foo": "bar",
  "iat": 1516239022
}
```
see e.g. https://jwt.io/


Import the config and add a configuration bean
```
@Configuration
@Import(JWTSecurityConfiguration.class)
public class MyConfiguration {

    ...
    
    @Bean
    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig.builder() //
                .addAnonymousPaths("/admin/app_health") //
                .addAnonymousMethods(HttpMethod.OPTIONS) //
                .addRequiredClaims("https://test.org/foo") //
                .addTokenAudiences("https://test.org/api") //
                .withTokenLeeway(300) //
                .build();
    }

    ...
}
```

Access the principal object to get claims from the token:

```
        final JWTPrincipal principal = JWTPrincipal.fromContext();

        log.info("principal foo {} with scopes '{}'",
              principal.getClaim("https://test.org/foo"),
              principal.getAuthorities());
```

## Example with token verification

```$java
@Configuration
@Import(JWTSecurityConfiguration.class)
public class MyConfiguration {

    ...
    
    @Bean
    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig
            .builder()
            .addAnonymousPaths("/admin/app_health")
            .addAnonymousMethods(HttpMethod.OPTIONS)
            .jwtKeyset(new Auth0JWTKeyset(auth0Domain))
            .addRequiredClaims("https://test.org/foo")
            .addRequiredClaims("https://test.org/bar")
            .addTokenAudiences("https://test.org/api")
            .withTokenLeeway(300)
            .build();
    }

    ...
}
```

## Roles / scopes integration

The content of the scope claim is parsed into the list of granted authorities.
