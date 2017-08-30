[![Build Status](https://travis-ci.org/Mercateo/spring-security-jwt.svg?branch=master)](https://travis-ci.org/Mercateo/spring-security-jwt)
[![Coverage Status](https://coveralls.io/repos/github/Mercateo/spring-security-jwt/badge.svg?branch=master)](https://coveralls.io/github/Mercateo/spring-security-jwt?branch=master)
[![MavenCentral](https://img.shields.io/maven-central/v/com.mercateo.spring/spring-security-jwt.svg)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.mercateo.spring%22%20AND%20a%3A%22spring-security-jwt%22)

# com.mercateo.spring.spring-security-jwt

## Example usage
How to add JWT support to your project.

Example Token
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpc3MiOiJuYW1lIiwic3ViIjoic3ViamVjdCJ9.teWF_9A5bY8DCZG23AvyiSZhPVfozbFvhx01AVY-Bb0
```
contains payload
```
{
  "foo": "bar",
  "iss": "name",
  "sub": "subject"
}
```
see e.g. https://jwt.io/


Import the config and add a configuration bean
```
@Configuration
@Import(JWTSecurityConfiguration.class)
public class MyConfiguration {

    @Bean
    public JWTSecurityConfig securityConfig() {
        return JWTSecurityConfig.builder() //
                .addAnonymousPaths("/admin/app_health") //
                .addAnonymousMethods(HttpMethod.OPTIONS) //
                .addNamespaces("https://test.org/") //
                .addRequiredClaims("foo") //
                .addTokenAudiences("https://test.org/api") //
                .withTokenLeeway(300) //
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
