package com.mercateo.spring.security.jwt.token.keyset;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.SigningKeyNotFoundException;
import io.vavr.control.Try;
import lombok.val;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Auth0JWTKeysetTest {

    @Test
    public void shouldStoreDomain() {
        val jwtKeyset = new Auth0JWTKeyset("domain");

        assertThat(jwtKeyset.getAuth0Domain()).isEqualTo("domain");
    }

    @Test
    public void shouldReturnFailureForUnknownKeyId() {
        val jwtKeyset = new Auth0JWTKeyset("domain");


        final Try<Jwk> foo = jwtKeyset.getKeysetForId("foo");
        assertThat(foo.isFailure()).isTrue();
        assertThat(foo.getCause()).isInstanceOf(SigningKeyNotFoundException.class);
    }
}