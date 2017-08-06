package com.mercateo.spring.security.jwt.config;

import java.util.List;

public interface JwtSecurityConfig {
    List<String> anonymousPaths();
}
