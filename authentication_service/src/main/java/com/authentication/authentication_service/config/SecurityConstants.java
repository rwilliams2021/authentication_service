package com.authentication.authentication_service.config;

import java.util.List;

public final class SecurityConstants {
    public static final List<String> PUBLIC_ENDPOINTS =
            List.of(
                    "/swagger-ui/**",
                    "/v3/api-docs/**",
                    "/openapi-schema/**",
                    "/v3/api-docs.yaml",
                    "/actuator/**",
                    "/oauth2/**",
                    "/api/auth/google-login",
                    "/api/auth/logout/callback"
            );

    private SecurityConstants() {}
}

