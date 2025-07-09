package com.authentication.authentication_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@Slf4j
public class SecurityConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final String baseUrl;
    private final String cookieName;
    private final String logoutCallbackUrl;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository, @Value("${app.base-url}") String baseUrl,
                          @Value("${server.servlet.session.cookie.name}") String cookieName, @Value("${app.google.logout-callback-url}") String logoutCallbackUrl
    ) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.baseUrl = baseUrl;
        this.cookieName = cookieName;
        this.logoutCallbackUrl = logoutCallbackUrl;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                                                                .requestMatchers(SecurityConstants.PUBLIC_ENDPOINTS.toArray(String[]::new)).permitAll()
                                                                .anyRequest().authenticated())
            .sessionManagement(this::configureSessionManagement)
            .oauth2Login(this::configureOAuth2Login)
            .exceptionHandling(this::configureExceptionHandling)
            .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                                    .logoutUrl("/logout")
                                    .invalidateHttpSession(true)
                                    .clearAuthentication(true)
                                    .deleteCookies(cookieName)
                                    .permitAll());
        return http.build();
    }

    private void configureSessionManagement(SessionManagementConfigurer<HttpSecurity> session) {
        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
               .maximumSessions(1)
               .maxSessionsPreventsLogin(false);
    }

    private void configureOAuth2Login(OAuth2LoginConfigurer<HttpSecurity> httpSecurityOAuth2LoginConfigurer) {
        httpSecurityOAuth2LoginConfigurer.successHandler(oidcSuccessHandler());
    }

    private AuthenticationSuccessHandler oidcSuccessHandler() {
        return (request, response, authentication) -> {

            log.debug("Google OIDC authentication successful");

            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                log.debug("Google user authenticated: {} ({})",
                          oidcUser.getFullName(), oidcUser.getEmail());
                log.debug("Google ID: {}", oidcUser.getSubject());
            }

            // Redirect to frontend success page or API endpoint
            String redirectUrl = baseUrl + "/api/auth/logged-in";
            response.sendRedirect(redirectUrl);
        };
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(
                        this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(logoutCallbackUrl);

        return oidcLogoutSuccessHandler;
    }

    private void configureExceptionHandling(ExceptionHandlingConfigurer<HttpSecurity> ex) {
        ex.authenticationEntryPoint((request, response, authException) -> {
            log.debug("Authentication exception: ", authException);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        });
    }
}