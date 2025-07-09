package com.authentication.authentication_service.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @GetMapping("/google-login")
    public RedirectView initiateLogin() {
        return new RedirectView("/oauth2/authorization/google");
    }

    @GetMapping("/logged-in")
    public String handleLogoutCallback(@AuthenticationPrincipal OidcUser oidcUser) {
        String name = oidcUser.getClaimAsString("given_name");
        return "Hi " + name + ", you are logged in";
    }

    @GetMapping("/logout/callback")
    public String handleLogoutCallback() {
        return "You are logged out";
    }
}
