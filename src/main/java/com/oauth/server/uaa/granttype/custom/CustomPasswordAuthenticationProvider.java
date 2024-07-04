package com.oauth.server.uaa.granttype.custom;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import com.oauth.server.uaa.entities.AccessTokenBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class CustomPasswordAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private final OAuth2AuthorizationService authorizationService;
    private final UserDetailsService userDetailsService;
    //private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final PasswordEncoder passwordEncoder;
    private String username = "";
    private String password = "";
    private Set<String> authorizedScopes = new HashSet<>();

    @Value("${external.token.provider.url}")
    private String tokenProviderUrl;


    public CustomPasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {

        Assert.notNull(authorizationService, "authorizationService cannot be null");
        //Assert.notNull(tokenGenerator, "TokenGenerator cannot be null");
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        Assert.notNull(passwordEncoder, "PasswordEncoder cannot be null");
        this.authorizationService = authorizationService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomPasswordAuthenticationToken customPasswordAuthenticationToken = (CustomPasswordAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(customPasswordAuthenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        username = customPasswordAuthenticationToken.getUsername();
        password = customPasswordAuthenticationToken.getPassword();

        UserDetails user = null;
        try {
            user = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException("Invalid credentials");
        }

        if (!passwordEncoder.matches(password, user.getPassword()) || !user.getUsername().equals(username)) {
            throw new OAuth2AuthenticationException("Invalid credentials");
        }


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic Y2xpZW50MS1pZDpjbGllbnQxLXNlY3JldA==");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

        ResponseEntity<AccessTokenBean> response = restTemplate().exchange(tokenProviderUrl, HttpMethod.POST, requestEntity, AccessTokenBean.class);

        DecodedJWT jwt = JWT.decode(Objects.requireNonNull(response.getBody()).getAccess_token());

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                Objects.requireNonNull(response.getBody()).getAccess_token(), jwt.getIssuedAtAsInstant(),
                jwt.getExpiresAtAsInstant());

        assert accessToken != null;
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {

        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

}
