package com.backendauthorizationserver.config;

import com.backendauthorizationserver.enumhelper.AccessDeniedField;
import com.backendauthorizationserver.model.UserStatusErrorException;
//import com.backendauthorizationserver.utility.UrlUtility;

//import com.backendauthorizationserver.utility.UrlUtility;
//import com.backendauthorizationserver.utility.UrlUtility3;
//import com.backendauthorizationserver.utility.UrlUtility3;
import com.google.gson.Gson;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.util.ObjectUtils;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;


@EnableAutoConfiguration(exclude= {UserDetailsServiceAutoConfiguration.class})
@Slf4j
@Configuration(proxyBeanMethods = false)
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    @Autowired
    private Gson gson;

    @Value("${oauth2.protocol.domain}")
    private String urlDomain;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String secretKey;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors()
                .configurationSource(request -> new CorsConfiguration()
                        .applyPermitDefaultValues());

        http.csrf().disable()
                .oauth2ResourceServer(
                        oauth2 -> oauth2.jwt().jwkSetUri(urlDomain+providerSettings().getJwkSetEndpoint())
                )
                .authorizeRequests()
                .requestMatchers(request -> request.getRequestURI().matches("/mini/checkStatus") &&
                        (ObjectUtils.isEmpty(request.getParameter(AccessDeniedField.authCode.toString())) ||
                                request.getParameter(AccessDeniedField.authCode.toString()).matches("(\\s+|null)"))
                )
                .denyAll()
                .antMatchers("/mini/checkStatus")
                .authenticated()

                .anyRequest().permitAll()
                .and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler())
                .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint());


        return http.build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}"+secretKey)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder()
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .build())
                .scope("read")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }
    @Bean
    public ProviderSettings providerSettings() {
        ProviderSettings providerSettings = ProviderSettings.builder()
                .issuer(urlDomain)
                .tokenEndpoint("/createToken")
                .tokenIntrospectionEndpoint("/checkToken")
                .build();
        log.info("Oauth2 Endpoints = {}",gson.toJson(providerSettings));
        return providerSettings;
    }



    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {

        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(2048);
        KeyPair keyPair = kg.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

    }



    //Custom response of Forbidden Response
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint(){
        return new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                Gson gson = new Gson();

                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write(gson.toJson(UserStatusErrorException.builder()
                        .transactionId(request.getParameter(AccessDeniedField.transactionId.toString()))
                        .status(String.valueOf(HttpStatus.FORBIDDEN.value()))
                        .description("You do not have permission to access.")
                        .redirectUrl("")
                        .title("FORBIDDEN")
                        .build()));
                log.info("Access Denied = authCode:{} transactionId:{}",
                        gson.toJson(request.getParameterValues(AccessDeniedField.authCode.toString())),
                        gson.toJson(request.getParameterValues(AccessDeniedField.transactionId.toString())));
            }
        };

    }
    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
            return new AccessDeniedHandler() {
                @Override
                public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

                    Gson gson = new Gson();

                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write(gson.toJson(UserStatusErrorException.builder()
                            .transactionId(request.getParameter(AccessDeniedField.transactionId.toString()))
                            .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                            .description("You do not have permission to access.")
                            .redirectUrl("")
                            .title("UNAUTHORIZED")
                            .build()));
                    log.info("Access Denied = authCode:{} transactionId:{}",
                            gson.toJson(request.getParameterValues(AccessDeniedField.authCode.toString())),
                            gson.toJson(request.getParameterValues(AccessDeniedField.transactionId.toString())));
                }
            };
    }



}
