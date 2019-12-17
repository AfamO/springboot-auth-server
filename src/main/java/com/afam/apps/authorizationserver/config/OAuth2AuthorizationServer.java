/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.afam.apps.authorizationserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 *
 * @author afam.okonkwo
 */
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    
    @Value("${user.oauth.clientId}")
    private String ClientID;
    @Value("${user.oauth.clientSecret}")
    private String ClientSecret;
    @Value("${user.oauth.redirectUris}")
    private String RedirectURLs;
    
    @Autowired
    private BCryptPasswordEncoder passwordEncoder; 
    
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer authServerConfigurer) {
        authServerConfigurer
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("permitAll()")
                //.allowFormAuthenticationForClients()
                //.addTokenEndpointAuthenticationFilter(filter);
                ;
                
    }
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clientDetailsConfig) throws Exception {
        clientDetailsConfig
                .inMemory()
                .withClient(ClientID)
                .secret(passwordEncoder.encode(ClientSecret))
                .redirectUris(this.RedirectURLs)
                .resourceIds("oauth2-resource")
                .authorizedGrantTypes("password","authorization_code","refresh_token")
                .authorities("READ_ONLY_CLIENT")
                .accessTokenValiditySeconds(120)
                .refreshTokenValiditySeconds(3600)
                .scopes("read_profile_info");
    }
    
}
