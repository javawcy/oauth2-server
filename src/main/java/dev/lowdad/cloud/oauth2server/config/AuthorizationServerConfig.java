package dev.lowdad.cloud.oauth2server.config;

import dev.lowdad.cloud.oauth2server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;

/**
 * <p>
 * IDP 配置
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/22
 */
@Configuration
@EnableAuthorizationServer
@RefreshScope
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final TokenStore jwtTokenStore;
    private final DataSource dataSource;
    private final JwtAccessTokenConverter jwtTokenEnhancer;

    @Autowired
    public AuthorizationServerConfig(AuthenticationManager authenticationManager, UserService userService, TokenStore jwtTokenStore, DataSource dataSource, JwtAccessTokenConverter jwtTokenEnhancer) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jwtTokenStore = jwtTokenStore;
        this.dataSource = dataSource;
        this.jwtTokenEnhancer = jwtTokenEnhancer;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(this.authenticationManager)
                .userDetailsService(this.userService)
                .tokenStore(this.jwtTokenStore)
                .accessTokenConverter(this.jwtTokenEnhancer);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientsDetails());
    }

    @Bean
    public ClientDetailsService clientsDetails() {
        return new JdbcClientDetailsService(this.dataSource);
    }
}
