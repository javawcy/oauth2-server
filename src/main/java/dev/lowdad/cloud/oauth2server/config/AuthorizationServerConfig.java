package dev.lowdad.cloud.oauth2server.config;

import dev.lowdad.cloud.oauth2server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
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
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final TokenStore jwtTokenStore;
    private final DataSource dataSource;

    @Autowired
    public AuthorizationServerConfig(AuthenticationManager authenticationManager, UserService userService, TokenStore jwtTokenStore, DataSource dataSource) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jwtTokenStore = jwtTokenStore;
        this.dataSource = dataSource;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(this.authenticationManager)
                .userDetailsService(this.userService)
                .tokenStore(this.jwtTokenStore);
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
