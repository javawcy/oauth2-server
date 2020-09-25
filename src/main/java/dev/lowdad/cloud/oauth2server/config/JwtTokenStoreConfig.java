package dev.lowdad.cloud.oauth2server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * <p>
 * 将token转换为jwt格式
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/22
 */
@Configuration
public class JwtTokenStoreConfig {

    private final JwtSignConfiguration jwtSignConfiguration;

    @Autowired
    public JwtTokenStoreConfig(JwtSignConfiguration jwtSignConfiguration) {
        this.jwtSignConfiguration = jwtSignConfiguration;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey(jwtSignConfiguration.getSignKey());
        return accessTokenConverter;
    }

    @Bean
    public JwtTokenEnhancer jwtTokenEnhancer() {
        return new JwtTokenEnhancer();
    }
}
