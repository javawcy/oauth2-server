package dev.lowdad.cloud.oauth2server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * <p>
 * redis 存储token
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/22
 */
@Configuration
public class RedisTokenStoreConfig {

    private final RedisConnectionFactory redisConnectionFactory;

    @Autowired
    public RedisTokenStoreConfig(RedisConnectionFactory redisConnectionFactory) {
        this.redisConnectionFactory = redisConnectionFactory;
    }

//    @Bean
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
}
