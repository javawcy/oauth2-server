package dev.lowdad.cloud.oauth2server.config;

import dev.lowdad.cloud.oauth2server.domain.UserInfoVO;
import dev.lowdad.cloud.oauth2server.filter.CustomClientCredentialsTokenEndpointFilter;
import dev.lowdad.cloud.oauth2server.granter.CustomMobilePassTokenGranter;
import dev.lowdad.cloud.oauth2server.granter.CustomRefreshTokenGranter;
import dev.lowdad.cloud.oauth2server.granter.CustomSmsTokenGranter;
import dev.lowdad.cloud.oauth2server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.beans.BeanMap;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.util.*;

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

    //定义token存储方式
    private enum TokenStoreType {
        REDIS, JWT
    }

    private final TokenStoreType tokenStoreType = TokenStoreType.JWT;
    private final UserService userService;
    private final DataSource dataSource;
    private final RedisConnectionFactory redisConnectionFactory;
    private final JwtSignConfiguration jwtSignConfiguration;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    public AuthorizationServerConfig(UserService userService, DataSource dataSource, RedisConnectionFactory redisConnectionFactory, JwtSignConfiguration jwtSignConfiguration, AuthenticationEntryPoint authenticationEntryPoint) {
        this.userService = userService;
        this.dataSource = dataSource;
        this.redisConnectionFactory = redisConnectionFactory;
        this.jwtSignConfiguration = jwtSignConfiguration;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

        CustomClientCredentialsTokenEndpointFilter endpointFilter = new CustomClientCredentialsTokenEndpointFilter(security);
        endpointFilter.afterPropertiesSet();
        endpointFilter.setAuthenticationEntryPoint(authenticationEntryPoint);

        security.authenticationEntryPoint(authenticationEntryPoint);
        security.addTokenEndpointAuthenticationFilter(endpointFilter);

        security
                .tokenKeyAccess("isAuthenticated()")
                .checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore());
        //替换验证方式
        List<TokenGranter> tokenGranters = getTokenGranters(endpoints.getAuthorizationCodeServices(),
                endpoints.getTokenStore(), endpoints.getTokenServices(), endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory());
        endpoints.tokenGranter(new CompositeTokenGranter(tokenGranters));
        //根据存储类型定义转换方式
        endpoints.tokenEnhancer(new TokenEnhancer() {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                //设定返回携带信息
                DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) accessToken;
                UserInfoVO user = (UserInfoVO) authentication.getPrincipal();
                Map<String, Object> map = new LinkedHashMap<>();
                map.put("username", user.getUsername());
                map.put("mobile", user.getMobile());
                map.put("client", user.getClient());
                map.put("expire", accessToken.getExpiresIn());
                token.setAdditionalInformation(map);

                //根据类型序列化
                if (tokenStoreType == TokenStoreType.JWT) {
                    token = (DefaultOAuth2AccessToken) jwtTokenEnhancer().enhance(accessToken, authentication);
                } else {
                    token.setValue(buildTokenValue());
                    if (token.getRefreshToken() != null) {
                        if (token.getRefreshToken() instanceof DefaultExpiringOAuth2RefreshToken) {
                            DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) token.getRefreshToken();
                            token.setRefreshToken(new DefaultExpiringOAuth2RefreshToken(buildTokenValue(), refreshToken.getExpiration()));
                        } else {
                            token.setRefreshToken(new DefaultOAuth2RefreshToken(buildTokenValue()));
                        }
                    }
                }

                return token;
            }

            public String buildTokenValue() {
                return UUID.randomUUID().toString() + UUID.randomUUID().toString();
            }
        });
    }


    /**
     * 关键代码，重新定义验证方式集合
     *
     * @param authorizationCodeServices 验证服务
     * @param tokenStore                存储token方式
     * @param tokenServices             token规则
     * @param clientDetailsService      client服务
     * @param oAuth2RequestFactory      请求
     * @return List<TokenGranter> 重新定义验证方式集合
     */
    private List<TokenGranter> getTokenGranters(AuthorizationCodeServices authorizationCodeServices, TokenStore tokenStore, AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory oAuth2RequestFactory) {
        return new ArrayList<>(Arrays.asList(
                new CustomRefreshTokenGranter(tokenStore, tokenServices, clientDetailsService, oAuth2RequestFactory),
                new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetailsService, oAuth2RequestFactory),
                new CustomSmsTokenGranter(userService, tokenServices, clientDetailsService, oAuth2RequestFactory),
                new CustomMobilePassTokenGranter(userService, tokenServices, clientDetailsService, oAuth2RequestFactory)
        ));
    }

    /**
     * 加载客户端获取方式
     *
     * @param clients 客户端配置
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientsDetails());
    }

    /**
     * 客户端类型从数据库读取
     *
     * @return ClientDetailsService
     */
    @Bean
    public ClientDetailsService clientsDetails() {
        return new JdbcClientDetailsService(this.dataSource);
    }


    /**
     * 定义token存储方式
     *
     * @return TokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        switch (tokenStoreType) {
            case REDIS:
                return new RedisTokenStore(redisConnectionFactory);
            case JWT:
                return new JwtTokenStore(jwtTokenEnhancer());
        }
        return new InMemoryTokenStore();
    }

    /**
     * jwt 序列化,signKey 可配置
     *
     * @return JwtAccessTokenConverter
     */
    @Bean
    @RefreshScope
    public JwtAccessTokenConverter jwtTokenEnhancer() {
        JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();
        jwtTokenEnhancer.setSigningKey(jwtSignConfiguration.getSignKey());
        ((DefaultAccessTokenConverter) jwtTokenEnhancer.getAccessTokenConverter()).setUserTokenConverter(new DefaultUserAuthenticationConverter() {
            @Override
            public Authentication extractAuthentication(Map<String, ?> map) {
                UserInfoVO userInfoVO = new UserInfoVO();
                BeanMap.create(userInfoVO).putAll(map);
                Object authorities = map.get("authorities");
                if (authorities instanceof String) {
                    userInfoVO.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList((String) authorities));
                } else if (authorities instanceof Collection) {
                    userInfoVO.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils.collectionToCommaDelimitedString((Collection) authorities)));
                }
                return new PreAuthenticatedAuthenticationToken(userInfoVO, null, userInfoVO.getAuthorities());
            }
        });
        return jwtTokenEnhancer;
    }
}
