package dev.lowdad.cloud.oauth2server.granter;

import dev.lowdad.cloud.oauth2server.domain.UserInfoVO;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Map;

/**
 * <p>
 * 自定义granter抽象类，定义校验方式
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/27
 */
public abstract class AbstractCustomTokenGranter extends AbstractTokenGranter {

    private final OAuth2RequestFactory requestFactory;

    protected AbstractCustomTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
        this.requestFactory = requestFactory;
    }


    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = tokenRequest.getRequestParameters();
        UserInfoVO user = getUserInfo(parameters);
        if (user == null) {
            throw new InvalidGrantException("无法获取用户信息");
        }
        OAuth2Request storedOAuth2Request = this.requestFactory.createOAuth2Request(client, tokenRequest);
        PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(user, null, user.getAuthorities());
        authentication.setDetails(user);
        return new OAuth2Authentication(storedOAuth2Request, authentication);
    }

    protected abstract UserInfoVO getUserInfo(Map<String, String> parameters);
}
