package dev.lowdad.cloud.oauth2server.granter;

import dev.lowdad.cloud.oauth2server.domain.UserInfoVO;
import dev.lowdad.cloud.oauth2server.service.UserService;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.Map;

/**
 * <p>
 * 手机号&密码验证
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/27
 */
public class CustomMobilePassTokenGranter extends AbstractCustomTokenGranter {

    protected UserService userDetailsService;

    public CustomMobilePassTokenGranter(UserService userDetailsService, AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, "pwd");
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected UserInfoVO getUserInfo(Map<String, String> parameters) {
        String mobile = parameters.get("mobile");
        String password = parameters.get("password");
        return userDetailsService.loadUserByMobileAndPassword(mobile, password);
    }
}
