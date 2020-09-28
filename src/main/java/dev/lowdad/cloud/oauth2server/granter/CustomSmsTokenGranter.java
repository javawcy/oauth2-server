package dev.lowdad.cloud.oauth2server.granter;

import dev.lowdad.cloud.common.model.vo.UserInfoVO;
import dev.lowdad.cloud.oauth2server.service.UserService;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.Map;

/**
 * <p>
 * 短信验证码方式
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/27
 */
public class CustomSmsTokenGranter extends AbstractCustomTokenGranter {

    protected UserService userDetailsService;

    public CustomSmsTokenGranter(UserService userDetailsService, AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, "sms_code");
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected UserInfoVO getUserInfo(Map<String, String> parameters) {
        String mobile = parameters.get("mobile");
        String smsCode = parameters.get("sms_code");
        return userDetailsService.loadByMobileAndSmsCode(mobile, smsCode);
    }
}
