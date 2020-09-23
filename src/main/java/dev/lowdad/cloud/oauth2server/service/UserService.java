package dev.lowdad.cloud.oauth2server.service;

import dev.lowdad.cloud.oauth2server.domain.User;
import dev.lowdad.cloud.oauth2server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * <p>
 * Oauth2 用户读取
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/22
 */
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(s);

        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        if (!user.isEnabled()) {
            throw new DisabledException("不可用");
        } else if (!user.isAccountNonLocked()) {
            throw new LockedException("已冻结");
        } else if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException("账户已过期");
        } else if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("权限过期");
        }
        return user;
    }

}
