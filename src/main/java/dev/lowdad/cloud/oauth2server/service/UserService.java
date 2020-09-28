package dev.lowdad.cloud.oauth2server.service;

import dev.lowdad.cloud.common.model.vo.UserInfoVO;
import dev.lowdad.cloud.oauth2server.domain.User;
import dev.lowdad.cloud.oauth2server.repository.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(s);
        available(user);
        UserInfoVO infoVO = new UserInfoVO();
        BeanUtils.copyProperties(user,infoVO);
        return infoVO;
    }

    public UserInfoVO loadByMobileAndSmsCode(String mobile, String code) throws UsernameNotFoundException {
        final User user = userRepository.findByMobile(mobile);
        available(user);

        if (!user.getLastSmsCode().equals(code)) {
            throw new UsernameNotFoundException("短信验证码错误");
        }
        UserInfoVO infoVO = new UserInfoVO();
        BeanUtils.copyProperties(user,infoVO);
        return infoVO;
    }

    public UserInfoVO loadUserByMobileAndPassword(String mobile, String password) {
        final User user = userRepository.findByMobile(mobile);
        available(user);
        if (!passwordEncoder.matches(password,user.getPassword())) {
            throw new UsernameNotFoundException("密码错误");
        }
        UserInfoVO infoVO = new UserInfoVO();
        BeanUtils.copyProperties(user,infoVO);
        return infoVO;
    }

    private void available(User user) {
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
    }
}
