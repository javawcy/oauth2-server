package dev.lowdad.cloud.oauth2server.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

/**
 * <p>
 * VO
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/27
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoVO implements AuthenticatedPrincipal, UserDetails, Serializable {

    private static final long serialVersionUID = -7570868119987757699L;
    private Long id;

    private String username;

    private String client;

    private String password;

    private String mobile;

    private String lastSmsCode;

    private Collection<? extends GrantedAuthority> authorities = new ArrayList<>();

    @Override
    public String getName() {
        return this.mobile;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
