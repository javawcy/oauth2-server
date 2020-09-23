package dev.lowdad.cloud.oauth2server.repository;

import dev.lowdad.cloud.oauth2server.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * <p>
 * 用户信息操作DAO
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/23
 */
public interface UserRepository extends JpaRepository<User,Long> {

    User findByUsername(String username);
}
