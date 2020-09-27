package dev.lowdad.cloud.oauth2server.domain;

import lombok.Data;

import javax.persistence.*;

/**
 * <p>
 * 用户信息表
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/23
 */
@Entity
@Table(name = "user")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;

    private String client;

    private String password;

    private String mobile;

    private String lastSmsCode;
}
