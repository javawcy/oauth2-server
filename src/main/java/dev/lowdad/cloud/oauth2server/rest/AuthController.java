package dev.lowdad.cloud.oauth2server.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * <p>
 *
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/24
 */
@RestController
@RequestMapping("/oauth2")
public class AuthController {

    @GetMapping("current")
    public Principal auth(Principal principal) {
        return principal;
    }
}
