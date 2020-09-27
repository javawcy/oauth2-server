package dev.lowdad.cloud.oauth2server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * <p>
 * jackson 配置
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/27
 */
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
    }
}