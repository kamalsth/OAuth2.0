package com.oauth.ks.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain oauthSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.headers().frameOptions().disable()
                .and()
                .cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("h2-console/**","h2-console").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login(withDefaults())
                .formLogin(withDefaults())
                .build();
    }
}
