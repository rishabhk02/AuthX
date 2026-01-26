package com.authx.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/register", "/auth/verify-email",
                                "/auth/resend-verification", "/auth/forgot-password", "/auth/reset-password",
                                "/auth/login", "/auth/verify-otp")
                        .permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    public static List<String> getPublicEndpoints() {
        return List.of(
                "POST:/auth/register",
                "POST:/auth/verify-email",
                "POST:/auth/resend-verification",
                "POST:/auth/login",
                "POST:/auth/verify-otp",
                "POST:/auth/forgot-password",
                "POST:/auth/reset-password",
                "GET:/v3/api-docs/**",
                "POST:/v3/api-docs/**",
                "PUT:/v3/api-docs/**",
                "DELETE:/v3/api-docs/**",
                "PATCH:/v3/api-docs/**",
                "GET:/swagger-ui/**",
                "POST:/swagger-ui/**",
                "PUT:/swagger-ui/**",
                "DELETE:/swagger-ui/**",
                "PATCH:/swagger-ui/**",
                "GET:/swagger-ui.html",
                "POST:/swagger-ui.html",
                "PUT:/swagger-ui.html",
                "DELETE:/swagger-ui.html",
                "PATCH:/swagger-ui.html",
                "GET:/webjars/**",
                "POST:/webjars/**",
                "PUT:/webjars/**",
                "DELETE:/webjars/**",
                "PATCH:/webjars/**");
    }

    public static boolean isPublicEndpoint(HttpServletRequest request) {
        if (request == null)
            return false;

        String method = request.getMethod();
        String path = request.getServletPath();

        for (String def : getPublicEndpoints()) {
            String[] parts = def.split(":", 2);
            if (parts.length != 2)
                continue;

            String expectedMethod = parts[0];
            String pattern = parts[1];

            // Method matching
            if (!expectedMethod.equalsIgnoreCase(method)) {
                continue;
            }

            // Prefix matching
            if (pattern.endsWith("/**")) {
                String prefix = pattern.substring(0, pattern.length() - 3);
                if (path.startsWith(prefix))
                    return true;
            } else if (pattern.equals(path)) {
                return true;
            }
        }
        return false;
    }
}