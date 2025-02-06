package com.springboot.config;

import com.springboot.auth.AuthorityUtils;
import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.filter.JwtVerificationFilter;
import com.springboot.auth.handler.AuthenticationFailureHandler;
import com.springboot.auth.handler.AuthenticationSuccessHandler;
import com.springboot.auth.jwt.JwtTokenizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final AuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, AuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                // 동일 출처(same origin)에서 iframe 사용을 허용(H2 콘솔)
                .headers().frameOptions().sameOrigin()
                .and()
                // CSRF 보호 비활성화
                .csrf().disable()
                // CORS 설정 활성화
                .cors(Customizer.withDefaults())
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // form 로그인 방식 비활성화
                .formLogin().disable()
                // HTTP Basic 인증 방식 비활성화
                .httpBasic().disable()
                .apply(new CustomFilterConfigurer())
                .and()
                // 모든 요청에 대해 인증 없이 접근 허용
                .authorizeHttpRequests(authorize ->
                        authorize
                                .antMatchers(HttpMethod.POST, "/*/members").permitAll()
                                .antMatchers(HttpMethod.PATCH, "/*/members/**").hasRole("USER")
                                .antMatchers(HttpMethod.GET, "/*/members").hasRole("ADMIN")
                                .antMatchers(HttpMethod.GET, "/*/members/**").hasAnyRole("USER", "ADMIN")
                                .antMatchers(HttpMethod.DELETE, "/*/members/**").hasRole("USER")
                                .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    // 비밀번호 암호화를 위한 PasswordEncoder Bean 생성
    public PasswordEncoder passwordEncoder(){
        // DelegatingPasswordEncoder를 생성하여 다양한 암호화 방식 지원 (기본 BCrypt)
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // CORS 설정 정의하는 Bean
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        // CORS 설정 객체 생성
        CorsConfiguration configuration = new CorsConfiguration();
        // 모든 출처에서의 요청 허용
        configuration.setAllowedOrigins(Arrays.asList("*"));
        // 허용할 HTTP 메서드 지정
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));

        // URL 패턴에 위에서 정의한 CORS 설정 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    // 만든 JwtAuthenticationFilter 를 등록하기 위한 메서드
    // filterChain에 등록하려면 configure 객체가 있어야해서 만듦.
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        @Override
        public void configure(HttpSecurity builder){
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            // Override 안하면 default 주소는 "/login"
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new AuthenticationFailureHandler());
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler());

            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, authorityUtils);

            builder.addFilter(jwtAuthenticationFilter)
                    // 항상 인증 뒤에 검증 필터 추가하겠다.
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }
}
