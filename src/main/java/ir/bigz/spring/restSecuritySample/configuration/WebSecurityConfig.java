package ir.bigz.spring.restSecuritySample.configuration;

import ir.bigz.spring.restSecuritySample.jwt.*;
import ir.bigz.spring.restSecuritySample.oauth.*;
import ir.bigz.spring.restSecuritySample.security.SecurityUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
//@EnableOAuth2Sso
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final SecurityUserService securityUserService;
    private final PasswordEncoder passwordEncoder;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    private final JwtTokenUtil jwtTokenUtil;

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

/*    @Autowired
    private CustomOidcUserService customOidcUserService;*/

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    public WebSecurityConfig(SecurityUserService securityUserService,
                             PasswordEncoder passwordEncoder,
                             SecretKey secretKey,
                             JwtConfig jwtConfig,
                             JwtTokenUtil jwtTokenUtil) {
        this.securityUserService = securityUserService;
        this.passwordEncoder = passwordEncoder;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
        this.jwtTokenUtil = jwtTokenUtil;
    }


    /*
    By default, Spring OAuth2 uses HttpSessionOAuth2AuthorizationRequestRepository to save
    the authorization request. But, since our service is stateless, we can't save it in
    the session. We'll save the request in a Base64 encoded cookie instead.
    */
    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

/*    @Bean // default
    public AuthorizationRequestRepository customAuthorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }*/

    @Override
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(securityUserService);
        return provider;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .cors()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf()
                .disable()
                .formLogin()
                .disable()
                .httpBasic()
                .disable()
                .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
                .and()
                .authorizeRequests()
                .antMatchers("/",
                        "/oauth/**",
                        "/error",
                        "/favicon.ico",
                        "/**/*.png",
                        "/**/*.gif",
                        "/**/*.svg",
                        "/**/*.jpg",
                        "/**/*.html",
                        "/**/*.css",
                        "/webjars/**",
                        "/**/*.js")
                .permitAll()
                .antMatchers("/auth/**",
                        "/oauth2/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
                .loginPage("/oauth/custom-login")
                .authorizationEndpoint()
                .baseUri("/oauth2/authorize")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                .redirectionEndpoint()
                .baseUri("/oauth2/callback/*")
                .and()
                .userInfoEndpoint()
                .userService(customOAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);


        //custom filter
        http.addFilterBefore(new JwtTokenVerifier(jwtConfig, jwtTokenUtil, securityUserService),
                UsernamePasswordAuthenticationFilter.class);

/*        http.csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthFilter(authenticationManager(), jwtConfig, jwtTokenUtil))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, jwtTokenUtil), JwtUsernameAndPasswordAuthFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .anyRequest()
                .authenticated();*/


/*
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //.addFilter(new JwtUsernameAndPasswordAuthFilter(authenticationManager(), jwtConfig, jwtTokenUtil))
                .authorizeRequests()
                .antMatchers("/login/**","/token/**","/","/css/*", "/js/*", "/error", "/webjars/**")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll()
                )
                .oauth2Login().successHandler(customAuthenticationSuccessHandler).and()
                .addFilterBefore(new JwtTokenVerifier(jwtConfig, jwtTokenUtil, securityUserService), UsernamePasswordAuthenticationFilter.class)
*/


/*        http
                .authorizeRequests(a -> a
                        .antMatchers("/", "/error", "/webjars/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .csrf(c -> c
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll()
                )
                .oauth2Login();*/
    }
}
