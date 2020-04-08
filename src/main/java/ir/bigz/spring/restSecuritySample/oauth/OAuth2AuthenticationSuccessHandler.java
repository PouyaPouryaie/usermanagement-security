package ir.bigz.spring.restSecuritySample.oauth;

import ir.bigz.spring.restSecuritySample.exception.BadRequestException;
import ir.bigz.spring.restSecuritySample.jwt.JwtConfig;
import ir.bigz.spring.restSecuritySample.jwt.JwtTokenUtil;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.model.AuthProvider;
import ir.bigz.spring.restSecuritySample.security.UserPermission;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import ir.bigz.spring.restSecuritySample.service.AppProperties;
import ir.bigz.spring.restSecuritySample.service.RoleService;
import ir.bigz.spring.restSecuritySample.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static ir.bigz.spring.restSecuritySample.oauth.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserService userService;
    private final RoleService roleService;
    private final JwtTokenUtil jwtTokenUtil;
    private final JwtConfig jwtConfig;
    private AppProperties appProperties;
    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Autowired
    private Environment env;

    @Autowired
    public OAuth2AuthenticationSuccessHandler(UserService userService, RoleService roleService, JwtTokenUtil jwtTokenUtil, JwtConfig jwtConfig, AppProperties appProperties, HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.userService = userService;
        this.roleService = roleService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.jwtConfig = jwtConfig;
        this.appProperties = appProperties;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {


        //String targetUrl = determineTargetUrl(request,response,authentication);

        if (response.isCommitted()) {
            return;
        }

/*        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);*/


        //start
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        ApplicationUser applicationUser = new ApplicationUser();

        if(userService.getUserByEmail(email).isPresent()){
            applicationUser = userService.getUserByEmail(email).get();
            //some things
        }
        else{
            applicationUser = new ApplicationUser();
            applicationUser.setEmail(email);
            applicationUser.setUserName(email);
            applicationUser.setActive(true);
            applicationUser.setAuthProvider(AuthProvider.google);
            userService.createUser(applicationUser);
            Set<UserRole> userRoleSet = new HashSet<>();
            userRoleSet.add(roleService.getUserRole("USER").get());
            applicationUser.setUserRoles(userRoleSet);
            userService.updateUser(applicationUser);

        }



        UserRole userRole = roleService.getUserRole("USER").get();
        Set<UserPermission> userPermissionsForRole = userRole.getUserPermissionsForRole();


        Set<SimpleGrantedAuthority> simpleGrantedAuthorities = userPermissionsForRole.stream()
                .map(m -> new SimpleGrantedAuthority(m.getPermissionName()))
                .collect(Collectors.toSet());

        Authentication myAuthenticationUser = new UsernamePasswordAuthenticationToken(
                applicationUser.getUserName(),
                null,
                simpleGrantedAuthorities
        );

        //new
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Date date = new Date();
        long t = date.getTime();
        Date expirationTime = new Date(t + jwtConfig.getTokenExpirationAfterMilliSecond());

        String token = jwtTokenUtil.generateToken(myAuthenticationUser, myAuthenticationUser.getName(), expirationTime);

        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);

        String redirectionUrl = UriComponentsBuilder.fromUriString(env.getProperty("application.basicUrl.home"))
                .build().toUriString();

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, redirectionUrl);

        //end


/*        DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
        Map attributes = oidcUser.getAttributes();
        String email = (String) attributes.get("email");
        ApplicationUser applicationUser = new ApplicationUser();

        if(userService.getUserByEmail(email).isPresent()){
            applicationUser = userService.getUserByEmail(email).get();
            //some things
        }
        else{
            applicationUser = new ApplicationUser();
            applicationUser.setEmail(email);
            applicationUser.setUserName(email);
            applicationUser.setActive(true);
            userService.createUser(applicationUser);
            Set<UserRole> userRoleSet = new HashSet<>();
            userRoleSet.add(roleService.getUserRole("USER").get());
            applicationUser.setUserRoles(userRoleSet);
            userService.updateUser(applicationUser);

        }



        UserRole userRole = roleService.getUserRole("USER").get();
        Set<UserPermission> userPermissionsForRole = userRole.getUserPermissionsForRole();


        Set<SimpleGrantedAuthority> simpleGrantedAuthorities = userPermissionsForRole.stream()
                .map(m -> new SimpleGrantedAuthority(m.getPermissionName()))
                .collect(Collectors.toSet());

        Authentication myAuthenticationUser = new UsernamePasswordAuthenticationToken(
                applicationUser.getUserName(),
                null,
                simpleGrantedAuthorities
        );

        //new
        Date date = new Date();
        long t = date.getTime();
        Date expirationTime = new Date(t + jwtConfig.getTokenExpirationAfterMilliSecond());

        String token = jwtTokenUtil.generateToken(myAuthenticationUser, myAuthenticationUser.getName(), expirationTime);

        //response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);

        String redirectionUrl = UriComponentsBuilder.fromUriString(env.getProperty("application.basicUrl.home"))
                .queryParam("auth_token", token)
                .build().toUriString();
        getRedirectStrategy().sendRedirect(request, response, redirectionUrl);*/
    }


    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

/*        UserRole userRole = roleService.getUserRole("USER").get();
        Set<UserPermission> userPermissionsForRole = userRole.getUserPermissionsForRole();


        Set<SimpleGrantedAuthority> simpleGrantedAuthorities = userPermissionsForRole.stream()
                .map(m -> new SimpleGrantedAuthority(m.getPermissionName()))
                .collect(Collectors.toSet());

        Authentication myAuthenticationUser = new UsernamePasswordAuthenticationToken(
                authentication.getName(),
                null,
                simpleGrantedAuthorities
        );*/

        Date date = new Date();
        long t = date.getTime();
        Date expirationTime = new Date(t + jwtConfig.getTokenExpirationAfterMilliSecond());

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        String token = jwtTokenUtil.generateToken(authentication, authentication.getName(), expirationTime);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", token)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    // Only validate host and port. Let the clients use different paths if they want to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
