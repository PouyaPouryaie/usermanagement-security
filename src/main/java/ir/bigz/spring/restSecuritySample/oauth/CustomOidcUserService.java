package ir.bigz.spring.restSecuritySample.oauth;

import ir.bigz.spring.restSecuritySample.exception.OAuth2AuthenticationProcessingException;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.model.AuthProvider;
import ir.bigz.spring.restSecuritySample.oauth.user.OAuth2UserInfo;
import ir.bigz.spring.restSecuritySample.oauth.user.OAuth2UserInfoFactory;
import ir.bigz.spring.restSecuritySample.security.UserPrincipal;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import ir.bigz.spring.restSecuritySample.service.RoleService;
import ir.bigz.spring.restSecuritySample.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

//@Service
public class CustomOidcUserService extends OidcUserService {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;


    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        OidcUser oidcUser = super.loadUser(userRequest);

        try {
            Map<String, Object> attributes = oidcUser.getAttributes();
            ApplicationUser userInfo = new ApplicationUser();
            userInfo.setEmail((String) attributes.get("email"));
            //userInfo.setId((String) attributes.get("sub"));
            //userInfo.setImageUrl((String) attributes.get("picture"));
            userInfo.setUserName((String) attributes.get("name"));

            Optional<ApplicationUser> user = userService.getUserByEmail(userInfo.getEmail());

            if(user.isPresent()){
                updateUser(userInfo);
            }
            else{
                ApplicationUser applicationUser = new ApplicationUser();
                applicationUser = userService.getUserByEmail(userInfo.getEmail()).get();
                applicationUser.setEmail(userInfo.getEmail());
                //user.setImageUrl(userInfo.getImageUrl());
                applicationUser.setUserName(userInfo.getUserName());
                applicationUser.setAuthProvider(AuthProvider.google);
                userService.createUser(applicationUser);

                UserRole userRole = roleService.getUserRole("USER").get();

                Set<UserRole> userRoles = new HashSet<>();
                userRoles.add(userRole);

                applicationUser.setUserRoles(userRoles);

                userService.updateUser(applicationUser);

            }

            return oidcUser;

        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }


    private void updateUser(ApplicationUser userInfo) {
        ApplicationUser applicationUser;

        if(userService.getUserByEmail(userInfo.getEmail()).isEmpty()) {
            applicationUser = new ApplicationUser();
        }

        applicationUser = userService.getUserByEmail(userInfo.getEmail()).get();
        applicationUser.setEmail(userInfo.getEmail());
        //user.setImageUrl(userInfo.getImageUrl());
        applicationUser.setUserName(userInfo.getUserName());
        applicationUser.setAuthProvider(AuthProvider.google);
        userService.updateUser(applicationUser);
    }
}
