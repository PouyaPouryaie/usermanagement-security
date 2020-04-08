package ir.bigz.spring.restSecuritySample.oauth;

import ir.bigz.spring.restSecuritySample.exception.OAuth2AuthenticationProcessingException;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.model.AuthProvider;
import ir.bigz.spring.restSecuritySample.oauth.user.OAuth2UserInfo;
import ir.bigz.spring.restSecuritySample.oauth.user.OAuth2UserInfoFactory;
import ir.bigz.spring.restSecuritySample.security.UserPrincipal;
import ir.bigz.spring.restSecuritySample.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<ApplicationUser> userOptional = userService.getUserByEmail(oAuth2UserInfo.getEmail());
        ApplicationUser user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
            if(!user.getAuthProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        user.getAuthProvider() + " account. Please use your " + user.getAuthProvider() +
                        " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private ApplicationUser registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        ApplicationUser user = new ApplicationUser();

        user.setAuthProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        //user.setProviderId(oAuth2UserInfo.getId());
        user.setUserName(oAuth2UserInfo.getName());
        user.setEmail(oAuth2UserInfo.getEmail());
        //user.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userService.createUser(user);
    }

    private ApplicationUser updateExistingUser(ApplicationUser existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setUserName(oAuth2UserInfo.getName());
        //existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userService.updateUser(existingUser);
    }
}
