package ir.bigz.spring.restSecuritySample.oauth.user;

import ir.bigz.spring.restSecuritySample.exception.OAuth2AuthenticationProcessingException;
import ir.bigz.spring.restSecuritySample.model.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
