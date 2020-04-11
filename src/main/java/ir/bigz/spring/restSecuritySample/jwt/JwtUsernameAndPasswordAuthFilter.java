package ir.bigz.spring.restSecuritySample.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class JwtUsernameAndPasswordAuthFilter extends UsernamePasswordAuthenticationFilter {

    //for authenticate user from request, first check username is exists then check password is correct
    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final JwtTokenUtil jwtTokenUtil;


    public JwtUsernameAndPasswordAuthFilter(AuthenticationManager authenticationManager,
                                            JwtConfig jwtConfig,
                                            JwtTokenUtil jwtTokenUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthRequest usernameAndPasswordAuthRequest = new ObjectMapper().
                    readValue(request.getInputStream(), UsernameAndPasswordAuthRequest.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    usernameAndPasswordAuthRequest.getUsername(),
                    usernameAndPasswordAuthRequest.getPassword());

            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

        } catch (IOException io) {
            throw new RuntimeException(io);
        }
    }

    //after authentication success this method call and we use send token for user
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        Date date = new Date();
        long t = date.getTime();
        Date expirationTime = new Date(t + jwtConfig.getTokenExpirationAfterMilliSecond());

        String token = jwtTokenUtil.generateToken(authResult, authResult.getName(), expirationTime);

        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
    }
}
