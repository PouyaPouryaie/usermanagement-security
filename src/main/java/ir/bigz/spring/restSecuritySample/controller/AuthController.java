package ir.bigz.spring.restSecuritySample.controller;

import ir.bigz.spring.restSecuritySample.exception.BadRequestException;
import ir.bigz.spring.restSecuritySample.jwt.JwtConfig;
import ir.bigz.spring.restSecuritySample.jwt.JwtTokenUtil;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.model.AuthProvider;
import ir.bigz.spring.restSecuritySample.payload.ApiResponse;
import ir.bigz.spring.restSecuritySample.payload.AuthResponse;
import ir.bigz.spring.restSecuritySample.payload.LoginRequest;
import ir.bigz.spring.restSecuritySample.payload.SignUpRequest;
import ir.bigz.spring.restSecuritySample.security.UserPermission;
import ir.bigz.spring.restSecuritySample.service.UserPermissionService;
import ir.bigz.spring.restSecuritySample.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private Environment env;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private UserPermissionService userPermissionService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtConfig jwtConfig;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );


        SecurityContextHolder.getContext().setAuthentication(authentication);

        Date date = new Date();
        long t = date.getTime();
        Date expirationTime = new Date(t + jwtConfig.getTokenExpirationAfterMilliSecond());
        String token = jwtTokenUtil.generateToken(authentication, authentication.getName(), expirationTime);

        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userService.getUserByEmail(signUpRequest.getEmail()).isPresent()) {
            throw new BadRequestException("Email address already in use.");
        }

        // Creating user's account
        ApplicationUser user = new ApplicationUser();
        user.setUserName(signUpRequest.getName());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(signUpRequest.getPassword());
        user.setAuthProvider(AuthProvider.local);

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        ApplicationUser result = userService.createUser(user);

        Set<UserPermission> userPermissionForRole = userPermissionService.getUserPermissionForRole(env.getProperty("application.basicRole.user"));
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
        for(UserPermission userPermission: userPermissionForRole){
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(userPermission.getPermissionName());
            simpleGrantedAuthorities.add(simpleGrantedAuthority);
        }

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user.getUserName(),
                null,
                simpleGrantedAuthorities
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        Date date = new Date();
        long t = date.getTime();
        Date expirationTime = new Date(t + jwtConfig.getTokenExpirationAfterMilliSecond());
        String token = jwtTokenUtil.generateTokenWithRole(simpleGrantedAuthorities, user.getUserName(), expirationTime);


        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/user/{username}")
                .buildAndExpand(result.getUserName()).toUri();

        return ResponseEntity.created(location)
                .header(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token)
                .body(new ApiResponse(true, "User registered successfully"));
    }
}
