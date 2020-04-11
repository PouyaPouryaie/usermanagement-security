package ir.bigz.spring.restSecuritySample.filter;

import com.google.common.base.Strings;
import ir.bigz.spring.restSecuritySample.jwt.JwtConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class CustomAuthorizeFilter extends OncePerRequestFilter {

    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        //check if authorizationHeader is null or
        // token dose not exists so reject request in this filter and dose not authenticated
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        List<String> endPointRequest = Arrays.asList(request.getRequestURI().split("/"));

        if(endPointRequest.size() == 0){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("token"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("oauth"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("login"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("oauth2"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("auth"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("webjars"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("api"))){
            filterChain.doFilter(request, response);
        }
        else if(endPointRequest.stream().anyMatch(s -> s.equals("user"))){
            filterChain.doFilter(request, response);
        }
        else{
            Map<String, String> endPointRequestMap = new HashMap<>();
            for(String s: endPointRequest){
                endPointRequestMap.put(s, s);
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

            boolean authorize = false;

            authorize = authorities.stream()
                    .anyMatch(o -> endPointRequestMap.get(o.getAuthority()) != null);


            if(authorize){
                filterChain.doFilter(request, response);
            }
            else{
                throw new IllegalAccessError(String.format("use %s not access", authentication.getName()));
            }
        }
    }
}
