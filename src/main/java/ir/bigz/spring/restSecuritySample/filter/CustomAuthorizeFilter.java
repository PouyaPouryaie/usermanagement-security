package ir.bigz.spring.restSecuritySample.filter;

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

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        List<String> endPointRequest = Arrays.asList(request.getRequestURI().split("/"));

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
