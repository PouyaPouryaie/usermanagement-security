package ir.bigz.spring.restSecuritySample.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import ir.bigz.spring.restSecuritySample.security.SecurityUserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final JwtTokenUtil jwtTokenUtil;
    private final SecurityUserService securityUserService;

    public JwtTokenVerifier(JwtConfig jwtConfig,
                            JwtTokenUtil jwtTokenUtil, SecurityUserService securityUserService) {
        this.jwtConfig = jwtConfig;
        this.jwtTokenUtil = jwtTokenUtil;
        this.securityUserService = securityUserService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {

            String username = null;
            String token = null;

            String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

            token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

            if (StringUtils.hasText(token) && jwtTokenUtil.validateToken(token)) {
                String usernameFromToken = jwtTokenUtil.getUsernameFromToken(token);

                UserDetails userDetails = securityUserService.loadUserByUsername(usernameFromToken);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

/*        String username = null;
        String token = null;

        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        //check if authorizationHeader is null or
        // token dose not exists so reject request in this filter and dose not authenticated
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try {

            username = jwtTokenUtil.getUsernameFromToken(token);

            UserDetails userDetails = securityUserService.loadUserByUsername(username);

            if(jwtTokenUtil.validateToken(token, userDetails)){

                Jws<Claims> claimsJws = jwtTokenUtil.parserToken(token);

                Claims body = claimsJws.getBody();

                //username = body.getSubject();

                var authorities = (List<Map<String, String>>) body.get("authorities");

                Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                        .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                        .collect(Collectors.toSet());

                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        simpleGrantedAuthorities
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);

                //new
                Date date = new Date();
                long nowDateTime = date.getTime();
                long exDateTime = body.getExpiration().getTime();
                if (exDateTime - nowDateTime < 3600000) {
                    Date expirationTime = new Date(exDateTime + 3600000);

                    token = jwtTokenUtil.generateToken(authentication, username, expirationTime);

                }
                response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token   );
            }

        } catch (IllegalArgumentException e) {
            logger.error("an error occured during getting username from token", e);
        } catch (ExpiredJwtException e) {
            logger.warn("the token is expired and not valid anymore", e);
        }*/

        filterChain.doFilter(request, response);
    }
}
