package ir.bigz.spring.restSecuritySample.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {

    private final SecretKey secretKey;

    public JwtTokenUtil(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public String generateToken(Authentication authentication, String subject, Date expirationTime){
        return Jwts.builder()
                .setSubject(subject) //username
                .claim("authorities", authentication.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(expirationTime)
                .signWith(secretKey)
                .compact();
    }

    public String generateTokenWithRole(List< ? extends GrantedAuthority> authorities, String subject, Date expirationTime){
        return Jwts.builder()
                .setSubject(subject) //username
                .claim("authorities", authorities)
                .setIssuedAt(new Date())
                .setExpiration(expirationTime)
                .signWith(secretKey)
                .compact();
    }

    public Jws<Claims> parserToken(String token){
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver){
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (
                username.equals(userDetails.getUsername())
                        && !isTokenExpired(token));
    }

    //new
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            System.out.println("Invalid JWT signature");
            //logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            System.out.println("Invalid JWT token");
            //logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            System.out.println("Expired JWT token");
            //logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            System.out.println("Unsupported JWT token");
            //logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string is empty.");
            //logger.error("JWT claims string is empty.");
        }
        return false;
    }

    /*    public String generateToken(User user) {
        return doGenerateToken(user.getUsername());
    }

    private String doGenerateToken(String subject) {

        Claims claims = Jwts.claims().setSubject(subject);
        claims.put("scopes", Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuer("http://devglan.com")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_SECONDS*1000))
                .signWith(SignatureAlgorithm.HS256, SIGNING_KEY)
                .compact();
    }*/
}
