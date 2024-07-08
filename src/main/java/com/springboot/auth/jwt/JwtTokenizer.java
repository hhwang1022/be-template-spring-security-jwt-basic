package com.springboot.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenizer {
    @Getter
    @Value("${jwt.key}")
    private String secretKey;
    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;
    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    public String encodeBase64SecretKey(String secretKey){
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generatedAccessToken(Map<String, Object> clamis,
                                       String subject,
                                       Date expiretion,
                                       String base64EncodedeSecretkey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedeSecretkey) ;

        return Jwts.builder()
                .setClaims(clamis)
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiretion)
                .signWith(key)
                .compact();
    }

    public String generatedRefreshToken(String subject,
                                       Date expiretion,
                                       String base64EncodedeSecretkey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedeSecretkey) ;

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiretion)
                .signWith(key)
                .compact();
    }

    public Jws<Claims> getClaims(String jws, String base64EncodedeSecretkey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedeSecretkey);

        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                // 검증까지 포함됨(다르면 검증오류가 뜸)
                .parseClaimsJws(jws);

        return claims;
    }

    public void verifySignature(String jws, String base64EncodedeSecretkey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedeSecretkey);

        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);
    }

    private Key getKeyFromBase64EncodedKey(String base64EncodedeSecretkey){
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedeSecretkey);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        return key;
    }

    public Date getTokenExpiration(int expirationMinutes){
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);
        Date expiration = calendar.getTime();
        return expiration;
    }
}
