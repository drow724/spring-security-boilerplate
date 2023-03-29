package com.example.security.demo.provider;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtProvider {

	@Value("${jwt.secret.key}")
	private String salt;

	private Key secretKey;

	private final long exp = 1000L * 60 * 60;

	@PostConstruct
	protected void init() {
		secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
	}

	public String createToken(String username, String type) {
		Claims claims = Jwts.claims().setSubject(username);
		claims.put("type", type);
		Date now = new Date();
		return Jwts.builder().setClaims(claims).setIssuedAt(now).setExpiration(new Date(now.getTime() + exp))
				.signWith(secretKey, SignatureAlgorithm.HS256).compact();
	}
	
	public String getAccount(String token) {
		return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
	}

	public String resolveToken(HttpServletRequest request) {
		return request.getHeader("Authorization");
	}

	// 토큰 검증
	public boolean validateToken(String token){

		// Bearer 검증
		if (token == null || token.equals("") || !token.substring(0, "BEARER ".length()).equalsIgnoreCase("BEARER ")) {
			throw new IllegalArgumentException();
		} else {
			token = token.split(" ")[1].trim();
		}

		Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);

		return !claims.getBody().getExpiration().before(new Date());
	}
}