package com.authenticationsystem.auth_api.securityJwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import com.authenticationsystem.auth_api.security.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtUtils {

	private static final Logger

	logger = LoggerFactory.getLogger(JwtUtils.class);

	@Value(" $ { app.jwtSecret } ")
	private String jwtSecret;

	@Value("${app.jwtExpirationMs}")
	private int jwtExpirationMs;

	public String generateJwtToken(UserDetailsImpl userPrincipal) {

		return generateTokenFromUsername(userPrincipal.getUsername());
	}

	public String generateTokenFromUsername(String username) {

		return Jwts.builder()
				.setSubject((username))
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(key(), SignatureAlgorithm.HS256)
				.compact();
	}

	private Key key() {

		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

	}

	public String getUserNameFromJwtToken(String token) {

		return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody().getSubject();

	}

	public boolean validateJwtToken(String authToken) {

		try {

			Jwts.parserBuilder()
			.setSigningKey(key())
			.build()
			.parse(authToken);

			return true;

		} catch (MalformedJwtException e) {

			logger.error("Jeton JWT invalide : {}", e.getMessage());
		}

		catch (ExpiredJwtException e) {

			logger.error("Le jeton JWT a expiré : {}", e.getMessage());

		} catch (UnsupportedJwtException e) {

			logger.error("Le jeton JWT n'est pas pris en charge : {}", e.getMessage());

		} catch (IllegalArgumentException e) {

			logger.error("La chaîne de revendications JWT est vide : {}", e.getMessage());

		}

		return false;
	}
}
