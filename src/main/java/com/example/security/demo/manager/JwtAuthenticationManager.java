package com.example.security.demo.manager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.security.demo.provider.JwtProvider;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationManager implements AuthenticationManager {

	private final JwtProvider jwtProvider;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!jwtProvider.validateToken(authentication.getCredentials().toString())) {
			throw new BadCredentialsException("");
		}
		return UsernamePasswordAuthenticationToken.authenticated(authentication.getPrincipal(),
				authentication.getCredentials(), authentication.getAuthorities());
	}

}
