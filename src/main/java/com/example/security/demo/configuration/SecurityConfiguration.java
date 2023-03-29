package com.example.security.demo.configuration;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

	private final AuthenticationManager authenticationManager;

	private final SecurityContextRepository securityContextRepository;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.httpBasic().disable().csrf().disable().cors(c -> {
			c.configurationSource(request -> {
				CorsConfiguration config = new CorsConfiguration();
				config.setAllowedOrigins(List.of("*"));
				config.setAllowedMethods(List.of("*"));
				return config;
			});
		}).securityContext().securityContextRepository(securityContextRepository).and()
				.authenticationManager(authenticationManager).sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeHttpRequests()
				.requestMatchers(HttpMethod.POST, "/post/**").hasAnyRole("REALTOR", "LESSOR", "LESSEE")
				.requestMatchers(HttpMethod.PUT, "/post/**").hasAnyRole("REALTOR", "LESSOR", "LESSEE")
				.requestMatchers(HttpMethod.POST, "/comment/**").hasAnyRole("REALTOR", "LESSOR", "LESSEE")
				.requestMatchers(HttpMethod.PUT, "/comment/**").hasAnyRole("REALTOR", "LESSOR", "LESSEE")
				.requestMatchers(HttpMethod.PUT, "/like/**").hasAnyRole("REALTOR", "LESSOR", "LESSEE").anyRequest()
				.denyAll();

		return http.build();
	}

}