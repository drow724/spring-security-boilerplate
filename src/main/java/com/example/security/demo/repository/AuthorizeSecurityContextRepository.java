package com.example.security.demo.repository;

import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import com.example.security.demo.entity.Member;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthorizeSecurityContextRepository implements SecurityContextRepository {

	private final AuthenticationManager authenticationManager;

	private final MemberRedisRepository repository;

	private final String headerName = "Authorization";

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	@Override
	public boolean containsContext(HttpServletRequest request) {
		return getContext(request) != null;
	}

	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		return loadDeferredContext(requestResponseHolder.getRequest()).get();
	}

	@Override
	public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
		Supplier<SecurityContext> supplier = () -> getContext(request);
		return new SupplierDeferredSecurityContext(supplier, this.securityContextHolderStrategy);
	}

	private SecurityContext getContext(HttpServletRequest request) {
		String role = request.getHeader("Authentication").split(" ")[0];
		String id = request.getHeader("Authentication").split(" ")[1];
		Member member = repository.findByIdAndRole(id, role).orElseThrow();
		Authentication auth = new UsernamePasswordAuthenticationToken(member, request.getHeader(headerName),
				member.getAuthorities());
		return new SecurityContextImpl(authenticationManager.authenticate(auth));
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		request.setAttribute(this.headerName, context);
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	static final class SupplierDeferredSecurityContext implements DeferredSecurityContext {

		private static final Log logger = LogFactory.getLog(SupplierDeferredSecurityContext.class);

		private final Supplier<SecurityContext> supplier;

		private final SecurityContextHolderStrategy strategy;

		private SecurityContext securityContext;

		private boolean missingContext;

		SupplierDeferredSecurityContext(Supplier<SecurityContext> supplier, SecurityContextHolderStrategy strategy) {
			this.supplier = supplier;
			this.strategy = strategy;
		}

		@Override
		public SecurityContext get() {
			init();
			return this.securityContext;
		}

		@Override
		public boolean isGenerated() {
			init();
			return this.missingContext;
		}

		private void init() {
			if (this.securityContext != null) {
				return;
			}

			this.securityContext = this.supplier.get();
			this.missingContext = (this.securityContext == null);
			if (this.missingContext) {
				this.securityContext = this.strategy.createEmptyContext();
				if (logger.isTraceEnabled()) {
					logger.trace(LogMessage.format("Created %s", this.securityContext));
				}
			}
		}

	}
}
