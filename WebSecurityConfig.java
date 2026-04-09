package com.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.CollectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

// =============================================================================
// OktaProperties
//
// application.yml — Option 1 (expiry only):
//   okta:
//     audience: abc-application
//     issuer-validation: false
//
// application.yml — Option 2 (configured uri list):
//   okta:
//     audience: abc-application
//     issuer-validation: true
//     validation-type: uri
//     issuer-uris:
//       - https://dev-123456.okta.com/oauth2/default
//       - https://prod-901234.okta.com/oauth2/aus9m2EXAMPLE
//
// application.yml — Option 3 (multiple domain patterns + expiry):
//   okta:
//     audience: abc-application
//     issuer-validation: true
//     validation-type: pattern
//     issuer-host-patterns:
//       - "*.abc.com"
//       - "*.oktapreview.com"
//       - "uatabctech.oktapreview.com"
//
// application.yml — Option 4 (multiple domain patterns + dynamic issuer + RS256):
//   okta:
//     audience: abc-application
//     issuer-validation: true
//     validation-type: dynamic
//     issuer-host-patterns:
//       - "*.abc.com"
//       - "*.oktapreview.com"
//       - "uatabctech.oktapreview.com"
// =============================================================================

@Getter
@Setter
@ConfigurationProperties(prefix = "okta")
class OktaProperties {
    private String audience;
    private boolean issuerValidation  = true;
    private String validationType     = "uri";
    private List<String> issuerUris;
    private List<String> issuerHostPatterns;   // supports multiple patterns for option 3 & 4
}

// =============================================================================
// ValidationResult
// =============================================================================

class ValidationResult {

    private final boolean valid;
    private final Map<String, Object> claims;
    private final String errorMessage;

    private ValidationResult(boolean valid, Map<String, Object> claims, String errorMessage) {
        this.valid        = valid;
        this.claims       = claims;
        this.errorMessage = errorMessage;
    }

    static ValidationResult success(Map<String, Object> claims) {
        return new ValidationResult(true, claims, null);
    }

    static ValidationResult failure(String errorMessage) {
        return new ValidationResult(false, null, errorMessage);
    }

    public boolean isValid()               { return valid; }
    public Map<String, Object> getClaims() { return claims; }
    public String getErrorMessage()        { return errorMessage; }
}

// =============================================================================
// ValidationStrategy
// =============================================================================

interface ValidationStrategy {
    ValidationResult validate(String token);
}

// =============================================================================
// JwtUtils — shared helpers
// =============================================================================

class JwtUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwtUtils() {}

    @SuppressWarnings("unchecked")
    static Map<String, Object> decodePayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("JWT must have exactly 3 parts.");
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(parts[1]);
            return MAPPER.readValue(bytes, Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode JWT payload: " + e.getMessage());
        }
    }

    static boolean isExpired(Map<String, Object> claims) {
        Object exp = claims.get("exp");
        if (exp == null) return true;
        return Instant.now().isAfter(Instant.ofEpochSecond(((Number) exp).longValue()));
    }

    /**
     * Checks if the issuer URI host matches a single pattern.
     *
     * Pattern rules:
     *   *.abc.com            → any subdomain of abc.com at any depth
     *   uatabctech.okta.com  → exact host match only (no wildcard)
     *
     * Path is intentionally ignored — only the host is checked.
     */
    static boolean matchesSinglePattern(String issuer, String pattern) {
        if (issuer == null || pattern == null) return false;
        try {
            String host = URI.create(issuer).getHost();
            if (host == null) return false;
            if (!pattern.startsWith("*")) {
                return host.equalsIgnoreCase(pattern.trim());
            }
            String suffix = pattern.trim().substring(1);
            return host.toLowerCase().endsWith(suffix.toLowerCase());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if the issuer URI host matches ANY pattern in the list.
     * Returns true on the first match found.
     *
     * Example patterns list:
     *   - *.abc.com                  → dev.abc.com, prod.abc.com
     *   - *.oktapreview.com          → dev.oktapreview.com
     *   - uatabctech.oktapreview.com → exact match only
     */
    static boolean matchesAnyPattern(String issuer, List<String> patterns) {
        if (CollectionUtils.isEmpty(patterns)) return false;
        return patterns.stream().anyMatch(pattern -> matchesSinglePattern(issuer, pattern));
    }

    /**
     * Returns the first pattern from the list that matched the issuer, or null if none matched.
     * Useful for logging which pattern accepted the issuer.
     */
    static String findMatchingPattern(String issuer, List<String> patterns) {
        if (CollectionUtils.isEmpty(patterns)) return null;
        return patterns.stream()
            .filter(pattern -> matchesSinglePattern(issuer, pattern))
            .findFirst()
            .orElse(null);
    }
}

// =============================================================================
// Option 1 — ExpiryOnlyValidationStrategy
// Checks: Expiry only
// =============================================================================

class ExpiryOnlyValidationStrategy implements ValidationStrategy {

    private static final Logger log = LoggerFactory.getLogger(ExpiryOnlyValidationStrategy.class);

    ExpiryOnlyValidationStrategy() {
        log.info("[Option 1] ExpiryOnlyValidationStrategy initialized.");
    }

    @Override
    public ValidationResult validate(String token) {
        try {
            Map<String, Object> claims = JwtUtils.decodePayload(token);

            if (JwtUtils.isExpired(claims)) {
                log.warn("[Option 1] Token is expired.");
                return ValidationResult.failure("Token has expired.");
            }

            log.debug("[Option 1] Token is valid (expiry only).");
            return ValidationResult.success(claims);

        } catch (IllegalArgumentException e) {
            log.warn("[Option 1] Malformed token — {}", e.getMessage());
            return ValidationResult.failure("Malformed token: " + e.getMessage());
        }
    }
}

// =============================================================================
// Option 2 — UriValidationStrategy
// Checks: RS256 signature + issuer (must match configured list) + audience + expiry
// =============================================================================

class UriValidationStrategy implements ValidationStrategy {

    private static final Logger log = LoggerFactory.getLogger(UriValidationStrategy.class);

    private final List<AccessTokenVerifier> verifiers;

    UriValidationStrategy(List<AccessTokenVerifier> verifiers) {
        if (CollectionUtils.isEmpty(verifiers)) {
            throw new IllegalArgumentException(
                "[Option 2] UriValidationStrategy requires at least one AccessTokenVerifier."
            );
        }
        this.verifiers = verifiers;
        log.info("[Option 2] UriValidationStrategy initialized with {} verifier(s).", verifiers.size());
    }

    @Override
    public ValidationResult validate(String token) {
        log.debug("[Option 2] Validating against {} configured issuer(s).", verifiers.size());

        for (int i = 0; i < verifiers.size(); i++) {
            try {
                com.okta.jwt.Jwt jwt = verifiers.get(i).decode(token);
                log.debug("[Option 2] Accepted by verifier #{} (of {}).", i + 1, verifiers.size());
                return ValidationResult.success(new HashMap<>(jwt.getClaims()));
            } catch (JwtVerificationException e) {
                log.trace("[Option 2] Verifier #{} rejected — {}", i + 1, e.getMessage());
            }
        }

        return ValidationResult.failure("Token rejected by all configured issuer URI verifiers.");
    }
}

// =============================================================================
// Option 3 — PatternValidationStrategy
// Checks: iss host must match at least one configured pattern + expiry
// Supports multiple patterns: *.abc.com, *.oktapreview.com, exact hosts, etc.
// No signature verification — no network calls.
// =============================================================================

class PatternValidationStrategy implements ValidationStrategy {

    private static final Logger log = LoggerFactory.getLogger(PatternValidationStrategy.class);

    private final List<String> issuerHostPatterns;

    PatternValidationStrategy(List<String> issuerHostPatterns) {
        if (CollectionUtils.isEmpty(issuerHostPatterns)) {
            throw new IllegalArgumentException(
                "[Option 3] PatternValidationStrategy requires at least one issuer-host-pattern."
            );
        }
        this.issuerHostPatterns = issuerHostPatterns.stream()
            .map(String::trim)
            .collect(Collectors.toList());
        log.info("[Option 3] PatternValidationStrategy initialized with {} pattern(s): {}.",
            this.issuerHostPatterns.size(), this.issuerHostPatterns);
    }

    @Override
    public ValidationResult validate(String token) {
        try {
            Map<String, Object> claims = JwtUtils.decodePayload(token);

            if (JwtUtils.isExpired(claims)) {
                log.warn("[Option 3] Token is expired.");
                return ValidationResult.failure("Token has expired.");
            }

            String issuer = (String) claims.get("iss");
            if (issuer == null || issuer.isBlank()) {
                log.warn("[Option 3] Token has no iss claim.");
                return ValidationResult.failure("Token is missing the issuer (iss) claim.");
            }

            String matchedPattern = JwtUtils.findMatchingPattern(issuer, issuerHostPatterns);
            if (matchedPattern == null) {
                log.warn("[Option 3] Issuer '{}' did not match any of the {} configured pattern(s): {}.",
                    issuer, issuerHostPatterns.size(), issuerHostPatterns);
                return ValidationResult.failure(
                    "Issuer '" + issuer + "' did not match any configured host pattern."
                );
            }

            log.debug("[Option 3] Issuer '{}' matched pattern '{}'.", issuer, matchedPattern);
            return ValidationResult.success(claims);

        } catch (IllegalArgumentException e) {
            log.warn("[Option 3] Malformed token — {}", e.getMessage());
            return ValidationResult.failure("Malformed token: " + e.getMessage());
        }
    }

    List<String> getIssuerHostPatterns() { return issuerHostPatterns; }
}

// =============================================================================
// Option 4 — DynamicIssuerValidationStrategy
// Checks: iss host must match at least one configured pattern + RS256 signature + audience + expiry
// iss is read from token itself, verified against pattern list, then used to fetch JWKS.
// Verifiers are cached per issuer URI.
// Supports multiple patterns: *.abc.com, *.oktapreview.com, exact hosts, etc.
// =============================================================================

class DynamicIssuerValidationStrategy implements ValidationStrategy {

    private static final Logger log = LoggerFactory.getLogger(DynamicIssuerValidationStrategy.class);

    private final List<String> issuerHostPatterns;
    private final String audience;
    private final ConcurrentHashMap<String, AccessTokenVerifier> verifierCache = new ConcurrentHashMap<>();

    DynamicIssuerValidationStrategy(List<String> issuerHostPatterns, String audience) {
        if (CollectionUtils.isEmpty(issuerHostPatterns)) {
            throw new IllegalArgumentException(
                "[Option 4] DynamicIssuerValidationStrategy requires at least one issuer-host-pattern."
            );
        }
        this.issuerHostPatterns = issuerHostPatterns.stream()
            .map(String::trim)
            .collect(Collectors.toList());
        this.audience = audience;
        log.info("[Option 4] DynamicIssuerValidationStrategy initialized — patterns: {}, audience: '{}'.",
            this.issuerHostPatterns, this.audience);
    }

    @Override
    public ValidationResult validate(String token) {
        // Step 1 — Decode payload (no network, no signature yet)
        Map<String, Object> rawClaims;
        try {
            rawClaims = JwtUtils.decodePayload(token);
        } catch (IllegalArgumentException e) {
            log.warn("[Option 4] Malformed token — {}", e.getMessage());
            return ValidationResult.failure("Malformed token: " + e.getMessage());
        }

        // Step 2 — Read iss claim
        String issuer = (String) rawClaims.get("iss");
        if (issuer == null || issuer.isBlank()) {
            log.warn("[Option 4] Token has no iss claim.");
            return ValidationResult.failure("Token is missing the issuer (iss) claim.");
        }

        // Step 3 — Validate iss host against ALL patterns BEFORE any network call (trust boundary)
        String matchedPattern = JwtUtils.findMatchingPattern(issuer, issuerHostPatterns);
        if (matchedPattern == null) {
            log.warn("[Option 4] Issuer '{}' did not match any of the {} configured pattern(s): {}.",
                issuer, issuerHostPatterns.size(), issuerHostPatterns);
            return ValidationResult.failure(
                "Issuer '" + issuer + "' did not match any configured host pattern."
            );
        }

        log.debug("[Option 4] Issuer '{}' matched pattern '{}'.", issuer, matchedPattern);

        // Step 4 — Check expiry early (avoids unnecessary JWKS fetch)
        if (JwtUtils.isExpired(rawClaims)) {
            log.warn("[Option 4] Token from issuer '{}' is expired.", issuer);
            return ValidationResult.failure("Token has expired.");
        }

        // Step 5 — Get or build verifier for this issuer (cached after first use)
        AccessTokenVerifier verifier = verifierCache.computeIfAbsent(issuer, this::buildVerifier);

        // Step 6 — Full Okta verification: RS256 signature + audience + expiry
        try {
            com.okta.jwt.Jwt validatedJwt = verifier.decode(token);
            log.debug("[Option 4] Token validated for issuer '{}'.", issuer);
            return ValidationResult.success(new HashMap<>(validatedJwt.getClaims()));
        } catch (JwtVerificationException e) {
            log.warn("[Option 4] Okta verification failed for issuer '{}' — {}", issuer, e.getMessage());
            return ValidationResult.failure("Token verification failed: " + e.getMessage());
        }
    }

    private AccessTokenVerifier buildVerifier(String issuerUri) {
        log.info("[Option 4] Building and caching verifier for issuer '{}'.", issuerUri);
        return JwtVerifiers.accessTokenVerifierBuilder()
            .setIssuer(issuerUri)
            .setAudience(audience)
            .build();
    }

    List<String> getIssuerHostPatterns() { return issuerHostPatterns; }
    String getAudience()                 { return audience; }
    int getCacheSize()                   { return verifierCache.size(); }
}

// =============================================================================
// OktaJwtAuthFilter
// =============================================================================

class OktaJwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OktaJwtAuthFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final ValidationStrategy strategy;

    OktaJwtAuthFilter(ValidationStrategy strategy) {
        if (strategy == null) {
            throw new IllegalArgumentException("ValidationStrategy must not be null.");
        }
        this.strategy = strategy;
        log.info("OktaJwtAuthFilter initialized with strategy: {}", strategy.getClass().getSimpleName());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        ValidationResult result = strategy.validate(token);

        if (result.isValid()) {
            setAuthentication(result.getClaims(), token);
            log.debug("Token validated for subject '{}' on {} {}",
                result.getClaims().get("sub"), request.getMethod(), request.getRequestURI());
            filterChain.doFilter(request, response);
        } else {
            log.warn("Token validation failed on {} {}: {}",
                request.getMethod(), request.getRequestURI(), result.getErrorMessage());
            sendUnauthorized(response, result.getErrorMessage());
        }
    }

    private void setAuthentication(Map<String, Object> claims, String rawToken) {
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken(
                claims.get("sub"), rawToken, extractAuthorities(claims)
            )
        );
    }

    @SuppressWarnings("unchecked")
    private List<SimpleGrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Object scp = claims.get("scp");
        if (scp instanceof List) {
            return ((List<String>) scp).stream()
                .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                .collect(Collectors.toList());
        }
        if (scp instanceof String) {
            return Arrays.stream(((String) scp).split("\\s+"))
                .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        SecurityContextHolder.clearContext();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"" + message + "\"}");
    }
}

// =============================================================================
// WebSecurityConfig
// =============================================================================

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(OktaProperties.class)
public class WebSecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    private final OktaProperties oktaProperties;

    public WebSecurityConfig(OktaProperties oktaProperties) {
        this.oktaProperties = oktaProperties;
    }

    @Bean
    public ValidationStrategy validationStrategy() {
        if (!oktaProperties.isIssuerValidation()) {
            log.info("Option 1 — ExpiryOnlyValidationStrategy selected.");
            return new ExpiryOnlyValidationStrategy();
        }

        String type = oktaProperties.getValidationType();

        switch (type.toLowerCase()) {
            case "uri":
                log.info("Option 2 — UriValidationStrategy selected.");
                return new UriValidationStrategy(buildUriVerifiers());

            case "pattern":
                log.info("Option 3 — PatternValidationStrategy selected.");
                return new PatternValidationStrategy(requirePatterns());

            case "dynamic":
                log.info("Option 4 — DynamicIssuerValidationStrategy selected.");
                return new DynamicIssuerValidationStrategy(
                    requirePatterns(), oktaProperties.getAudience()
                );

            default:
                throw new IllegalStateException(
                    "Unknown okta.validation-type: '" + type +
                    "'. Supported values: 'uri', 'pattern', 'dynamic'."
                );
        }
    }

    @Bean
    public OktaJwtAuthFilter oktaJwtAuthFilter() {
        return new OktaJwtAuthFilter(validationStrategy());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(oktaJwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private List<AccessTokenVerifier> buildUriVerifiers() {
        List<String> uris = oktaProperties.getIssuerUris();
        if (CollectionUtils.isEmpty(uris)) {
            throw new IllegalStateException(
                "okta.issuer-uris must contain at least one entry when validation-type is 'uri'."
            );
        }
        return uris.stream()
            .map(uri -> JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer(uri.trim())
                .setAudience(oktaProperties.getAudience())
                .build())
            .collect(Collectors.toList());
    }

    private List<String> requirePatterns() {
        List<String> patterns = oktaProperties.getIssuerHostPatterns();
        if (CollectionUtils.isEmpty(patterns)) {
            throw new IllegalStateException(
                "okta.issuer-host-patterns must contain at least one entry " +
                "when validation-type is 'pattern' or 'dynamic'."
            );
        }
        return patterns;
    }
}
