package com.example.security;

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

// =============================================================================
// Shared JWT builder
// =============================================================================

class JwtTestBuilder {

    static String build(Long exp, String issuer, String scopeJson) {
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"RS256\"}".getBytes());
        String payloadJson = "{\"sub\":\"user@example.com\""
            + (exp      != null ? ",\"exp\":"   + exp              : "")
            + (issuer   != null ? ",\"iss\":\"" + issuer + "\""    : "")
            + (scopeJson != null ? ",\"scp\":"  + scopeJson        : "")
            + "}";
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());
        return header + "." + payload + ".fakesig";
    }

    static String valid(String issuer)   { return build(Instant.now().plusSeconds(3600).getEpochSecond(), issuer, null); }
    static String expired(String issuer) { return build(Instant.now().minusSeconds(3600).getEpochSecond(), issuer, null); }
    static String noExp(String issuer)   { return build(null, issuer, null); }
    static String noIssuer()             { return build(Instant.now().plusSeconds(3600).getEpochSecond(), null, null); }
}

// =============================================================================
// OktaPropertiesTest
// =============================================================================

class OktaPropertiesTest {

    private OktaProperties props;

    @BeforeEach
    void setUp() { props = new OktaProperties(); }

    @Nested
    class Defaults {
        @Test void issuerValidation_defaultsToTrue()     { assertTrue(props.isIssuerValidation()); }
        @Test void validationType_defaultsToUri()        { assertEquals("uri", props.getValidationType()); }
        @Test void audience_defaultsToNull()             { assertNull(props.getAudience()); }
        @Test void issuerUris_defaultsToNull()           { assertNull(props.getIssuerUris()); }
        @Test void issuerHostPatterns_defaultsToNull()   { assertNull(props.getIssuerHostPatterns()); }
    }

    @Nested
    class Setters {
        @Test void audience()               { props.setAudience("abc"); assertEquals("abc", props.getAudience()); }
        @Test void issuerValidationFalse()  { props.setIssuerValidation(false); assertFalse(props.isIssuerValidation()); }
        @Test void validationTypePattern()  { props.setValidationType("pattern"); assertEquals("pattern", props.getValidationType()); }
        @Test void validationTypeDynamic()  { props.setValidationType("dynamic"); assertEquals("dynamic", props.getValidationType()); }

        @Test
        void issuerHostPatterns_multipleValues() {
            List<String> patterns = List.of("*.abc.com", "*.oktapreview.com", "uatabctech.oktapreview.com");
            props.setIssuerHostPatterns(patterns);
            assertEquals(3, props.getIssuerHostPatterns().size());
            assertEquals("*.abc.com", props.getIssuerHostPatterns().get(0));
            assertEquals("*.oktapreview.com", props.getIssuerHostPatterns().get(1));
            assertEquals("uatabctech.oktapreview.com", props.getIssuerHostPatterns().get(2));
        }

        @Test
        void issuerHostPatterns_singleValue() {
            props.setIssuerHostPatterns(List.of("*.abc.com"));
            assertEquals(1, props.getIssuerHostPatterns().size());
        }

        @Test
        void issuerUris_multipleValues() {
            props.setIssuerUris(List.of("https://dev.okta.com/oauth2/default", "https://prod.okta.com/oauth2/default"));
            assertEquals(2, props.getIssuerUris().size());
        }
    }
}

// =============================================================================
// OktaPropertiesBindingTest — @SpringExtension only (no server startup)
// =============================================================================

@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(OktaProperties.class)
@TestPropertySource(properties = {
    "okta.audience=abc-application",
    "okta.issuer-validation=false"
})
class Option1BindingTest {

    @Autowired private OktaProperties props;

    @Test void issuerValidationFalse()  { assertFalse(props.isIssuerValidation()); }
    @Test void audienceIsBound()        { assertEquals("abc-application", props.getAudience()); }
    @Test void issuerUrisIsNull()       { assertNull(props.getIssuerUris()); }
    @Test void patternsIsNull()         { assertNull(props.getIssuerHostPatterns()); }
}

@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(OktaProperties.class)
@TestPropertySource(properties = {
    "okta.audience=abc-application",
    "okta.issuer-validation=true",
    "okta.validation-type=uri",
    "okta.issuer-uris[0]=https://dev.okta.com/oauth2/default",
    "okta.issuer-uris[1]=https://prod.okta.com/oauth2/default"
})
class Option2BindingTest {

    @Autowired private OktaProperties props;

    @Test void validationTypeIsUri()     { assertEquals("uri", props.getValidationType()); }
    @Test void issuerUrisCount()         { assertEquals(2, props.getIssuerUris().size()); }
    @Test void patternsIsNull()          { assertNull(props.getIssuerHostPatterns()); }
}

@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(OktaProperties.class)
@TestPropertySource(properties = {
    "okta.audience=abc-application",
    "okta.issuer-validation=true",
    "okta.validation-type=pattern",
    "okta.issuer-host-patterns[0]=*.abc.com",
    "okta.issuer-host-patterns[1]=*.oktapreview.com",
    "okta.issuer-host-patterns[2]=uatabctech.oktapreview.com"
})
class Option3BindingTest {

    @Autowired private OktaProperties props;

    @Test void validationTypeIsPattern()    { assertEquals("pattern", props.getValidationType()); }
    @Test void patternsCount()              { assertEquals(3, props.getIssuerHostPatterns().size()); }
    @Test void firstPattern()              { assertEquals("*.abc.com", props.getIssuerHostPatterns().get(0)); }
    @Test void secondPattern()             { assertEquals("*.oktapreview.com", props.getIssuerHostPatterns().get(1)); }
    @Test void thirdPatternExact()         { assertEquals("uatabctech.oktapreview.com", props.getIssuerHostPatterns().get(2)); }
    @Test void issuerUrisIsNull()           { assertNull(props.getIssuerUris()); }
}

@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(OktaProperties.class)
@TestPropertySource(properties = {
    "okta.audience=abc-application",
    "okta.issuer-validation=true",
    "okta.validation-type=dynamic",
    "okta.issuer-host-patterns[0]=*.abc.com",
    "okta.issuer-host-patterns[1]=*.oktapreview.com",
    "okta.issuer-host-patterns[2]=uatabctech.oktapreview.com"
})
class Option4BindingTest {

    @Autowired private OktaProperties props;

    @Test void validationTypeIsDynamic()    { assertEquals("dynamic", props.getValidationType()); }
    @Test void patternsCount()              { assertEquals(3, props.getIssuerHostPatterns().size()); }
    @Test void firstPattern()              { assertEquals("*.abc.com", props.getIssuerHostPatterns().get(0)); }
    @Test void issuerUrisIsNull()           { assertNull(props.getIssuerUris()); }
}

// =============================================================================
// JwtUtilsTest
// =============================================================================

class JwtUtilsTest {

    @Nested
    class DecodePayload {
        @Test void validJwt_decodesSubject()         { assertEquals("user@example.com", JwtUtils.decodePayload(JwtTestBuilder.valid("https://dev.abc.com/oauth2/default")).get("sub")); }
        @Test void twoParts_throwsIllegalArgument()  { assertThrows(IllegalArgumentException.class, () -> JwtUtils.decodePayload("header.payload")); }
        @Test void fourParts_throwsIllegalArgument() { assertThrows(IllegalArgumentException.class, () -> JwtUtils.decodePayload("a.b.c.d")); }
        @Test void invalidBase64_throwsException()   { assertThrows(IllegalArgumentException.class, () -> JwtUtils.decodePayload("hdr.!!invalid!!.sig")); }
    }

    @Nested
    class IsExpired {
        @Test void futureExpAsInt_false()   { Map<String, Object> c = new HashMap<>(); c.put("exp", (int) Instant.now().plusSeconds(3600).getEpochSecond()); assertFalse(JwtUtils.isExpired(c)); }
        @Test void futureExpAsLong_false()  { Map<String, Object> c = new HashMap<>(); c.put("exp", Instant.now().plusSeconds(3600).getEpochSecond()); assertFalse(JwtUtils.isExpired(c)); }
        @Test void pastExp_true()           { Map<String, Object> c = new HashMap<>(); c.put("exp", (int) Instant.now().minusSeconds(3600).getEpochSecond()); assertTrue(JwtUtils.isExpired(c)); }
        @Test void missingExp_true()        { assertTrue(JwtUtils.isExpired(new HashMap<>())); }
    }

    @Nested
    class MatchesSinglePattern {
        @Test void wildcardSubdomain_matches()       { assertTrue(JwtUtils.matchesSinglePattern("https://dev.abc.com/oauth2/default", "*.abc.com")); }
        @Test void wildcardDeepSubdomain_matches()   { assertTrue(JwtUtils.matchesSinglePattern("https://dev.okta.abc.com/oauth2/default", "*.abc.com")); }
        @Test void differentDomain_noMatch()         { assertFalse(JwtUtils.matchesSinglePattern("https://dev.xyz.com/oauth2/default", "*.abc.com")); }
        @Test void rootDomain_noMatch()              { assertFalse(JwtUtils.matchesSinglePattern("https://abc.com/oauth2/default", "*.abc.com")); }
        @Test void nullIssuer_false()                { assertFalse(JwtUtils.matchesSinglePattern(null, "*.abc.com")); }
        @Test void nullPattern_false()               { assertFalse(JwtUtils.matchesSinglePattern("https://dev.abc.com", null)); }
        @Test void malformedUri_false()              { assertFalse(JwtUtils.matchesSinglePattern("not a uri", "*.abc.com")); }
        @Test void caseInsensitive()                 { assertTrue(JwtUtils.matchesSinglePattern("https://DEV.ABC.COM/oauth2/default", "*.abc.com")); }
        @Test void pathIgnored()                     { assertTrue(JwtUtils.matchesSinglePattern("https://dev.abc.com/some/path", "*.abc.com")); }
        @Test void exactMatch_noWildcard()           { assertTrue(JwtUtils.matchesSinglePattern("https://uatabctech.oktapreview.com/oauth2/default", "uatabctech.oktapreview.com")); }
        @Test void exactMatch_wrongHost_noMatch()    { assertFalse(JwtUtils.matchesSinglePattern("https://dev.oktapreview.com/oauth2/default", "uatabctech.oktapreview.com")); }
    }

    @Nested
    class MatchesAnyPattern {

        private static final List<String> PATTERNS = List.of(
            "*.abc.com",
            "*.oktapreview.com",
            "uatabctech.oktapreview.com"
        );

        @Test void matchesFirstPattern()            { assertTrue(JwtUtils.matchesAnyPattern("https://dev.abc.com/oauth2/default", PATTERNS)); }
        @Test void matchesSecondPattern()           { assertTrue(JwtUtils.matchesAnyPattern("https://dev.oktapreview.com/oauth2/default", PATTERNS)); }
        @Test void matchesThirdPatternExact()       { assertTrue(JwtUtils.matchesAnyPattern("https://uatabctech.oktapreview.com/oauth2/default", PATTERNS)); }
        @Test void matchesNone_returnsFalse()       { assertFalse(JwtUtils.matchesAnyPattern("https://dev.evil.com/oauth2/default", PATTERNS)); }
        @Test void emptyPatternList_returnsFalse()  { assertFalse(JwtUtils.matchesAnyPattern("https://dev.abc.com/oauth2/default", Collections.emptyList())); }
        @Test void nullPatternList_returnsFalse()   { assertFalse(JwtUtils.matchesAnyPattern("https://dev.abc.com/oauth2/default", null)); }
        @Test void nullIssuer_returnsFalse()        { assertFalse(JwtUtils.matchesAnyPattern(null, PATTERNS)); }

        @Test
        void singlePattern_list_works() {
            assertTrue(JwtUtils.matchesAnyPattern("https://dev.abc.com/oauth2/default", List.of("*.abc.com")));
        }
    }

    @Nested
    class FindMatchingPattern {

        private static final List<String> PATTERNS = List.of("*.abc.com", "*.oktapreview.com");

        @Test void returnsMatchedPattern()          { assertEquals("*.abc.com", JwtUtils.findMatchingPattern("https://dev.abc.com/oauth2/default", PATTERNS)); }
        @Test void returnsSecondMatchedPattern()    { assertEquals("*.oktapreview.com", JwtUtils.findMatchingPattern("https://dev.oktapreview.com/oauth2/default", PATTERNS)); }
        @Test void returnsNullWhenNoMatch()         { assertNull(JwtUtils.findMatchingPattern("https://dev.evil.com/oauth2/default", PATTERNS)); }
        @Test void returnsNullForEmptyList()        { assertNull(JwtUtils.findMatchingPattern("https://dev.abc.com/oauth2/default", Collections.emptyList())); }
        @Test void returnsNullForNullList()         { assertNull(JwtUtils.findMatchingPattern("https://dev.abc.com/oauth2/default", null)); }
    }
}

// =============================================================================
// Option 1 — ExpiryOnlyValidationStrategyTest
// =============================================================================

class ExpiryOnlyValidationStrategyTest {

    private ExpiryOnlyValidationStrategy strategy;

    @BeforeEach
    void setUp() { strategy = new ExpiryOnlyValidationStrategy(); }

    @Nested
    class ValidToken {
        @Test void nonExpired_returnsSuccess()  { assertTrue(strategy.validate(JwtTestBuilder.valid(null)).isValid()); }
        @Test void subjectInClaims()            { assertEquals("user@example.com", strategy.validate(JwtTestBuilder.valid(null)).getClaims().get("sub")); }
        @Test void anyIssuerAccepted()          { assertTrue(strategy.validate(JwtTestBuilder.valid("https://any.evil.com")).isValid()); }
        @Test void noIssuerAccepted()           { assertTrue(strategy.validate(JwtTestBuilder.noIssuer()).isValid()); }
    }

    @Nested
    class InvalidToken {
        @Test void expired_returnsFailure()          { assertFalse(strategy.validate(JwtTestBuilder.expired(null)).isValid()); }
        @Test void expired_errorContainsExpired()    { assertTrue(strategy.validate(JwtTestBuilder.expired(null)).getErrorMessage().contains("expired")); }
        @Test void noExpClaim_returnsFailure()        { assertFalse(strategy.validate(JwtTestBuilder.noExp(null)).isValid()); }
        @Test void malformed_twoParts_failure()      { assertFalse(strategy.validate("header.payload").isValid()); }
        @Test void malformed_errorContainsMalformed(){ assertTrue(strategy.validate("header.payload").getErrorMessage().contains("Malformed")); }
    }
}

// =============================================================================
// Option 2 — UriValidationStrategyTest
// =============================================================================

@ExtendWith(MockitoExtension.class)
class UriValidationStrategyTest {

    @Mock private AccessTokenVerifier verifier1;
    @Mock private AccessTokenVerifier verifier2;
    @Mock private Jwt mockJwt;

    @Nested
    class Constructor {
        @Test void throwsWhenNull()      { assertThrows(IllegalArgumentException.class, () -> new UriValidationStrategy(null)); }
        @Test void throwsWhenEmpty()     { assertThrows(IllegalArgumentException.class, () -> new UriValidationStrategy(Collections.emptyList())); }
        @Test void succeedsWithOne()     { assertDoesNotThrow(() -> new UriValidationStrategy(List.of(verifier1))); }
        @Test void succeedsWithTwo()     { assertDoesNotThrow(() -> new UriValidationStrategy(List.of(verifier1, verifier2))); }
    }

    @Nested
    class Validate {
        @Test
        void firstVerifierMatches_noSecondCall() throws Exception {
            UriValidationStrategy strategy = new UriValidationStrategy(List.of(verifier1, verifier2));
            when(verifier1.decode("token")).thenReturn(mockJwt);
            when(mockJwt.getClaims()).thenReturn(Map.of("sub", "user@example.com"));
            assertTrue(strategy.validate("token").isValid());
            verify(verifier2, never()).decode(any());
        }

        @Test
        void firstFails_secondMatches() throws Exception {
            UriValidationStrategy strategy = new UriValidationStrategy(List.of(verifier1, verifier2));
            when(verifier1.decode("token")).thenThrow(new JwtVerificationException("wrong issuer"));
            when(verifier2.decode("token")).thenReturn(mockJwt);
            when(mockJwt.getClaims()).thenReturn(Map.of("sub", "user@example.com"));
            assertTrue(strategy.validate("token").isValid());
        }

        @Test
        void allVerifiersFail_returnsFailure() throws Exception {
            UriValidationStrategy strategy = new UriValidationStrategy(List.of(verifier1, verifier2));
            when(verifier1.decode("token")).thenThrow(new JwtVerificationException("expired"));
            when(verifier2.decode("token")).thenThrow(new JwtVerificationException("bad sig"));
            assertFalse(strategy.validate("token").isValid());
        }

        @Test
        void claimsAreCopied() throws Exception {
            UriValidationStrategy strategy = new UriValidationStrategy(List.of(verifier1));
            Map<String, Object> claims = Map.of("sub", "user@example.com", "iss", "https://dev.okta.com");
            when(verifier1.decode("token")).thenReturn(mockJwt);
            when(mockJwt.getClaims()).thenReturn(claims);
            assertEquals(claims, strategy.validate("token").getClaims());
        }
    }
}

// =============================================================================
// Option 3 — PatternValidationStrategyTest
// =============================================================================

class PatternValidationStrategyTest {

    private static final List<String> MULTI_PATTERNS = List.of(
        "*.abc.com",
        "*.oktapreview.com",
        "uatabctech.oktapreview.com"
    );

    @Nested
    class Constructor {
        @Test void throwsWhenNull()          { assertThrows(IllegalArgumentException.class, () -> new PatternValidationStrategy(null)); }
        @Test void throwsWhenEmpty()         { assertThrows(IllegalArgumentException.class, () -> new PatternValidationStrategy(Collections.emptyList())); }
        @Test void succeedsWithOnePattern()  { assertDoesNotThrow(() -> new PatternValidationStrategy(List.of("*.abc.com"))); }
        @Test void succeedsWithMultiple()    { assertDoesNotThrow(() -> new PatternValidationStrategy(MULTI_PATTERNS)); }
        @Test void storesPatterns()          { assertEquals(3, new PatternValidationStrategy(MULTI_PATTERNS).getIssuerHostPatterns().size()); }
        @Test void trimsPatterns()           { assertEquals("*.abc.com", new PatternValidationStrategy(List.of("  *.abc.com  ")).getIssuerHostPatterns().get(0)); }
    }

    @Nested
    class SinglePatternValidation {

        private PatternValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new PatternValidationStrategy(List.of("*.abc.com")); }

        @Test void matchingIssuer_returnsSuccess()     { assertTrue(strategy.validate(JwtTestBuilder.valid("https://dev.abc.com/oauth2/default")).isValid()); }
        @Test void nonMatchingIssuer_returnsFailure()  { assertFalse(strategy.validate(JwtTestBuilder.valid("https://dev.xyz.com/oauth2/default")).isValid()); }
        @Test void expired_returnsFailure()            { assertFalse(strategy.validate(JwtTestBuilder.expired("https://dev.abc.com/oauth2/default")).isValid()); }
        @Test void noIssuerClaim_returnsFailure()      { assertFalse(strategy.validate(JwtTestBuilder.noIssuer()).isValid()); }
        @Test void noExpClaim_returnsFailure()          { assertFalse(strategy.validate(JwtTestBuilder.noExp("https://dev.abc.com/oauth2/default")).isValid()); }
        @Test void malformed_returnsFailure()          { assertFalse(strategy.validate("not.valid").isValid()); }
    }

    @Nested
    class MultiPatternValidation {

        private PatternValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new PatternValidationStrategy(MULTI_PATTERNS); }

        @Test void matchesFirstPattern_abcDomain() {
            assertTrue(strategy.validate(JwtTestBuilder.valid("https://dev.abc.com/oauth2/default")).isValid());
        }

        @Test void matchesFirstPattern_differentAbcSubdomain() {
            assertTrue(strategy.validate(JwtTestBuilder.valid("https://prod.abc.com/oauth2/default")).isValid());
        }

        @Test void matchesSecondPattern_oktapreviewWildcard() {
            assertTrue(strategy.validate(JwtTestBuilder.valid("https://dev.oktapreview.com/oauth2/default")).isValid());
        }

        @Test void matchesThirdPattern_exactHost() {
            assertTrue(strategy.validate(JwtTestBuilder.valid("https://uatabctech.oktapreview.com/oauth2/default")).isValid());
        }

        @Test void noMatchInAnyPattern_returnsFailure() {
            ValidationResult r = strategy.validate(JwtTestBuilder.valid("https://dev.evil.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("did not match any configured host pattern"));
        }

        @Test void expiredToken_matchingPattern_returnsFailure() {
            assertFalse(strategy.validate(JwtTestBuilder.expired("https://dev.abc.com/oauth2/default")).isValid());
        }

        @Test void missingIssuer_returnsFailure() {
            ValidationResult r = strategy.validate(JwtTestBuilder.noIssuer());
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("missing"));
        }
    }
}

// =============================================================================
// Option 4 — DynamicIssuerValidationStrategyTest
// =============================================================================

class DynamicIssuerValidationStrategyTest {

    private static final List<String> MULTI_PATTERNS = List.of(
        "*.abc.com",
        "*.oktapreview.com",
        "uatabctech.oktapreview.com"
    );

    @Nested
    class Constructor {
        @Test void throwsWhenPatternsNull()     { assertThrows(IllegalArgumentException.class, () -> new DynamicIssuerValidationStrategy(null, "abc")); }
        @Test void throwsWhenPatternsEmpty()    { assertThrows(IllegalArgumentException.class, () -> new DynamicIssuerValidationStrategy(Collections.emptyList(), "abc")); }
        @Test void succeedsWithOnePattern()     { assertDoesNotThrow(() -> new DynamicIssuerValidationStrategy(List.of("*.abc.com"), "abc-application")); }
        @Test void succeedsWithMultiplePatterns(){ assertDoesNotThrow(() -> new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc-application")); }
        @Test void succeedsWithNullAudience()   { assertDoesNotThrow(() -> new DynamicIssuerValidationStrategy(List.of("*.abc.com"), null)); }
        @Test void storesPatterns()             { assertEquals(3, new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc").getIssuerHostPatterns().size()); }
        @Test void storesAudience()             { assertEquals("abc-application", new DynamicIssuerValidationStrategy(List.of("*.abc.com"), "abc-application").getAudience()); }
        @Test void cacheStartsEmpty()           { assertEquals(0, new DynamicIssuerValidationStrategy(List.of("*.abc.com"), "abc").getCacheSize()); }
    }

    @Nested
    class MalformedToken {

        private DynamicIssuerValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc-application"); }

        @Test void twoParts_returnsFailure()        { assertFalse(strategy.validate("header.payload").isValid()); }
        @Test void fourParts_returnsFailure()        { assertFalse(strategy.validate("a.b.c.d").isValid()); }
        @Test void errorContainsMalformed()          { assertTrue(strategy.validate("header.payload").getErrorMessage().contains("Malformed")); }
    }

    @Nested
    class MissingIssuer {

        private DynamicIssuerValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc-application"); }

        @Test void noIssClaim_returnsFailure() {
            ValidationResult r = strategy.validate(JwtTestBuilder.noIssuer());
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("missing"));
        }
    }

    @Nested
    class PatternMismatch {

        private DynamicIssuerValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc-application"); }

        @Test void wrongDomain_rejectsWithoutNetworkCall() {
            ValidationResult r = strategy.validate(JwtTestBuilder.valid("https://dev.evil.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("did not match any configured host pattern"));
            assertEquals(0, strategy.getCacheSize());
        }

        @Test void allPatternsChecked_noneMatch() {
            // Issuer that does not match *.abc.com, *.oktapreview.com, or exact uatabctech.oktapreview.com
            assertFalse(strategy.validate(JwtTestBuilder.valid("https://dev.notallowed.com/oauth2/default")).isValid());
            assertEquals(0, strategy.getCacheSize());
        }

        @Test void expiredTokenWithWrongDomain_failsOnPattern() {
            // Pattern check happens before expiry check
            ValidationResult r = strategy.validate(JwtTestBuilder.expired("https://dev.evil.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("did not match any configured host pattern"));
        }
    }

    @Nested
    class MultiPatternMatching {

        private DynamicIssuerValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc-application"); }

        @Test void firstPatternMatch_abcDomain_proceedsToVerifier() {
            // Token passes pattern check (dev.abc.com matches *.abc.com)
            // Then expired check catches it before network call
            ValidationResult r = strategy.validate(JwtTestBuilder.expired("https://dev.abc.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("expired"));  // not "did not match"
        }

        @Test void secondPatternMatch_oktapreview_proceedsToVerifier() {
            ValidationResult r = strategy.validate(JwtTestBuilder.expired("https://qa.oktapreview.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("expired"));
        }

        @Test void thirdPatternMatch_exactHost_proceedsToVerifier() {
            ValidationResult r = strategy.validate(JwtTestBuilder.expired("https://uatabctech.oktapreview.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("expired"));
        }
    }

    @Nested
    class ExpiredToken {

        private DynamicIssuerValidationStrategy strategy;

        @BeforeEach
        void setUp() { strategy = new DynamicIssuerValidationStrategy(MULTI_PATTERNS, "abc-application"); }

        @Test void expiredTokenWithValidPattern_failsBeforeJwksFetch() {
            ValidationResult r = strategy.validate(JwtTestBuilder.expired("https://dev.abc.com/oauth2/default"));
            assertFalse(r.isValid());
            assertTrue(r.getErrorMessage().contains("expired"));
            assertEquals(0, strategy.getCacheSize());  // no verifier built
        }

        @Test void noExpClaim_returnsFailure() {
            assertFalse(strategy.validate(JwtTestBuilder.noExp("https://dev.abc.com/oauth2/default")).isValid());
            assertEquals(0, strategy.getCacheSize());
        }
    }
}

// =============================================================================
// OktaJwtAuthFilterTest
// =============================================================================

@ExtendWith(MockitoExtension.class)
class OktaJwtAuthFilterTest {

    @Mock private ValidationStrategy strategy;
    @Mock private HttpServletRequest request;
    @Mock private FilterChain filterChain;

    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() { response = new MockHttpServletResponse(); SecurityContextHolder.clearContext(); }

    @AfterEach
    void tearDown() { SecurityContextHolder.clearContext(); }

    @Nested
    class Constructor {
        @Test void throwsWhenNull()  { assertThrows(IllegalArgumentException.class, () -> new OktaJwtAuthFilter(null)); }
        @Test void succeeds()        { assertDoesNotThrow(() -> new OktaJwtAuthFilter(strategy)); }
    }

    @Nested
    class NoAuthorizationHeader {
        @Test
        void nullHeader_passesThrough() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
            filter.doFilterInternal(request, response, filterChain);
            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(strategy);
        }

        @Test
        void basicAuth_passesThrough() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic dXNlcjpwYXNz");
            filter.doFilterInternal(request, response, filterChain);
            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(strategy);
        }
    }

    @Nested
    class ValidToken {
        @Test
        void success_setsAuthentication() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer valid.token");
            when(strategy.validate("valid.token")).thenReturn(ValidationResult.success(Map.of("sub", "user@example.com")));
            filter.doFilterInternal(request, response, filterChain);
            assertEquals("user@example.com", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        }

        @Test
        void whitespace_trimmed() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer   valid.token");
            when(strategy.validate("valid.token")).thenReturn(ValidationResult.success(Map.of("sub", "user@example.com")));
            filter.doFilterInternal(request, response, filterChain);
            verify(strategy).validate("valid.token");
        }

        @Test
        void rawTokenStoredAsCredentials() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer valid.token");
            when(strategy.validate("valid.token")).thenReturn(ValidationResult.success(Map.of("sub", "user@example.com")));
            filter.doFilterInternal(request, response, filterChain);
            assertEquals("valid.token", SecurityContextHolder.getContext().getAuthentication().getCredentials());
        }
    }

    @Nested
    class InvalidToken {
        @Test
        void failure_returns401() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer bad.token");
            when(strategy.validate("bad.token")).thenReturn(ValidationResult.failure("Token rejected."));
            filter.doFilterInternal(request, response, filterChain);
            assertEquals(401, response.getStatus());
            assertTrue(response.getContentAsString().contains("Token rejected."));
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void response_hasJsonFields() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer bad.token");
            when(strategy.validate("bad.token")).thenReturn(ValidationResult.failure("expired"));
            filter.doFilterInternal(request, response, filterChain);
            String body = response.getContentAsString();
            assertTrue(body.contains("\"error\""));
            assertTrue(body.contains("\"Unauthorized\""));
            assertTrue(body.contains("\"message\""));
        }
    }

    @Nested
    class ScopeExtraction {
        @Test
        void scopeAsList_mapsToAuthorities() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "user@example.com");
            claims.put("scp", Arrays.asList("read:items", "write:items"));
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token");
            when(strategy.validate("token")).thenReturn(ValidationResult.success(claims));
            filter.doFilterInternal(request, response, filterChain);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertTrue(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_read:items")));
            assertTrue(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_write:items")));
        }

        @Test
        void scopeAsString_mapsToAuthorities() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "user@example.com");
            claims.put("scp", "read:items write:items");
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token");
            when(strategy.validate("token")).thenReturn(ValidationResult.success(claims));
            filter.doFilterInternal(request, response, filterChain);
            assertTrue(SecurityContextHolder.getContext().getAuthentication()
                .getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_read:items")));
        }

        @Test
        void noScope_emptyAuthorities() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token");
            when(strategy.validate("token")).thenReturn(ValidationResult.success(Map.of("sub", "user@example.com")));
            filter.doFilterInternal(request, response, filterChain);
            assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().isEmpty());
        }

        @Test
        void unexpectedScopeType_emptyAuthorities() throws Exception {
            OktaJwtAuthFilter filter = new OktaJwtAuthFilter(strategy);
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "user@example.com");
            claims.put("scp", 12345);
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token");
            when(strategy.validate("token")).thenReturn(ValidationResult.success(claims));
            filter.doFilterInternal(request, response, filterChain);
            assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().isEmpty());
        }
    }
}

// =============================================================================
// WebSecurityConfigTest
// =============================================================================

class WebSecurityConfigTest {

    private static final List<String> MULTI_PATTERNS = List.of("*.abc.com", "*.oktapreview.com", "uatabctech.oktapreview.com");

    private OktaProperties buildProps(boolean issuerValidation, String validationType,
                                       List<String> issuerUris, List<String> patterns) {
        OktaProperties props = new OktaProperties();
        props.setAudience("abc-application");
        props.setIssuerValidation(issuerValidation);
        props.setValidationType(validationType);
        props.setIssuerUris(issuerUris);
        props.setIssuerHostPatterns(patterns);
        return props;
    }

    @Nested
    class Option1_ExpiryOnly {
        @Test void returnsExpiryOnlyStrategy()          { assertInstanceOf(ExpiryOnlyValidationStrategy.class, new WebSecurityConfig(buildProps(false, "uri", null, null)).validationStrategy()); }
        @Test void ignoresValidationType()              { assertInstanceOf(ExpiryOnlyValidationStrategy.class, new WebSecurityConfig(buildProps(false, "dynamic", null, null)).validationStrategy()); }
        @Test void filterCreated()                      { assertNotNull(new WebSecurityConfig(buildProps(false, "uri", null, null)).oktaJwtAuthFilter()); }
    }

    @Nested
    class Option2_UriList {
        @Test void returnsUriStrategy() {
            assertInstanceOf(UriValidationStrategy.class,
                new WebSecurityConfig(buildProps(true, "uri", List.of("https://dev.okta.com/oauth2/default"), null)).validationStrategy());
        }

        @Test void throwsWhenUrisNull() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "uri", null, null)).validationStrategy());
        }

        @Test void throwsWhenUrisEmpty() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "uri", Collections.emptyList(), null)).validationStrategy());
        }

        @Test void multipleUris_allBuilt() {
            assertDoesNotThrow(() -> new WebSecurityConfig(buildProps(true, "uri",
                List.of("https://dev.okta.com/oauth2/default", "https://prod.okta.com/oauth2/default"), null)).validationStrategy());
        }
    }

    @Nested
    class Option3_Pattern {
        @Test void returnsPatternStrategy_singlePattern() {
            assertInstanceOf(PatternValidationStrategy.class,
                new WebSecurityConfig(buildProps(true, "pattern", null, List.of("*.abc.com"))).validationStrategy());
        }

        @Test void returnsPatternStrategy_multiplePatterns() {
            assertInstanceOf(PatternValidationStrategy.class,
                new WebSecurityConfig(buildProps(true, "pattern", null, MULTI_PATTERNS)).validationStrategy());
        }

        @Test void throwsWhenPatternsNull() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "pattern", null, null)).validationStrategy());
        }

        @Test void throwsWhenPatternsEmpty() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "pattern", null, Collections.emptyList())).validationStrategy());
        }
    }

    @Nested
    class Option4_Dynamic {
        @Test void returnsDynamicStrategy_singlePattern() {
            assertInstanceOf(DynamicIssuerValidationStrategy.class,
                new WebSecurityConfig(buildProps(true, "dynamic", null, List.of("*.abc.com"))).validationStrategy());
        }

        @Test void returnsDynamicStrategy_multiplePatterns() {
            assertInstanceOf(DynamicIssuerValidationStrategy.class,
                new WebSecurityConfig(buildProps(true, "dynamic", null, MULTI_PATTERNS)).validationStrategy());
        }

        @Test void throwsWhenPatternsNull() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "dynamic", null, null)).validationStrategy());
        }

        @Test void throwsWhenPatternsEmpty() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "dynamic", null, Collections.emptyList())).validationStrategy());
        }
    }

    @Nested
    class UnknownValidationType {
        @Test void throwsIllegalStateException() {
            assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "unknown", null, null)).validationStrategy());
        }

        @Test void errorMessageListsSupportedTypes() {
            IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new WebSecurityConfig(buildProps(true, "unknown", null, null)).validationStrategy());
            assertTrue(ex.getMessage().contains("uri"));
            assertTrue(ex.getMessage().contains("pattern"));
            assertTrue(ex.getMessage().contains("dynamic"));
        }
    }
}
