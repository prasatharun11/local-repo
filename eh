package com.yourapp.api.error;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;

@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE) // <-- ensures this runs LAST
public class FallbackGlobalExceptionHandler {

    private static final String TRACE_ID = "traceId";

    // ---------- DTO (kept inside same file for simplicity) ----------
    public static class ApiError {
        public final String code;
        public final String message;
        public final String traceId;
        public final Instant timestamp;
        public final String path;

        public ApiError(String code, String message, String traceId, String path) {
            this.code = code;
            this.message = message;
            this.traceId = traceId;
            this.timestamp = Instant.now();
            this.path = path;
        }
    }

    // ---------- Utility ----------
    private String ensureTraceId(HttpServletRequest request) {
        String traceId = MDC.get(TRACE_ID);

        if (traceId == null) {
            traceId = (String) request.getAttribute(TRACE_ID);
        }

        if (traceId == null) {
            traceId = UUID.randomUUID().toString();
            MDC.put(TRACE_ID, traceId);
        }

        return traceId;
    }

    // ---------- Catch-all handler ----------
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnhandledException(
            Exception ex,
            HttpServletRequest request
    ) {

        String traceId = ensureTraceId(request);

        // Full internal logging (never expose this to client)
        org.slf4j.LoggerFactory.getLogger(getClass())
                .error("Unhandled exception. traceId={}, path={}", traceId, request.getRequestURI(), ex);

        ApiError body = new ApiError(
                "INTERNAL_SERVER_ERROR",
                "Something went wrong. Please contact support.",
                traceId,
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body);
    }
}