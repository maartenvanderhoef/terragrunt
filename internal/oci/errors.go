package oci

import (
	"fmt"
	"strings"
)

// OCIError is the base interface for all OCI-related errors.
// It provides a common way to identify and handle OCI errors.
type OCIError interface {
	error
	OCIError() string
}

// OCIAuthenticationError represents an error that occurred during authentication with an OCI registry.
type OCIAuthenticationError struct {
	registry           string
	reason             string
	attemptedMethods   []string
	lastAttemptedMethod string
	requestID          string
}

func (e OCIAuthenticationError) Error() string {
	baseMsg := fmt.Sprintf("failed to authenticate with OCI registry %s: %s", e.registry, e.reason)
	
	if e.lastAttemptedMethod != "" {
		baseMsg += fmt.Sprintf(" (last attempted method: %s)", e.lastAttemptedMethod)
	}
	
	if len(e.attemptedMethods) > 0 {
		baseMsg += fmt.Sprintf(" (attempted methods: %v)", e.attemptedMethods)
	}
	
	if e.requestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.requestID)
	}
	
	return baseMsg
}

func (e OCIAuthenticationError) OCIError() string {
	return "authentication_error"
}

// GetAttemptedMethods returns the list of authentication methods that were attempted
func (e OCIAuthenticationError) GetAttemptedMethods() []string {
	return e.attemptedMethods
}

// GetRequestID returns the request ID for tracing
func (e OCIAuthenticationError) GetRequestID() string {
	return e.requestID
}

// OCIRegistryConnectionError represents an error that occurred when connecting to an OCI registry.
type OCIRegistryConnectionError struct {
	registry   string
	repository string
	details    string
}

func (e OCIRegistryConnectionError) Error() string {
	if e.repository != "" {
		return fmt.Sprintf("failed to connect to OCI repository %s in registry %s: %s", e.repository, e.registry, e.details)
	}
	return fmt.Sprintf("failed to connect to OCI registry %s: %s", e.registry, e.details)
}

func (e OCIRegistryConnectionError) OCIError() string {
	return "registry_connection_error"
}

// OCIReferenceResolutionError represents an error that occurred when resolving an OCI reference.
type OCIReferenceResolutionError struct {
	reference string
	registry  string
	details   string
}

func (e OCIReferenceResolutionError) Error() string {
	return fmt.Sprintf("failed to resolve OCI reference %s in registry %s: %s", e.reference, e.registry, e.details)
}

func (e OCIReferenceResolutionError) OCIError() string {
	return "reference_resolution_error"
}

// OCIBlobDownloadError represents an error that occurred when downloading a blob from an OCI registry.
type OCIBlobDownloadError struct {
	digest   string
	registry string
	details  string
}

func (e OCIBlobDownloadError) Error() string {
	return fmt.Sprintf("failed to download OCI blob %s from registry %s: %s", e.digest, e.registry, e.details)
}

func (e OCIBlobDownloadError) OCIError() string {
	return "blob_download_error"
}



// OCIRegistryUnavailableError represents an error when a registry is temporarily unavailable.
type OCIRegistryUnavailableError struct {
	Registry    string
	Cause       error
	HTTPStatus  int
	RetryAfter  string // From Retry-After header if available
	RequestID   string
}

func (e OCIRegistryUnavailableError) Error() string {
	baseMsg := fmt.Sprintf("OCI registry %s is temporarily unavailable", e.Registry)
	
	if e.HTTPStatus > 0 {
		baseMsg += fmt.Sprintf(" (HTTP %d)", e.HTTPStatus)
	}
	
	if e.RetryAfter != "" {
		baseMsg += fmt.Sprintf(" (retry after: %s)", e.RetryAfter)
	}
	
	if e.Cause != nil {
		baseMsg += fmt.Sprintf(": %v", e.Cause)
	}
	
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	
	return baseMsg
}

func (e OCIRegistryUnavailableError) OCIError() string {
	return "registry_unavailable_error"
}

func (e OCIRegistryUnavailableError) Unwrap() error {
	return e.Cause
}

// OCICredentialExpiredError represents an error when credentials have expired.
type OCICredentialExpiredError struct {
	Registry  string
	Method    string
	ExpiresAt string // If available from token
	RequestID string
}

func (e OCICredentialExpiredError) Error() string {
	baseMsg := fmt.Sprintf("credentials for OCI registry %s have expired", e.Registry)
	
	if e.Method != "" {
		baseMsg += fmt.Sprintf(" (method: %s)", e.Method)
	}
	
	if e.ExpiresAt != "" {
		baseMsg += fmt.Sprintf(" (expired at: %s)", e.ExpiresAt)
	}
	
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	
	return baseMsg
}

func (e OCICredentialExpiredError) OCIError() string {
	return "credential_expired_error"
}

// OCIRateLimitError represents an error when rate limits are exceeded.
type OCIRateLimitError struct {
	Registry   string
	Limit      string // From X-RateLimit-Limit header
	Remaining  string // From X-RateLimit-Remaining header
	ResetTime  string // From X-RateLimit-Reset header
	RetryAfter string // From Retry-After header
	RequestID  string
}

func (e OCIRateLimitError) Error() string {
	baseMsg := fmt.Sprintf("rate limit exceeded for OCI registry %s", e.Registry)
	
	if e.Limit != "" {
		baseMsg += fmt.Sprintf(" (limit: %s)", e.Limit)
	}
	
	if e.Remaining != "" {
		baseMsg += fmt.Sprintf(" (remaining: %s)", e.Remaining)
	}
	
	if e.ResetTime != "" {
		baseMsg += fmt.Sprintf(" (resets at: %s)", e.ResetTime)
	}
	
	if e.RetryAfter != "" {
		baseMsg += fmt.Sprintf(" (retry after: %s)", e.RetryAfter)
	}
	
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	
	return baseMsg
}

func (e OCIRateLimitError) OCIError() string {
	return "rate_limit_error"
}

// OCINetworkError represents network-related errors with detailed context.
type OCINetworkError struct {
	Registry  string
	Operation string // "dns", "tcp", "http", "tls"
	Cause     error
	RequestID string
}

func (e OCINetworkError) Error() string {
	baseMsg := fmt.Sprintf("network error connecting to OCI registry %s", e.Registry)
	
	if e.Operation != "" {
		baseMsg += fmt.Sprintf(" during %s operation", e.Operation)
	}
	
	if e.Cause != nil {
		baseMsg += fmt.Sprintf(": %v", e.Cause)
	}
	
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	
	return baseMsg
}

func (e OCINetworkError) OCIError() string {
	return "network_error"
}

func (e OCINetworkError) Unwrap() error {
	return e.Cause
}

// OCITimeoutError represents timeout errors with context about what timed out.
type OCITimeoutError struct {
	Registry  string
	Operation string // "resolve", "fetch", "ping", "auth"
	Timeout   string // Duration that was exceeded
	RequestID string
}

func (e OCITimeoutError) Error() string {
	baseMsg := fmt.Sprintf("timeout connecting to OCI registry %s", e.Registry)
	
	if e.Operation != "" {
		baseMsg += fmt.Sprintf(" during %s operation", e.Operation)
	}
	
	if e.Timeout != "" {
		baseMsg += fmt.Sprintf(" (timeout: %s)", e.Timeout)
	}
	
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	
	return baseMsg
}

func (e OCITimeoutError) OCIError() string {
	return "timeout_error"
}

// OCIPermissionError represents permission/authorization errors.
type OCIPermissionError struct {
	Registry   string
	Repository string
	Operation  string // "read", "write", "delete"
	HTTPStatus int
	RequestID  string
}

func (e OCIPermissionError) Error() string {
	baseMsg := fmt.Sprintf("permission denied for OCI registry %s", e.Registry)
	
	if e.Repository != "" {
		baseMsg += fmt.Sprintf(" repository %s", e.Repository)
	}
	
	if e.Operation != "" {
		baseMsg += fmt.Sprintf(" (%s operation)", e.Operation)
	}
	
	if e.HTTPStatus > 0 {
		baseMsg += fmt.Sprintf(" (HTTP %d)", e.HTTPStatus)
	}
	
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	
	return baseMsg
}

func (e OCIPermissionError) OCIError() string {
	return "permission_error"
}





// Helper functions for creating specific errors from common scenarios

// NewOCIErrorFromHTTPResponse creates appropriate OCI errors based on HTTP response status codes.
func NewOCIErrorFromHTTPResponse(registry, repository, operation string, statusCode int, headers map[string]string, requestID string) OCIError {
	switch statusCode {
	case 401:
		// Check if it's a credential expiration issue
		if authHeader, exists := headers["WWW-Authenticate"]; exists && strings.Contains(strings.ToLower(authHeader), "expired") {
			return OCICredentialExpiredError{
				Registry:  registry,
				Method:    "unknown", // Could be enhanced to track the method
				RequestID: requestID,
			}
		}
		return OCIPermissionError{
			Registry:   registry,
			Repository: repository,
			Operation:  operation,
			HTTPStatus: statusCode,
			RequestID:  requestID,
		}
		
	case 403:
		return OCIPermissionError{
			Registry:   registry,
			Repository: repository,
			Operation:  operation,
			HTTPStatus: statusCode,
			RequestID:  requestID,
		}
		
	case 404:
		if repository != "" {
			return OCIRegistryConnectionError{
				registry: registry,
				details:  fmt.Sprintf("repository %s not found (HTTP %d)", repository, statusCode),
			}
		}
		return OCIRegistryConnectionError{
			registry: registry,
			details:  fmt.Sprintf("registry endpoint not found (HTTP %d)", statusCode),
		}
		
	case 429:
		return OCIRateLimitError{
			Registry:   registry,
			Limit:      headers["X-RateLimit-Limit"],
			Remaining:  headers["X-RateLimit-Remaining"],
			ResetTime:  headers["X-RateLimit-Reset"],
			RetryAfter: headers["Retry-After"],
			RequestID:  requestID,
		}
		
	case 500, 502, 503, 504:
		return OCIRegistryUnavailableError{
			Registry:   registry,
			HTTPStatus: statusCode,
			RetryAfter: headers["Retry-After"],
			RequestID:  requestID,
		}
		
	default:
		return OCIRegistryConnectionError{
			registry: registry,
			details:  fmt.Sprintf("unexpected HTTP status %d during %s operation", statusCode, operation),
		}
	}
}

// NewOCINetworkErrorFromError creates a network error from a standard Go error.
func NewOCINetworkErrorFromError(registry, operation string, err error, requestID string) OCINetworkError {
	return OCINetworkError{
		Registry:  registry,
		Operation: operation,
		Cause:     err,
		RequestID: requestID,
	}
}

// NewOCITimeoutErrorFromContext creates a timeout error from context cancellation.
func NewOCITimeoutErrorFromContext(registry, operation, timeout string, requestID string) OCITimeoutError {
	return OCITimeoutError{
		Registry:  registry,
		Operation: operation,
		Timeout:   timeout,
		RequestID: requestID,
	}
}

