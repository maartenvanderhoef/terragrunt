package oci

import (
	"fmt"
)

// OCIError is the base interface for all OCI-related errors.
// It provides a common way to identify and handle OCI errors.
type OCIError interface {
	error
	OCIError() string
}

// OCIAuthenticationError represents an error that occurred during authentication with an OCI registry.
type OCIAuthenticationError struct {
	registry  string
	reason    string
	requestID string
}

func (e OCIAuthenticationError) Error() string {
	baseMsg := fmt.Sprintf("failed to authenticate with OCI registry %s: %s", e.registry, e.reason)
	if e.requestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.requestID)
	}
	return baseMsg
}

func (e OCIAuthenticationError) OCIError() string {
	return "authentication_error"
}

// OCIRegistryConnectionError represents an error that occurred when connecting to an OCI registry.
type OCIRegistryConnectionError struct {
	registry string
	details  string
	requestID string
}

func (e OCIRegistryConnectionError) Error() string {
	return fmt.Sprintf("failed to connect to OCI registry %s: %s", e.registry, e.details)
}

func (e OCIRegistryConnectionError) OCIError() string {
	return "registry_connection_error"
}

// OCIReferenceResolutionError represents an error that occurred when resolving an OCI reference.
type OCIReferenceResolutionError struct {
	registry string
	details  string
	requestID string
}

func (e OCIReferenceResolutionError) Error() string {
	return fmt.Sprintf("failed to resolve OCI reference in registry %s: %s", e.registry, e.details)
}

func (e OCIReferenceResolutionError) OCIError() string {
	return "reference_resolution_error"
}

// OCIBlobDownloadError represents an error that occurred when downloading a blob from an OCI registry.
type OCIBlobDownloadError struct {
	registry string
	details  string
	requestID string
}

func (e OCIBlobDownloadError) Error() string {
	return fmt.Sprintf("failed to download OCI blob from registry %s: %s", e.registry, e.details)
}

func (e OCIBlobDownloadError) OCIError() string {
	return "blob_download_error"
}

// OCIRegistryUnavailableError represents an error when a registry is temporarily unavailable.
type OCIRegistryUnavailableError struct {
	Registry  string
	RequestID string
	Reason    string
}

func (e OCIRegistryUnavailableError) Error() string {
	baseMsg := fmt.Sprintf("OCI registry %s is temporarily unavailable", e.Registry)
	if e.Reason != "" {
		baseMsg += ": " + e.Reason
	}
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	return baseMsg
}

func (e OCIRegistryUnavailableError) OCIError() string {
	return "registry_unavailable_error"
}

// OCICredentialExpiredError represents an error when credentials have expired.
type OCICredentialExpiredError struct {
	Registry  string
	RequestID string
	Reason    string
}

func (e OCICredentialExpiredError) Error() string {
	baseMsg := fmt.Sprintf("credentials for OCI registry %s have expired", e.Registry)
	if e.Reason != "" {
		baseMsg += ": " + e.Reason
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
	Registry  string
	RequestID string
	Reason    string
}

func (e OCIRateLimitError) Error() string {
	baseMsg := fmt.Sprintf("rate limit exceeded for OCI registry %s", e.Registry)
	if e.Reason != "" {
		baseMsg += ": " + e.Reason
	}
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	return baseMsg
}

func (e OCIRateLimitError) OCIError() string {
	return "rate_limit_error"
}

// OCINetworkError represents network-related errors with minimal context.
type OCINetworkError struct {
	Registry  string
	RequestID string
	Reason    string
}

func (e OCINetworkError) Error() string {
	baseMsg := fmt.Sprintf("network error connecting to OCI registry %s", e.Registry)
	if e.Reason != "" {
		baseMsg += ": " + e.Reason
	}
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	return baseMsg
}

func (e OCINetworkError) OCIError() string {
	return "network_error"
}

// OCITimeoutError represents timeout errors with minimal context.
type OCITimeoutError struct {
	Registry  string
	RequestID string
	Reason    string
}

func (e OCITimeoutError) Error() string {
	baseMsg := fmt.Sprintf("timeout connecting to OCI registry %s", e.Registry)
	if e.Reason != "" {
		baseMsg += ": " + e.Reason
	}
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	return baseMsg
}

func (e OCITimeoutError) OCIError() string {
	return "timeout_error"
}

// OCIPermissionError represents permission/authorization errors with minimal context.
type OCIPermissionError struct {
	Registry  string
	RequestID string
	Reason    string
}

func (e OCIPermissionError) Error() string {
	baseMsg := fmt.Sprintf("permission denied for OCI registry %s", e.Registry)
	if e.Reason != "" {
		baseMsg += ": " + e.Reason
	}
	if e.RequestID != "" {
		baseMsg += fmt.Sprintf(" [request: %s]", e.RequestID)
	}
	return baseMsg
}

func (e OCIPermissionError) OCIError() string {
	return "permission_error"
}
