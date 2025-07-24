// Portions derived from OpenTofu's OCI distribution implementation
// Copyright (c) The OpenTofu Authors  
// SPDX-License-Identifier: MPL-2.0

package oci

import (
	"context"
	"fmt"
	"time"
	orasRemote "oras.land/oras-go/v2/registry/remote"

	"github.com/gruntwork-io/terragrunt/internal/cache"
	ociconfig "github.com/gruntwork-io/terragrunt/internal/oci/config"
	"github.com/gruntwork-io/terragrunt/pkg/log"
	"github.com/gruntwork-io/terragrunt/telemetry"
)

const ociRepositoryCacheName = "oci_repository_store"

// Context keys for OCI operations
const (
	OCIRequestIDContextKey ctxKey = iota
	OCIRegistryDomainContextKey
	OCIRetryAttemptsContextKey
)

type ctxKey byte

// Global cache instance - shared across all factories for better performance
var globalRepositoryCache = cache.NewCache[RepositoryStore](ociRepositoryCacheName)



// ContextWithOCIRequestID adds a request ID to the context for tracing
func ContextWithOCIRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, OCIRequestIDContextKey, requestID)
}

// OCIRequestIDFromContext retrieves the request ID from the context
func OCIRequestIDFromContext(ctx context.Context) string {
	if val := ctx.Value(OCIRequestIDContextKey); val != nil {
		if requestID, ok := val.(string); ok {
			return requestID
		}
	}
	return ""
}

// ContextWithOCIRetryAttempts adds retry attempts to the context
func ContextWithOCIRetryAttempts(ctx context.Context, retryAttempts int) context.Context {
	return context.WithValue(ctx, OCIRetryAttemptsContextKey, retryAttempts)
}

// OCIRetryAttemptsFromContext retrieves retry attempts from the context
func OCIRetryAttemptsFromContext(ctx context.Context) int {
	if val := ctx.Value(OCIRetryAttemptsContextKey); val != nil {
		if retryAttempts, ok := val.(int); ok {
			return retryAttempts
		}
	}
	return ociconfig.DefaultOCIRetryAttempts
}

// RepositoryStoreFactory creates repository stores for specific registries and repositories.
// It is initialized once with configuration and then lazily creates connections as needed.
type RepositoryStoreFactory interface {
	// CreateRepositoryStore creates or retrieves a cached repository store for the specified registry and repository.
	// Connections are only established when operations are performed on the returned store.
	CreateRepositoryStore(ctx context.Context, registryDomain, repositoryName string) (RepositoryStore, error)
}

// DefaultRepositoryStoreFactory is the default implementation of RepositoryStoreFactory.
// It creates repository stores based on the provided OCI configuration and caches them
// for efficient reuse across multiple operations using the global cache.
type DefaultRepositoryStoreFactory struct {
	// OCIConfig contains the OCI configuration from terragrunt.hcl
	OCIConfig *ociconfig.OCIConfig
	
	// AuthFactory is used to create authenticated clients for registry access
	AuthFactory AuthClientFactory
	
	// Logger is used for debug output
	Logger log.Logger
	
	// Telemeter provides telemetry collection for operations
	Telemeter *telemetry.Telemeter
	
	// HealthChecker provides registry health checking capabilities
	HealthChecker *RegistryHealthChecker
}

// CreateRepositoryStore creates and caches ORAS-Go repository connections with
// enhanced context support for timeouts, cancellation, and tracing.
//
// Context enhancements:
//   - Respects timeout configuration from OCI config
//   - Supports cancellation during long operations
//   - Adds request ID for tracing and debugging
//   - Provides telemetry through cache operations
//
// Connection setup process:
//   1. Set up timeout context from OCI configuration
//   2. Add request ID for tracing
//   3. Check global cache for existing connection
//   4. Create new ORAS registry instance with timeout context
//   5. Configure authentication using AuthClientFactory
//   6. Validate connectivity with registry.Ping() (respects cancellation)
//   7. Create repository instance
//   8. Store in global cache for future use
//
// Parameters:
//   - ctx: Context for cancellation, timeout, and request scoping
//   - registryDomain: Registry hostname (e.g., registry.example.com)
//   - repositoryName: Repository path (e.g., namespace/module-name)
//
// Returns a configured RepositoryStore or an error if connection setup fails.
// Operations respect context cancellation and configured timeouts.
func (f *DefaultRepositoryStoreFactory) CreateRepositoryStore(ctx context.Context, registryDomain, repositoryName string) (RepositoryStore, error) {
	// Create request ID for tracing
	requestID := fmt.Sprintf("oci-repo-%s-%s-%d", registryDomain, repositoryName, time.Now().UnixNano())
	ctx = ContextWithOCIRequestID(ctx, requestID)
	
	// Apply timeout from OCI configuration if specified
	if f.OCIConfig != nil {
		if timeoutDuration := f.OCIConfig.GetTimeoutDurationForRegistry(registryDomain); timeoutDuration > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeoutDuration)
			defer cancel()
			f.Logger.Debugf("[%s] Applied timeout for registry %s: %v", requestID, registryDomain, timeoutDuration)
		}
		
		// Add registry-specific retry attempts to context
		retryAttempts := f.OCIConfig.GetRetryAttemptsForRegistry(registryDomain)
		ctx = ContextWithOCIRetryAttempts(ctx, retryAttempts)
		f.Logger.Tracef("[%s] Using retry attempts for registry %s: %d", requestID, registryDomain, retryAttempts)
	}
	
	// Create composite cache key
	key := fmt.Sprintf("%s/%s", registryDomain, repositoryName)
	
	// Check for cancellation before cache operation
	select {
	case <-ctx.Done():
		return nil, NewOCITimeoutErrorFromContext(registryDomain, "cache_lookup", "context cancelled", requestID)
	default:
	}
	
	// Try to get from global cache first - this provides automatic telemetry
	if store, found := globalRepositoryCache.Get(ctx, key); found {
		f.Logger.Debugf("[%s] Found OCI repository store in global cache for %s", requestID, key)
		return store, nil
	}
	
	f.Logger.Debugf("[%s] Creating new OCI repository store for %s/%s", requestID, registryDomain, repositoryName)
	
	// Check for cancellation before expensive registry operations
	select {
	case <-ctx.Done():
		return nil, NewOCITimeoutErrorFromContext(registryDomain, "registry_creation", "context cancelled", requestID)
	default:
	}
	
	// Create ORAS registry with context support
	registry, err := orasRemote.NewRegistry(registryDomain)
	if err != nil {
		return nil, OCIRegistryConnectionError{
			registry: registryDomain,
			details:  fmt.Sprintf("[%s] failed to create registry: %v", requestID, err),
		}
	}
	
	// Set up authentication with context
	authClient, err := f.AuthFactory.CreateAuthClient(ctx, registryDomain)
	if err != nil {
		return nil, fmt.Errorf("[%s] authentication failed: %w", requestID, err)
	}
	registry.Client = authClient
	
	// Check for cancellation before ping (network operation)
	select {
	case <-ctx.Done():
		return nil, NewOCITimeoutErrorFromContext(registryDomain, "registry_ping", "context cancelled", requestID)
	default:
	}
	
	// Perform comprehensive health check before ping
	if f.HealthChecker != nil {
		f.Logger.Debugf("[%s] Performing health check for %s", requestID, registryDomain)
		healthStatus := f.HealthChecker.CheckRegistryHealth(ctx, registryDomain)
		
		if !healthStatus.Available {
			suggestions := GetHealthCheckSuggestions(healthStatus)
			details := fmt.Sprintf("[%s] health check failed: %s. Suggestions: %v", 
				requestID, healthStatus.Details, suggestions)
			
			return nil, OCIRegistryConnectionError{
				registry: registryDomain,
				details:  details,
			}
		}
		
		f.Logger.Debugf("[%s] Health check passed for %s (response time: %v)", 
			requestID, registryDomain, healthStatus.ResponseTime)
	}
	
	// Test connection with ping - this respects context cancellation
	f.Logger.Debugf("[%s] Testing connectivity to %s", requestID, registryDomain)
	
	err = WithOCITelemetry(ctx, f.Telemeter, "registry_ping", registryDomain, "", func(ctx context.Context) error {
		return registry.Ping(ctx)
	})
	
	if err != nil {
		return nil, OCIRegistryConnectionError{
			registry: registryDomain,
			details:  fmt.Sprintf("[%s] ping failed: %v", requestID, err),
		}
	}
	
	// Create repository with context support
	repo, err := registry.Repository(ctx, repositoryName)
	if err != nil {
		return nil, OCIRegistryConnectionError{
			registry:   registryDomain,
			repository: repositoryName,
			details:    fmt.Sprintf("[%s] repository creation failed: %v", requestID, err),
		}
	}
	
	// Create the store wrapper
	store := &orasRepositoryStore{
		repository:     repo,
		registry:       registryDomain,
		repositoryName: repositoryName,
		logger:         f.Logger,
		telemeter:      f.Telemeter,
	}
	
	// Final cancellation check before caching
	select {
	case <-ctx.Done():
		// Don't cache if operation was cancelled
		f.Logger.Debugf("[%s] Operation cancelled, not caching store", requestID)
		return store, nil
	default:
	}
	
	// Cache globally using the generic cache - this provides automatic telemetry
	globalRepositoryCache.Put(ctx, key, store)
	f.Logger.Debugf("[%s] Successfully created and cached OCI repository store globally for %s", requestID, key)
	
	return store, nil
}

// NewRepositoryStoreFactory creates a new DefaultRepositoryStoreFactory with the provided configuration.
// This is the recommended way to create a repository store factory.
func NewRepositoryStoreFactory(ociConfig *ociconfig.OCIConfig, logger log.Logger) RepositoryStoreFactory {
	return NewRepositoryStoreFactoryWithTelemetry(ociConfig, logger, nil)
}

// NewRepositoryStoreFactoryWithTelemetry creates a new DefaultRepositoryStoreFactory with telemetry support.
// This enables enhanced observability and debugging capabilities.
func NewRepositoryStoreFactoryWithTelemetry(ociConfig *ociconfig.OCIConfig, logger log.Logger, telemeter *telemetry.Telemeter) RepositoryStoreFactory {
	authFactory := &DefaultAuthClientFactory{
		OCIConfig: ociConfig,
		Logger:    logger,
	}
	
	healthChecker := NewRegistryHealthChecker(logger, telemeter)
	
	return &DefaultRepositoryStoreFactory{
		OCIConfig:     ociConfig,
		AuthFactory:   authFactory,
		Logger:        logger,
		Telemeter:     telemeter,
		HealthChecker: healthChecker,
	}
}