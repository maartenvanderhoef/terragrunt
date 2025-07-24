package config

import (
	"fmt"
	"sort"
	"time"

	"github.com/gruntwork-io/terragrunt/pkg/log"
)

// OCI configuration constants following terragrunt patterns
const (
	DefaultOCIDiscoverAmbientCredentials = true
	DefaultOCICacheCredentials          = true
	DefaultOCIRetryAttempts            = 3
    DefaultOCITimeout                  = "30s"
)

// OCIConfig represents the OCI configuration block in terragrunt.hcl
// This provides authentication and connection settings for OCI registries
// used when downloading modules from OCI distribution endpoints.
type OCIConfig struct {
	// DiscoverAmbientCredentials enables automatic discovery of credentials
	// from environment variables, Docker config files, and credential helpers.
	// Defaults to true for convenience.
	DiscoverAmbientCredentials *bool `hcl:"discover_ambient_credentials,attr" cty:"discover_ambient_credentials"`

	// DockerConfigFiles specifies explicit paths to Docker-style config files
	// to search for credentials. If nil, uses default discovery locations.
	// If empty slice, disables Docker config file discovery entirely.
	DockerConfigFiles []string `hcl:"docker_config_files,attr" cty:"docker_config_files"`

	// CredentialHelpers specifies which Docker credential helpers to try
	// in order of preference. Common values: "desktop", "osxkeychain", 
	// "wincred", "pass", "secretservice"
	CredentialHelpers []string `hcl:"credential_helpers,attr" cty:"credential_helpers"`

	// DefaultCredentialHelper specifies a default credential helper to use
	// for any registry that doesn't have specific credentials configured
	DefaultCredentialHelper *string `hcl:"default_credential_helper,attr" cty:"default_credential_helper"`

	// CacheCredentials enables caching of authentication tokens to avoid
	// repeated authentication requests during a single terragrunt run.
	// Defaults to true for performance.
	CacheCredentials *bool `hcl:"cache_credentials,attr" cty:"cache_credentials"`

	// Timeout specifies the maximum time to wait for registry operations.
	// Supports duration strings like "30s", "1m", "5m30s".
	Timeout *string `hcl:"timeout,attr" cty:"timeout"`

	// RetryAttempts specifies the number of retry attempts for failed
	// registry operations. Defaults to 3.
	RetryAttempts *int `hcl:"retry_attempts,attr" cty:"retry_attempts"`

	// Credentials contains registry-specific authentication configurations
	Credentials []OCICredentialsConfig `hcl:"credentials,block" cty:"credentials"`
}

// OCICredentialsConfig represents a credentials block for a specific registry or registry pattern.
// Multiple authentication methods can be specified and will be tried in priority order:
// 1. Username/Password (basic auth) - highest priority
// 2. Token (bearer token auth)
// 3. CredentialHelper (Docker credential helper)
// 4. TokenCommand (execute command for token)
// 5. DisableAuth (explicit opt-out) - lowest priority
type OCICredentialsConfig struct {
	// Registry is the registry hostname or pattern (e.g., "registry.io", "*.company.com")
	// This is the HCL attribute for the credentials block
	Registry string `hcl:"registry,attr" cty:"registry"`

	// Username for basic authentication (priority 1)
	Username *string `hcl:"username,optional" cty:"username"`

	// Password for basic authentication (must be paired with username)
	Password *string `hcl:"password,optional" cty:"password"`

	// Token for bearer token authentication (priority 2)
	Token *string `hcl:"token,optional" cty:"token"`

	// CredentialHelper specifies a Docker credential helper to use for this registry (priority 3)
	CredentialHelper *string `hcl:"credential_helper,optional" cty:"credential_helper"`

	// TokenCommand specifies a command to run to get an authentication token (priority 4)
	// The command output (stdout) will be used as the bearer token
	TokenCommand []string `hcl:"token_command,optional" cty:"token_command"`

	// DisableAuth explicitly disables authentication for this registry (priority 5)
	// Useful for public registries or to override global settings
	DisableAuth *bool `hcl:"disable_auth,optional" cty:"disable_auth"`
	
	// Timeout specifies the maximum time to wait for registry operations.
	// Supports duration strings like "30s", "1m", "5m30s".
	// Overrides the global timeout for this specific registry.
	Timeout *string `hcl:"timeout,optional" cty:"timeout"`
	
	// RetryAttempts specifies the number of retry attempts for failed
	// registry operations. Overrides the global retry attempts for this specific registry.
	RetryAttempts *int `hcl:"retry_attempts,optional" cty:"retry_attempts"`
	
	// CacheCredentials enables caching of authentication tokens to avoid
	// repeated authentication requests during a single terragrunt run.
	// Overrides the global cache credentials setting for this specific registry.
	CacheCredentials *bool `hcl:"cache_credentials,optional" cty:"cache_credentials"`
}

// String returns a string representation of the OCI config for debugging
func (cfg *OCIConfig) String() string {
	if cfg == nil {
		return "OCIConfig{<nil>}"
	}
	
	timeout := ""
	if cfg.Timeout != nil {
		timeout = *cfg.Timeout
	}
	
	retryAttempts := ""
	if cfg.RetryAttempts != nil {
		retryAttempts = fmt.Sprintf("%d", *cfg.RetryAttempts)
	}
	
	return fmt.Sprintf(
		"OCIConfig{DiscoverAmbientCredentials = %v, DockerConfigFiles = %v, CredentialHelpers = %v, Timeout = %s, RetryAttempts = %s, Credentials = %d}",
		cfg.DiscoverAmbientCredentials,
		cfg.DockerConfigFiles,
		cfg.CredentialHelpers,
		timeout,
		retryAttempts,
		len(cfg.Credentials),
	)
}

// String returns a string representation of the credentials config
func (cfg *OCICredentialsConfig) String() string {
	hasPassword := cfg.Password != nil && *cfg.Password != ""
	hasToken := cfg.Token != nil && *cfg.Token != ""
	username := ""
	if cfg.Username != nil {
		username = *cfg.Username
	}
	credHelper := ""
	if cfg.CredentialHelper != nil {
		credHelper = *cfg.CredentialHelper
	}
	
	timeout := ""
	if cfg.Timeout != nil {
		timeout = *cfg.Timeout
	}
	
	retryAttempts := ""
	if cfg.RetryAttempts != nil {
		retryAttempts = fmt.Sprintf("%d", *cfg.RetryAttempts)
	}
	
	cacheCredentials := ""
	if cfg.CacheCredentials != nil {
		cacheCredentials = fmt.Sprintf("%t", *cfg.CacheCredentials)
	}
	
	return fmt.Sprintf(
		"OCICredentialsConfig{Registry = %s, Username = %s, HasPassword = %t, HasToken = %t, CredentialHelper = %s, HasTokenCommand = %t, Timeout = %s, RetryAttempts = %s, CacheCredentials = %s}",
		cfg.Registry,
		username,
		hasPassword,
		hasToken,
		credHelper,
		len(cfg.TokenCommand) > 0,
		timeout,
		retryAttempts,
		cacheCredentials,
	)
}

// Validate validates the OCI configuration
func (cfg *OCIConfig) Validate() error {
	if cfg == nil {
		return nil
	}

	// Validate timeout format if specified
	if cfg.Timeout != nil && *cfg.Timeout != "" {
		if _, err := time.ParseDuration(*cfg.Timeout); err != nil {
			return fmt.Errorf("invalid timeout format %q: must be a valid duration (e.g., '30s', '1m', '5m30s')", *cfg.Timeout)
		}
	}

	// Validate retry attempts
	if cfg.RetryAttempts != nil && *cfg.RetryAttempts < 0 {
		return fmt.Errorf("retry_attempts must be non-negative, got %d", *cfg.RetryAttempts)
	}

	// Validate each credentials block
	for i, cred := range cfg.Credentials {
		if err := cred.Validate(); err != nil {
			return fmt.Errorf("credentials block %d (registry: %s): %w", i, cred.Registry, err)
		}
	}

	return nil
}

// Validate validates the credentials configuration.
// Following OpenTofu's approach, multiple authentication methods are allowed
// and will be tried in priority order at runtime.
func (cfg *OCICredentialsConfig) Validate() error {
    //fmt.Errorf("username %s password %s", cfg.Username, cfg.Password)
	if cfg.Registry == "" {
		return fmt.Errorf("registry hostname cannot be empty")
	}

	user := cfg.Username != nil && *cfg.Username != ""
	pass := cfg.Password != nil && *cfg.Password != ""

	if user != pass {
		return fmt.Errorf("username and password must be specified together")
	}

	// Validate timeout format if specified
	if cfg.Timeout != nil && *cfg.Timeout != "" {
		if _, err := time.ParseDuration(*cfg.Timeout); err != nil {
			return fmt.Errorf("invalid timeout format %q: must be a valid duration (e.g., '30s', '1m', '5m30s')", *cfg.Timeout)
		}
	}

	// Validate retry attempts
	if cfg.RetryAttempts != nil && *cfg.RetryAttempts < 0 {
		return fmt.Errorf("retry_attempts must be non-negative, got %d", *cfg.RetryAttempts)
	}

	// Note: CacheCredentials is a boolean, so no validation needed

	// Note: We intentionally do NOT validate that only one auth method is specified.
	// Following OpenTofu's pattern, multiple methods can be configured and will be
	// tried in priority order: username/password -> token -> credential_helper -> token_command -> disable_auth

	return nil
}

// GetDiscoverAmbientCredentials returns the configured value or default
func (cfg *OCIConfig) GetDiscoverAmbientCredentials() bool {
	if cfg == nil || cfg.DiscoverAmbientCredentials == nil {
		return DefaultOCIDiscoverAmbientCredentials
	}
	return *cfg.DiscoverAmbientCredentials
}

// GetCacheCredentials returns the configured value or default for a specific registry or globally
// If registry is empty, returns the global cache credentials setting
func (cfg *OCIConfig) GetCacheCredentials(registry ...string) bool {
	// If registry is provided, check for registry-specific cache credentials
	if len(registry) > 0 && registry[0] != "" {
		// Check if we have registry-specific credentials with cache credentials setting
		creds := cfg.FindCredentialsForRegistry(registry[0])
		if creds != nil && creds.CacheCredentials != nil {
			return *creds.CacheCredentials
		}
	}
	
	// Use global cache credentials
	if cfg == nil || cfg.CacheCredentials == nil {
		return DefaultOCICacheCredentials
	}
	return *cfg.CacheCredentials
}

// GetDockerConfigFiles returns the configured Docker config file paths or default paths.
// If DockerConfigFiles is nil, returns the default paths.
// If DockerConfigFiles is an empty slice, returns an empty slice (disables Docker config file discovery).
// All paths are expanded to handle ~ and environment variables.
func (cfg *OCIConfig) GetDockerConfigFiles() []string {
	if cfg == nil {
		return DefaultDockerConfigFiles()
	}
	
	if cfg.DockerConfigFiles == nil {
		return DefaultDockerConfigFiles()
	}
	
	// Empty slice means explicitly disable Docker config file discovery
	if len(cfg.DockerConfigFiles) == 0 {
		return []string{}
	}
	
	// Expand paths with ~ and environment variables
	return ExpandPaths(cfg.DockerConfigFiles)
}

// GetRetryAttempts returns the configured value or default for a specific registry or globally
// If registry is empty, returns the global retry attempts
func (cfg *OCIConfig) GetRetryAttempts(registry ...string) int {
	// If registry is provided, check for registry-specific retry attempts
	if len(registry) > 0 && registry[0] != "" {
		// Check if we have registry-specific credentials with retry attempts
		creds := cfg.FindCredentialsForRegistry(registry[0])
		if creds != nil && creds.RetryAttempts != nil {
			return *creds.RetryAttempts
		}
	}
	
	// Use global retry attempts
	if cfg == nil || cfg.RetryAttempts == nil {
		return DefaultOCIRetryAttempts
	}
	return *cfg.RetryAttempts
}

// GetRetryAttemptsForRegistry returns the retry attempts for a specific registry or the global default
// This is a convenience wrapper around GetRetryAttempts for backward compatibility
func (cfg *OCIConfig) GetRetryAttemptsForRegistry(registry string) int {
	return cfg.GetRetryAttempts(registry)
}

// GetCacheCredentialsForRegistry returns the cache credentials setting for a specific registry or the global default
// This is a convenience wrapper around GetCacheCredentials for backward compatibility
func (cfg *OCIConfig) GetCacheCredentialsForRegistry(registry string) bool {
	return cfg.GetCacheCredentials(registry)
}

// GetTimeoutDuration returns the parsed timeout duration for a specific registry or the global default
// If registry is empty, returns the global timeout
func (cfg *OCIConfig) GetTimeoutDuration(registry ...string) time.Duration {
	// If registry is provided, check for registry-specific timeout
	if len(registry) > 0 && registry[0] != "" {
		// Check if we have registry-specific credentials with a timeout
		creds := cfg.FindCredentialsForRegistry(registry[0])
		if creds != nil && creds.Timeout != nil && *creds.Timeout != "" {
			duration, err := time.ParseDuration(*creds.Timeout)
			if err != nil {
				// This should have been caught by Validate(), but provide a fallback
				log.Printf("[WARN] Invalid OCI timeout format %q for registry %s, using global timeout. This should have been caught by validation.", 
					*creds.Timeout, registry[0])
			} else {
				return duration
			}
		}
	}
	
	// Use global timeout
	if cfg == nil || cfg.Timeout == nil || *cfg.Timeout == "" {
		duration, _ := time.ParseDuration(DefaultOCITimeout)
		return duration
	}
	
	duration, err := time.ParseDuration(*cfg.Timeout)
	if err != nil {
		// This should have been caught by Validate(), but provide a fallback
		log.Printf("[WARN] Invalid OCI timeout format %q, using default %s. This should have been caught by validation.", *cfg.Timeout, DefaultOCITimeout)

		fallback, _ := time.ParseDuration(DefaultOCITimeout)
		return fallback
	}
	
	return duration
}

// GetTimeoutDurationForRegistry returns the parsed timeout duration for a specific registry or the global default
// This is a convenience wrapper around GetTimeoutDuration for backward compatibility
func (cfg *OCIConfig) GetTimeoutDurationForRegistry(registry string) time.Duration {
	return cfg.GetTimeoutDuration(registry)
}

// FindCredentialsForRegistry finds the most specific credentials configuration
// for the given registry hostname. Supports wildcard patterns.
// Returns the most specific match following OpenTofu's precedence rules:
// 1. Exact matches take precedence over wildcard matches
// 2. Among wildcards, more specific patterns take precedence
func (cfg *OCIConfig) FindCredentialsForRegistry(registry string) *OCICredentialsConfig {
	if cfg == nil {
		return nil
	}

	var exactMatch *OCICredentialsConfig
	var wildcardMatch *OCICredentialsConfig

	for i := range cfg.Credentials {
		cred := &cfg.Credentials[i]
		
		// Exact match takes highest priority
		if cred.Registry == registry {
			exactMatch = cred
			break
		}
		
		// Wildcard match (e.g., "*.company.com" matches "registry.company.com")
		if wildcardMatch == nil && matchesWildcard(cred.Registry, registry) {
			wildcardMatch = cred
		}
	}

	// Return exact match if found, otherwise wildcard match
	if exactMatch != nil {
		return exactMatch
	}
	return wildcardMatch
}

// GetPrimaryAuthMethod returns the highest priority authentication method configured
// for this credentials block, following OpenTofu's priority order.
func (cfg *OCICredentialsConfig) GetPrimaryAuthMethod() string {
	if cfg.Username != nil && *cfg.Username != "" && cfg.Password != nil && *cfg.Password != "" {
		return "basic"
	}
	if cfg.Token != nil && *cfg.Token != "" {
		return "token"
	}
	if cfg.CredentialHelper != nil && *cfg.CredentialHelper != "" {
		return "credential_helper"
	}
	if len(cfg.TokenCommand) > 0 {
		return "token_command"
	}
	if cfg.DisableAuth != nil && *cfg.DisableAuth {
		return "disabled"
	}
	return "none"
}

// HasAnyAuthMethod returns true if any authentication method is configured
func (cfg *OCICredentialsConfig) HasAnyAuthMethod() bool {
	return cfg.GetPrimaryAuthMethod() != "none"
}

// IsAuthDisabled returns true if authentication is explicitly disabled
func (cfg *OCICredentialsConfig) IsAuthDisabled() bool {
	return cfg.DisableAuth != nil && *cfg.DisableAuth
}

// matchesWildcard checks if a registry pattern matches a hostname.
// Supports simple wildcard patterns like "*.company.com"
func matchesWildcard(pattern, hostname string) bool {
	// Simple wildcard matching for patterns like "*.company.com"
	if len(pattern) == 0 {
		return false
	}
	
	// If pattern doesn't contain wildcards, it must be an exact match
	if pattern[0] != '*' {
		return pattern == hostname
	}
	
	// Handle patterns like "*.company.com"
	if len(pattern) < 2 || pattern[1] != '.' {
		return false
	}
	
	suffix := pattern[2:] // Remove "*."
	return len(hostname) > len(suffix) && hostname[len(hostname)-len(suffix):] == suffix
}

// MergeOciConfig merges two OCI configurations, with child values taking precedence over parent values.
func MergeOciConfig(parent, child *OCIConfig) *OCIConfig {
	if parent == nil {
		return child
	}
	if child == nil {
		return parent
	}

	merged := &OCIConfig{}

	// For pointer types, the child's value is used if it's not nil.
	if child.DiscoverAmbientCredentials != nil {
		merged.DiscoverAmbientCredentials = child.DiscoverAmbientCredentials
	} else {
		merged.DiscoverAmbientCredentials = parent.DiscoverAmbientCredentials
	}

	if child.CacheCredentials != nil {
		merged.CacheCredentials = child.CacheCredentials
	} else {
		merged.CacheCredentials = parent.CacheCredentials
	}
    
	if child.Timeout != nil {
		merged.Timeout = child.Timeout
	} else {
		merged.Timeout = parent.Timeout
	}
    
	if child.RetryAttempts != nil {
		merged.RetryAttempts = child.RetryAttempts
	} else {
		merged.RetryAttempts = parent.RetryAttempts
	}
    
	if child.DefaultCredentialHelper != nil {
		merged.DefaultCredentialHelper = child.DefaultCredentialHelper
	} else {
		merged.DefaultCredentialHelper = parent.DefaultCredentialHelper
	}

	// For slice properties, the child's slice completely replaces the parent's if it's set.
	if child.DockerConfigFiles != nil {
		merged.DockerConfigFiles = child.DockerConfigFiles
	} else {
		merged.DockerConfigFiles = parent.DockerConfigFiles
	}

	if child.CredentialHelpers != nil {
		merged.CredentialHelpers = child.CredentialHelpers
	} else {
		merged.CredentialHelpers = parent.CredentialHelpers
	}

	// For credentials blocks, merge them by registry name. The child's block for a given
	// registry name completely overrides the parent's.
	credMap := make(map[string]OCICredentialsConfig)
	for _, cred := range parent.Credentials {
		credMap[cred.Registry] = cred
	}
	for _, cred := range child.Credentials {
		credMap[cred.Registry] = cred
	}

	// Convert the map back to a slice for the final config.
	for _, cred := range credMap {
		merged.Credentials = append(merged.Credentials, cred)
	}

	// Sort for a deterministic order.
	sort.Slice(merged.Credentials, func(i, j int) bool {
		return merged.Credentials[i].Registry < merged.Credentials[j].Registry
	})

	return merged
}