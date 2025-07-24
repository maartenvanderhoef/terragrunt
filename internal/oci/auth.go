// Portions derived from OpenTofu's OCI distribution implementation
// Copyright (c) The OpenTofu Authors  
// SPDX-License-Identifier: MPL-2.0

package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	orasAuth "oras.land/oras-go/v2/registry/remote/auth"
	svchost "github.com/hashicorp/terraform-svchost"
	orasCreds "oras.land/oras-go/v2/registry/remote/credentials"

	ociconfig "github.com/gruntwork-io/terragrunt/internal/oci/config"
	"github.com/gruntwork-io/terragrunt/pkg/log"
	"github.com/gruntwork-io/terragrunt/tf/cliconfig"
)

// Environment variable name for OCI registry token
const ociAuthTokenEnvName = "TG_OCI_REGISTRY_TOKEN"

// AuthClientFactory is an interface for creating authenticated ORAS clients
// for accessing OCI registries. It provides a way to create clients with
// appropriate authentication for different registries.
type AuthClientFactory interface {
	// CreateAuthClient creates an authenticated ORAS client for the specified registry.
	// The client is configured with appropriate credentials for the registry.
	CreateAuthClient(ctx context.Context, registryDomain string) (*orasAuth.Client, error)
}

// DefaultAuthClientFactory is the default implementation of AuthClientFactory.
// It creates authenticated ORAS clients based on the provided OCI configuration.
type DefaultAuthClientFactory struct {
	// OCIConfig contains the OCI configuration from terragrunt.hcl
	OCIConfig *ociconfig.OCIConfig
	
	// Logger is used for debug output
	Logger log.Logger
	
	// cache stores auth clients by registry domain
	cache     map[string]*orasAuth.Client
	cacheLock sync.RWMutex
}

// CreateAuthClient creates an authenticated ORAS client for the specified registry.
// It implements the AuthClientFactory interface.
func (f *DefaultAuthClientFactory) CreateAuthClient(ctx context.Context, registryDomain string) (*orasAuth.Client, error) {
	// Check cache first with read lock
	f.cacheLock.RLock()
	if client, exists := f.cache[registryDomain]; exists {
		f.cacheLock.RUnlock()
		f.Logger.Debugf("Reusing cached OCI auth client for %s", registryDomain)
		return client, nil
	}
	f.cacheLock.RUnlock()
	
	// Create new client with write lock
	f.cacheLock.Lock()
	defer f.cacheLock.Unlock()
	
	// Double-check after acquiring write lock
	if client, exists := f.cache[registryDomain]; exists {
		f.Logger.Debugf("Reusing cached OCI auth client for %s (double-check)", registryDomain)
		return client, nil
	}
	
	f.Logger.Debugf("Creating new OCI auth client for %s", registryDomain)
	
	client, err := createOCIAuthClient(ctx, registryDomain, f.OCIConfig, f.Logger)
	if err != nil {
		requestID := OCIRequestIDFromContext(ctx)
		return nil, OCIAuthenticationError{
			registry:  registryDomain,
			reason:    err.Error(),
			requestID: requestID,
		}
	}
	
	// Initialize cache if needed
	if f.cache == nil {
		f.cache = make(map[string]*orasAuth.Client)
	}
	
	// Cache the client
	f.cache[registryDomain] = client
	
	return client, nil
}

// createOCIAuthClient creates an authenticated ORAS client for accessing the specified
// OCI registry. This function follows the same authentication patterns as Terragrunt's
// Terraform Registry (TFR) getter to provide consistent credential handling.
//
// The client is configured with credential caching to avoid repeated authentication
// requests and uses a callback-based approach to lookup credentials on demand.
//
// Authentication sources (in priority order):
//   1. Terraform CLI configuration files (~/.terraformrc, etc.)
//   2. TG_OCI_REGISTRY_TOKEN environment variable
//   3. No authentication (for public registries)
//
// Parameters:
//   - ctx: Context for the authentication setup
//   - registryDomain: The registry hostname (e.g., registry.example.com)
//   - ociConfig: OCI configuration from terragrunt.hcl
//   - logger: Logger for debug output
//
// Returns a configured ORAS auth client or an error if setup fails.
func createOCIAuthClient(ctx context.Context, registryDomain string, ociConfig *ociconfig.OCIConfig, logger log.Logger) (*orasAuth.Client, error) {
    logger.Debugf("Setting up OCI authentication for registry: %s", registryDomain)
    
    // Create base HTTP client (reuse the same one as TFR)
    httpClient := &http.Client{
        Transport: http.DefaultTransport,
    }
    
    // Determine if we should use credential caching based on config
    var cache orasAuth.Cache
    if ociConfig != nil && !ociConfig.GetCacheCredentialsForRegistry(registryDomain) {
        logger.Debugf("OCI credential caching disabled for registry %s", registryDomain)
        cache = nil
    } else {
        cache = orasAuth.NewCache() // Default to caching credentials
    }
    
    // Create ORAS auth client with credential callback
    authClient := &orasAuth.Client{
        Client: httpClient,
        Credential: func(ctx context.Context, hostport string) (orasAuth.Credential, error) {
            return getOCICredentials(ctx, hostport, ociConfig, logger)
        },
        Cache: cache,
    }
    
    logger.Debugf("Created OCI auth client for registry: %s", registryDomain)
    return authClient, nil
}

// CredentialMethod represents the different authentication methods available
type CredentialMethod string

const (
    CredentialMethodOCIConfig      CredentialMethod = "oci_config"
    CredentialMethodTerraformCLI   CredentialMethod = "terraform_cli"
    CredentialMethodEnvironment    CredentialMethod = "environment"
    CredentialMethodDockerConfig   CredentialMethod = "docker_config"
    CredentialMethodDockerHelper   CredentialMethod = "docker_helper"
    CredentialMethodNone           CredentialMethod = "none"
)

// CredentialLookupResult contains detailed information about credential discovery
type CredentialLookupResult struct {
    Method      CredentialMethod
    Found       bool
    Error       error
    Details     string
    Credential  orasAuth.Credential
}

// getOCICredentials retrieves authentication credentials for the specified registry host.
// This function implements the same credential lookup strategy as Terragrunt's TFR getter
// to ensure consistent authentication behavior across different registry types.
//
// The credential lookup follows a specific priority order:
//   1. Terragrunt OCI configuration (highest priority)
//   2. Terraform CLI configuration (most secure, follows terraform login patterns)
//   3. Environment variables (TG_OCI_REGISTRY_TOKEN)
//   4. Docker credential helpers
//   5. No credentials (allows access to public registries)
//
// Parameters:
//   - ctx: Context for the credential lookup
//   - hostport: Registry hostname, optionally with port (e.g., registry.io:443)
//   - ociConfig: OCI configuration from terragrunt.hcl
//   - logger: Logger for debug output
//
// Returns ORAS credentials or orasAuth.EmptyCredential for unauthenticated access.
// Errors during credential lookup are logged but don't prevent operation
func getOCICredentials(ctx context.Context, hostport string, ociConfig *ociconfig.OCIConfig, logger log.Logger) (orasAuth.Credential, error) {
    requestID := OCIRequestIDFromContext(ctx)
    logger.Debugf("[%s] Starting credential discovery for host: %s", requestID, hostport)
    
    // Track all credential lookup attempts for detailed logging
    var attempts []CredentialLookupResult
    
    // Method 0: Check Terragrunt OCI configuration first (highest priority)
    if ociConfig != nil {
        logger.Debugf("[%s] Attempting credential method: %s", requestID, CredentialMethodOCIConfig)
        cred, found := getCredentialsFromOCIConfig(ctx, hostport, ociConfig, logger)
        
        result := CredentialLookupResult{
            Method:     CredentialMethodOCIConfig,
            Found:      found,
            Credential: cred,
        }
        
        if found {
            result.Details = "Found credentials in Terragrunt OCI configuration"
            attempts = append(attempts, result)
            logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
            return cred, nil
        } else {
            result.Details = "No credentials found in Terragrunt OCI configuration"
        }
        attempts = append(attempts, result)
        
        // If ambient credential discovery is disabled, don't try the other methods
        if !ociConfig.GetDiscoverAmbientCredentials() {
            logger.Tracef("[%s] Ambient credential discovery disabled for %s, skipping ambient credential sources", requestID, hostport)
            result := CredentialLookupResult{
                Method:     CredentialMethodNone,
                Found:      true,
                Details:    "Ambient credential discovery disabled",
                Credential: orasAuth.EmptyCredential,
            }
            attempts = append(attempts, result)
            logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
            return orasAuth.EmptyCredential, nil
        }
    }
    
    // Method 1: Try Terraform CLI configuration first (same as TFR)
    logger.Tracef("[%s] Attempting credential method: %s", requestID, CredentialMethodTerraformCLI)
    cred, err := getCredentialsFromTerraformCLI(hostport, logger)
    
    result := CredentialLookupResult{
        Method: CredentialMethodTerraformCLI,
        Error:  err,
    }
    
    if err != nil {
        result.Details = fmt.Sprintf("Error loading Terraform CLI config: %v", err)
        logger.Tracef("[%s] %s", requestID, result.Details)
    } else if cred != (orasAuth.Credential{}) {
        result.Found = true
        result.Credential = cred
        result.Details = "Found credentials in Terraform CLI configuration"
        attempts = append(attempts, result)
        logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
        return cred, nil
    } else {
        result.Details = "No credentials found in Terraform CLI configuration"
    }
    attempts = append(attempts, result)
    
    // Method 2: Fall back to TG_OCI_REGISTRY_TOKEN environment variable
    logger.Tracef("[%s] Attempting credential method: %s", requestID, CredentialMethodEnvironment)
    cred, found := getCredentialsFromEnvironment(hostport, logger)
    
    result = CredentialLookupResult{
        Method: CredentialMethodEnvironment,
        Found:  found,
    }
    
    if found {
        result.Credential = cred
        result.Details = "Found credentials in environment variables"
        attempts = append(attempts, result)
        logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
        return cred, nil
    } else {
        result.Details = "No credentials found in environment variables"
    }
    attempts = append(attempts, result)

    // Method 3: Try Docker config files
    dockerConfigFiles := []string{}
    if ociConfig != nil {
        dockerConfigFiles = ociConfig.GetDockerConfigFiles()
    } else {
        // If no config provided, use defaults
        dockerConfigFiles = ociconfig.DefaultDockerConfigFiles()
    }
    
    if len(dockerConfigFiles) > 0 {
        logger.Tracef("[%s] Attempting credential method: %s (files: %v)", requestID, CredentialMethodDockerConfig, dockerConfigFiles)
        cred, err := getCredentialsFromDockerConfigFiles(ctx, hostport, dockerConfigFiles, logger)
        
        result := CredentialLookupResult{
            Method: CredentialMethodDockerConfig,
            Error:  err,
        }
        
        if err != nil {
            result.Details = fmt.Sprintf("Error reading Docker config files: %v", err)
            logger.Tracef("[%s] %s", requestID, result.Details)
        } else if cred != (orasAuth.Credential{}) {
            result.Found = true
            result.Credential = cred
            result.Details = "Found credentials in Docker config files"
            attempts = append(attempts, result)
            logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
            return cred, nil
        } else {
            result.Details = "No credentials found in Docker config files"
        }
        attempts = append(attempts, result)
    }
    
    // Method 4: Try Docker credential helpers
    logger.Tracef("[%s] Attempting credential method: %s", requestID, CredentialMethodDockerHelper)
    cred, err = getCredentialsFromDockerHelper(ctx, hostport, ociConfig, logger)
    
    result = CredentialLookupResult{
        Method: CredentialMethodDockerHelper,
        Error:  err,
    }
    
    if err != nil {
        result.Details = fmt.Sprintf("Error querying Docker credential helpers: %v", err)
        logger.Tracef("[%s] %s", requestID, result.Details)
    } else if cred != (orasAuth.Credential{}) {
        result.Found = true
        result.Credential = cred
        result.Details = "Found credentials from Docker credential helper"
        attempts = append(attempts, result)
        logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
        return cred, nil
    } else {
        result.Details = "No credentials found from Docker credential helpers"
    }
    attempts = append(attempts, result)
    
    // Method 5: Return empty credentials (no authentication)
    result = CredentialLookupResult{
        Method:     CredentialMethodNone,
        Found:      true,
        Details:    "No credentials found, proceeding without authentication",
        Credential: orasAuth.EmptyCredential,
    }
    attempts = append(attempts, result)
    logCredentialDiscoveryResult(logger, requestID, hostport, attempts, result)
    
    return orasAuth.EmptyCredential, nil
}

// logCredentialDiscoveryResult logs detailed information about the credential discovery process
func logCredentialDiscoveryResult(logger log.Logger, requestID, hostport string, attempts []CredentialLookupResult, finalResult CredentialLookupResult) {
    logger.Debugf("[%s] Credential discovery completed for %s using method: %s", requestID, hostport, finalResult.Method)
    
    // Log detailed summary of all attempts for troubleshooting (trace level for verbosity)
    logger.Tracef("[%s] Credential discovery summary for %s:", requestID, hostport)
    for i, attempt := range attempts {
        status := "FAILED"
        if attempt.Found {
            status = "SUCCESS"
        } else if attempt.Error != nil {
            status = "ERROR"
        }
        logger.Tracef("[%s]   %d. %s: %s - %s", requestID, i+1, attempt.Method, status, attempt.Details)
    }
}

// getCredentialsFromDockerHelper attempts to retrieve credentials using Docker credential helpers.
// This method tries credential helpers in order of preference, providing compatibility
// with existing Docker registry authentication setups.
//
// The function tries helpers in the following order:
//   1. Helpers specified in the OCI configuration
//   2. Default credential helper from OCI configuration
//   3. Common credential helpers (desktop, osxkeychain, wincred, pass, secretservice)
//
// Parameters:
//   - ctx: Context for the credential lookup operation
//   - hostport: Registry hostname to look up credentials for
//   - ociConfig: OCI configuration from terragrunt.hcl
//   - logger: Logger for debug output
//
// Returns ORAS credentials if found via any helper, or empty credentials if none work.
// Errors from individual helpers are logged but don't prevent trying other helpers.
func getCredentialsFromDockerHelper(ctx context.Context, hostport string, ociConfig *ociconfig.OCIConfig, logger log.Logger) (orasAuth.Credential, error) {
    var helpers []string
    
    // Use configured helpers if available
    if ociConfig != nil {
        // Check for registry-specific credential helper
        if creds := ociConfig.FindCredentialsForRegistry(hostport); creds != nil && creds.CredentialHelper != nil {
            helpers = []string{*creds.CredentialHelper}
        } else if ociConfig.DefaultCredentialHelper != nil {
            // Fall back to default credential helper
            helpers = []string{*ociConfig.DefaultCredentialHelper}
        } else if len(ociConfig.CredentialHelpers) > 0 {
            // Use configured credential helpers
            helpers = ociConfig.CredentialHelpers
        }
    }
    
    // Fall back to default helpers if none configured
    if len(helpers) == 0 {
        helpers = []string{
            "desktop",        // Docker Desktop (docker-credential-desktop)
            "osxkeychain",    // macOS keychain (docker-credential-osxkeychain)
            "wincred",        // Windows credential manager (docker-credential-wincred)
            "pass",           // Linux pass (docker-credential-pass)
            "secretservice",  // Linux secret service (docker-credential-secretservice)
        }
    }
    
    for _, helper := range helpers {
        logger.Tracef("Trying Docker credential helper: %s for %s", helper, hostport)
        
        // Use ORAS-Go's native store implementation (same as OpenTofu)
        store := orasCreds.NewNativeStore(helper)
        creds, err := store.Get(ctx, "https://"+hostport)
        
        if err != nil {
            logger.Tracef("Docker credential helper %s failed for %s: %v", helper, hostport, err)
            continue // Try next helper
        }
        
        // Check if we got valid credentials
        if creds.Username != "" && creds.Password != "" {
            logger.Debugf("Successfully got credentials from Docker credential helper %s for %s", helper, hostport)
            return orasAuth.Credential{
                Username: creds.Username,
                Password: creds.Password,
            }, nil
        }
        
        // Check for access token (for token-based auth like GitHub)
        if creds.AccessToken != "" {
            logger.Debugf("Successfully got access token from Docker credential helper %s for %s", helper, hostport)
            return orasAuth.Credential{
                AccessToken: creds.AccessToken,
            }, nil
        }
        
        logger.Tracef("Docker credential helper %s returned empty credentials for %s", helper, hostport)
    }

    return orasAuth.Credential{}, nil
}

// getCredentialsFromTerraformCLI loads credentials from Terraform CLI configuration files.
// This method reuses Terragrunt's existing CLI configuration parsing to maintain
// consistency with how Terraform Registry authentication works.
//
// The function looks for credentials in standard Terraform configuration locations:
//   - ~/.terraformrc (Unix/Linux)
//   - %APPDATA%\terraform.rc (Windows)
//   - Custom paths specified by TF_CLI_CONFIG_FILE
//
// Credentials are converted from Terraform's format to ORAS format by extracting
// the Authorization header that would be used for HTTP requests.
//
// Parameters:
//   - hostport: Registry hostname to look up credentials for
//   - logger: Logger for debug output
//
// Returns ORAS credentials if found, or empty credentials if none exist.
// Errors are returned only for configuration parsing failures.
func getCredentialsFromTerraformCLI(hostport string, logger log.Logger) (orasAuth.Credential, error) {
	// Load user config exactly like TFR does
	cliCfg, err := cliconfig.LoadUserConfig()
	if err != nil {
		return orasAuth.Credential{}, err
	}
	
	// Look up credentials for this host exactly like TFR does
	hostname := svchost.Hostname(hostport)
	if creds := cliCfg.CredentialsSource().ForHost(hostname); creds != nil {
		// Convert Terraform credentials to ORAS credentials
		// The PrepareRequest method will add the appropriate Authorization header
		req, err := http.NewRequest("GET", "https://"+hostport, nil)
		if err != nil {
			return orasAuth.Credential{}, err
		}
		
		creds.PrepareRequest(req)
		
		// Extract the authorization header and convert to ORAS format
		if authHeader := req.Header.Get("Authorization"); authHeader != "" {
			logger.Debugf("Found Terraform CLI credentials for %s", hostport)
			return parseAuthorizationHeader(authHeader)
		}
	}
	
	return orasAuth.Credential{}, nil
}

// getCredentialsFromEnvironment checks environment variables for OCI registry credentials.
// This provides a fallback authentication method when Terraform CLI configuration
// is not available or desired.
//
// Currently supports:
//   - TG_OCI_REGISTRY_TOKEN: Bearer token for authentication
//
// Future versions could extend this to support additional patterns like:
//   - TF_TOKEN_<hostname>: Host-specific tokens (similar to TFR)
//   - Registry-specific environment variables
//
// Parameters:
//   - hostport: Registry hostname (used for future host-specific token support)
//   - logger: Logger for debug output
//
// Returns ORAS credentials and a boolean indicating whether credentials were found.
func getCredentialsFromEnvironment(hostport string, logger log.Logger) (orasAuth.Credential, bool) {
	// Check TG_OCI_REGISTRY_TOKEN (primary fallback)
	if token := os.Getenv(ociAuthTokenEnvName); token != "" {
		logger.Debugf("Found TG_OCI_REGISTRY_TOKEN for %s", hostport)
		return orasAuth.Credential{
			AccessToken: token,
		}, true
	}
	
	// Could add support for TF_TOKEN_<hostname> pattern here in the future
	// This would be automatic through the Terraform CLI config system
	
	return orasAuth.Credential{}, false
}

// parseAuthorizationHeader converts an HTTP Authorization header to ORAS credentials.
// This function handles the common authentication header formats used by container
// registries and converts them to the format expected by the ORAS library.
//
// Supported formats:
//   - "Bearer <token>": OAuth2 bearer tokens (most common for registries)
//   - "Basic <base64>": HTTP Basic authentication (passed through to ORAS)
//   - Other formats: Passed as access tokens for ORAS to handle
//
// The function uses a simple prefix-based approach rather than complex parsing
// to handle the most common authentication scenarios. ORAS handles the detailed
// protocol implementation for each authentication type.
//
// Parameters:
//   - authHeader: Raw Authorization header value from HTTP response
//
// Returns ORAS credentials configured for the detected authentication type.
func parseAuthorizationHeader(authHeader string) (orasAuth.Credential, error) {
	switch {
	case strings.HasPrefix(authHeader, "Bearer "):
		return orasAuth.Credential{AccessToken: authHeader[7:]}, nil
	case strings.HasPrefix(authHeader, "Basic "):
		return orasAuth.Credential{AccessToken: authHeader[6:]}, nil
	default:
		return orasAuth.Credential{AccessToken: authHeader}, nil
	}
}

// getCredentialsFromOCIConfig retrieves credentials from the Terragrunt OCI configuration.
// It checks for registry-specific credentials and returns them if found.
func getCredentialsFromOCIConfig(ctx context.Context, hostport string, ociConfig *ociconfig.OCIConfig, logger log.Logger) (orasAuth.Credential, bool) {
    // Find registry-specific credentials
    creds := ociConfig.FindCredentialsForRegistry(hostport)
    if creds == nil {
        return orasAuth.Credential{}, false
    }
    
    // Check if authentication is explicitly disabled for this registry
    if creds.IsAuthDisabled() {
        logger.Debugf("Authentication explicitly disabled for %s in OCI config", hostport)
        return orasAuth.EmptyCredential, true
    }
    
    // Try username/password (highest priority)
    if creds.Username != nil && *creds.Username != "" && creds.Password != nil && *creds.Password != "" {
        logger.Debugf("Using username/password authentication from OCI config for %s", hostport)
        return orasAuth.Credential{
            Username: *creds.Username,
            Password: *creds.Password,
        }, true
    }
    
    // Try token
    if creds.Token != nil && *creds.Token != "" {
        logger.Debugf("Using token authentication from OCI config for %s", hostport)
        return orasAuth.Credential{
            AccessToken: *creds.Token,
        }, true
    }

    // Docker config files are now handled in the main credential lookup flow
    // in getOCICredentials, so we don't need to check them here

    
    // Try token command
    if len(creds.TokenCommand) > 0 {
        logger.Debugf("Executing token command from OCI config for %s", hostport)
        token, err := executeTokenCommand(ctx, creds.TokenCommand)
        if err != nil {
            logger.Debugf("Token command failed for %s: %v", hostport, err)
        } else if token != "" {
            return orasAuth.Credential{
                AccessToken: token,
            }, true
        }
    }
    
    return orasAuth.Credential{}, false
}

// executeTokenCommand runs a command to get an authentication token.
// The command's output (stdout) is used as the token.
func executeTokenCommand(ctx context.Context, cmdArgs []string) (string, error) {
    if len(cmdArgs) == 0 {
        return "", fmt.Errorf("empty token command")
    }
    
    cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
    output, err := cmd.Output()
    if err != nil {
        var exitErr *exec.ExitError
        if errors.As(err, &exitErr) {
            return "", fmt.Errorf("token command failed: %v, stderr: %s", err, exitErr.Stderr)
        }
        return "", fmt.Errorf("token command failed: %v", err)
    }
    
    // Trim whitespace from the output
    token := strings.TrimSpace(string(output))
    if token == "" {
        return "", fmt.Errorf("token command returned empty token")
    }
    
    return token, nil
}

func getCredentialsFromDockerConfigFiles(ctx context.Context, hostport string, configFiles []string, logger log.Logger) (orasAuth.Credential, error) {
    // Note: Paths should already be expanded by GetDockerConfigFiles
    for _, configFile := range configFiles {
        logger.Tracef("Checking Docker config file: %s", configFile)
        cred, err := readDockerConfigFile(ctx, hostport, configFile, logger)
        if err != nil {
            logger.Tracef("Error reading %s: %v", configFile, err)
            continue
        }
        if cred != (orasAuth.Credential{}) {
            logger.Debugf("Found credentials in %s for %s", configFile, hostport)
            return cred, nil
        }
    }
    return orasAuth.Credential{}, nil
}

func readDockerConfigFile(ctx context.Context, hostport, filename string, logger log.Logger) (orasAuth.Credential, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return orasAuth.Credential{}, err
    }
    
    var config struct {
        Auths map[string]*struct {
            Auth     string `json:"auth"`
            Username string `json:"username"`
            Password string `json:"password"`
        } `json:"auths"`
    }
    
    if err := json.Unmarshal(data, &config); err != nil {
        return orasAuth.Credential{}, fmt.Errorf("parsing %s: %w", filename, err)
    }
    
    // Look for exact match first, then domain match
    for authKey, auth := range config.Auths {
        if auth == nil {
            continue
        }
        
        // Check if this auth entry matches our registry
        if authKey == hostport || authKey == strings.Split(hostport, ":")[0] {
            // First try username/password fields if present
            if auth.Username != "" && auth.Password != "" {
                logger.Debugf("Found username/password credentials in %s for %s", filename, hostport)
                return orasAuth.Credential{
                    Username: auth.Username,
                    Password: auth.Password,
                }, nil
            }
            
            // Then try auth field if present
            if auth.Auth != "" {
                // Docker stores auth as base64(username:password)
                authBytes, err := base64.StdEncoding.DecodeString(auth.Auth)
                if err != nil {
                    logger.Debugf("Error decoding auth in %s for %s: %v", filename, hostport, err)
                    continue
                }
                
                username, password, hasColon := strings.Cut(string(authBytes), ":")
                if hasColon {
                    logger.Debugf("Found base64-encoded credentials in %s for %s", filename, hostport)
                    return orasAuth.Credential{
                        Username: username,
                        Password: password,
                    }, nil
                }
            }
        }
    }
    
    return orasAuth.Credential{}, nil
}