package config

import (
	"fmt"

	"github.com/gruntwork-io/terragrunt/internal/ctyhelper"
	ociconfig "github.com/gruntwork-io/terragrunt/internal/oci/config"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Type aliases for backward compatibility
type OCIConfig = ociconfig.OCIConfig
type OCICredentialsConfig = ociconfig.OCICredentialsConfig

// OCIConfigFile represents the OCI configuration as parsed from HCL
// This struct handles the cty.Value types used during HCL parsing
type OCIConfigFile struct {
	DiscoverAmbientCredentials *bool                      `hcl:"discover_ambient_credentials,optional"`
	DockerConfigFiles          *cty.Value                 `hcl:"docker_config_files,optional"`
	CredentialHelpers          *cty.Value                 `hcl:"credential_helpers,optional"`
	DefaultCredentialHelper    *string                    `hcl:"default_credential_helper,optional"`
	CacheCredentials           *bool                      `hcl:"cache_credentials,optional"`
	Timeout                    *string                    `hcl:"timeout,optional"`
	RetryAttempts              *int                       `hcl:"retry_attempts,optional"`
	Credentials                []OCICredentialsConfigFile `hcl:"credentials,block"`
}

// OCICredentialsConfigFile represents a credentials block as parsed from HCL
type OCICredentialsConfigFile struct {
	Registry         string     `hcl:"registry,attr"`
	Username         *string    `hcl:"username,optional"`
	Password         *string    `hcl:"password,optional"`
	Token            *string    `hcl:"token,optional"`
	CredentialHelper *string    `hcl:"credential_helper,optional"`
	TokenCommand     *cty.Value `hcl:"token_command,optional"`
	DisableAuth      *bool      `hcl:"disable_auth,optional"`
	Timeout          *string    `hcl:"timeout,optional"`
	RetryAttempts    *int       `hcl:"retry_attempts,optional"`
	CacheCredentials *bool      `hcl:"cache_credentials,optional"`
}

// Decode converts the OCIConfigFile (HCL parsing structure) to the final OCIConfig structure
// that will be used by the application. This handles converting cty.Value fields to their
// native Go equivalents.
func (cfg *OCIConfigFile) Decode(ctx *hcl.EvalContext) (*ociconfig.OCIConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	result := &ociconfig.OCIConfig{
		DiscoverAmbientCredentials: cfg.DiscoverAmbientCredentials,
		DefaultCredentialHelper:    cfg.DefaultCredentialHelper,
		CacheCredentials:           cfg.CacheCredentials,
		Timeout:                    cfg.Timeout,
		RetryAttempts:              cfg.RetryAttempts,
	}

	// Convert DockerConfigFiles from cty.Value to []string
	if cfg.DockerConfigFiles != nil {
		dockerConfigFiles, err := ctyhelper.ParseCtyValueToStringSlice(*cfg.DockerConfigFiles)
		if err != nil {
			return nil, fmt.Errorf("error parsing docker_config_files: %w", err)
		}
		result.DockerConfigFiles = dockerConfigFiles
	}

	// Convert CredentialHelpers from cty.Value to []string
	if cfg.CredentialHelpers != nil {
		credentialHelpers, err := ctyhelper.ParseCtyValueToStringSlice(*cfg.CredentialHelpers)
		if err != nil {
			return nil, fmt.Errorf("error parsing credential_helpers: %w", err)
		}
		result.CredentialHelpers = credentialHelpers
	}

	// Convert credentials blocks
	for _, credFile := range cfg.Credentials {
		cred := ociconfig.OCICredentialsConfig{
			Registry:         credFile.Registry,
			Username:         credFile.Username,
			Password:         credFile.Password,
			Token:            credFile.Token,
			CredentialHelper: credFile.CredentialHelper,
			DisableAuth:      credFile.DisableAuth,
			Timeout:          credFile.Timeout,
			RetryAttempts:    credFile.RetryAttempts,
			CacheCredentials: credFile.CacheCredentials,
		}

		// Convert TokenCommand from cty.Value to []string
		if credFile.TokenCommand != nil {
			tokenCommand, err := ctyhelper.ParseCtyValueToStringSlice(*credFile.TokenCommand)
			if err != nil {
				return nil, fmt.Errorf("error parsing token_command for registry %s: %w", credFile.Registry, err)
			}
			cred.TokenCommand = tokenCommand
		}

		result.Credentials = append(result.Credentials, cred)
	}

	return result, nil
}

// MergeOciConfig merges two OCI configurations, with child values taking precedence over parent values.
func MergeOciConfig(parent, child *OCIConfig) *OCIConfig {
	return ociconfig.MergeOciConfig(parent, child)
}
