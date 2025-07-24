package config

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestOCIConfigFileDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *OCIConfigFile
		expected *OCIConfig
		hasError bool
	}{
		{
			name:     "nil config",
			input:    nil,
			expected: nil,
			hasError: false,
		},
		{
			name:  "basic config with scalar values",
			input: &OCIConfigFile{
				DiscoverAmbientCredentials: boolPtr(true),
				CacheCredentials:           boolPtr(false),
				Timeout:                    strPtr("60s"),
				RetryAttempts:              intPtr(5),
				DefaultCredentialHelper:    strPtr("desktop"),
			},
			expected: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(true),
				CacheCredentials:           boolPtr(false),
				Timeout:                    strPtr("60s"),
				RetryAttempts:              intPtr(5),
				DefaultCredentialHelper:    strPtr("desktop"),
			},
			hasError: false,
		},
		{
			name: "config with credentials blocks",
			input: &OCIConfigFile{
				Credentials: []OCICredentialsConfigFile{
					{
						Registry:         "registry.example.com",
						Username:         strPtr("user"),
						Password:         strPtr("pass"),
						Timeout:          strPtr("30s"),
						RetryAttempts:    intPtr(3),
						CacheCredentials: boolPtr(true),
					},
				},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry:         "registry.example.com",
						Username:         strPtr("user"),
						Password:         strPtr("pass"),
						Timeout:          strPtr("30s"),
						RetryAttempts:    intPtr(3),
						CacheCredentials: boolPtr(true),
					},
				},
			},
			hasError: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			
			result, err := test.input.Decode(&hcl.EvalContext{})
			
			if test.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected, result)
			}
		})
	}
}

func TestOCICredentialsConfigFileDecoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    OCICredentialsConfigFile
		expected OCICredentialsConfig
	}{
		{
			name: "basic credentials config",
			input: OCICredentialsConfigFile{
				Registry:         "registry.example.com",
				Username:         strPtr("user"),
				Password:         strPtr("pass"),
				Timeout:          strPtr("45s"),
				RetryAttempts:    intPtr(2),
				CacheCredentials: boolPtr(false),
			},
			expected: OCICredentialsConfig{
				Registry:         "registry.example.com",
				Username:         strPtr("user"),
				Password:         strPtr("pass"),
				Timeout:          strPtr("45s"),
				RetryAttempts:    intPtr(2),
				CacheCredentials: boolPtr(false),
			},
		},
		{
			name: "credentials config with token",
			input: OCICredentialsConfigFile{
				Registry: "*.internal.com",
				Token:    strPtr("token123"),
				Timeout:  strPtr("10s"),
			},
			expected: OCICredentialsConfig{
				Registry: "*.internal.com",
				Token:    strPtr("token123"),
				Timeout:  strPtr("10s"),
			},
		},
		{
			name: "credentials config with all new fields",
			input: OCICredentialsConfigFile{
				Registry:         "secure.registry.com",
				CredentialHelper: strPtr("osxkeychain"),
				Timeout:          strPtr("2m"),
				RetryAttempts:    intPtr(10),
				CacheCredentials: boolPtr(true),
			},
			expected: OCICredentialsConfig{
				Registry:         "secure.registry.com",
				CredentialHelper: strPtr("osxkeychain"),
				Timeout:          strPtr("2m"),
				RetryAttempts:    intPtr(10),
				CacheCredentials: boolPtr(true),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			
			configFile := &OCIConfigFile{
				Credentials: []OCICredentialsConfigFile{test.input},
			}
			
			result, err := configFile.Decode(&hcl.EvalContext{})
			require.NoError(t, err)
			require.Len(t, result.Credentials, 1)
			assert.Equal(t, test.expected, result.Credentials[0])
		})
	}
}

func TestOCIConfigFileDecodeWithValidCtyValues(t *testing.T) {
	t.Parallel()

	// Test with valid cty values for slices
	dockerConfigFiles := cty.ListVal([]cty.Value{
		cty.StringVal("~/.docker/config.json"),
		cty.StringVal("/etc/docker/config.json"),
	})
	
	credentialHelpers := cty.ListVal([]cty.Value{
		cty.StringVal("desktop"),
		cty.StringVal("osxkeychain"),
	})

	tokenCommand := cty.ListVal([]cty.Value{
		cty.StringVal("aws"),
		cty.StringVal("ecr"),
		cty.StringVal("get-login-password"),
	})

	configFile := &OCIConfigFile{
		DockerConfigFiles: &dockerConfigFiles,
		CredentialHelpers: &credentialHelpers,
		Credentials: []OCICredentialsConfigFile{
			{
				Registry:     "123456789.dkr.ecr.us-west-2.amazonaws.com",
				TokenCommand: &tokenCommand,
			},
		},
	}

	result, err := configFile.Decode(&hcl.EvalContext{})
	require.NoError(t, err)
	
	assert.Equal(t, []string{"~/.docker/config.json", "/etc/docker/config.json"}, result.DockerConfigFiles)
	assert.Equal(t, []string{"desktop", "osxkeychain"}, result.CredentialHelpers)
	require.Len(t, result.Credentials, 1)
	assert.Equal(t, []string{"aws", "ecr", "get-login-password"}, result.Credentials[0].TokenCommand)
}