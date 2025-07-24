package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOCIConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      *OCIConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: false,
		},
		{
			name: "valid config with defaults",
			config: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(true),
				CacheCredentials:           boolPtr(true),
				RetryAttempts:              intPtr(3),
				Timeout:                    strPtr("30s"),
			},
			expectError: false,
		},
		{
			name: "valid config with custom values",
			config: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),
				DockerConfigFiles:          []string{"/path/to/config.json"},
				CredentialHelpers:          []string{"osxkeychain", "pass"},
				DefaultCredentialHelper:    strPtr("desktop"),
				CacheCredentials:           boolPtr(false),
				RetryAttempts:              intPtr(5),
				Timeout:                    strPtr("1m30s"),
				Credentials: []OCICredentialsConfig{
					{
						Registry: "registry.example.com",
						Username: strPtr("user"),
						Password: strPtr("pass"),
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid timeout format",
			config: &OCIConfig{
				Timeout: strPtr("not-a-duration"),
			},
			expectError: true,
			errorMsg:    "invalid timeout format",
		},
		{
			name: "negative retry attempts",
			config: &OCIConfig{
				RetryAttempts: intPtr(-1),
			},
			expectError: true,
			errorMsg:    "retry_attempts must be non-negative",
		},
		{
			name: "valid credentials with multiple auth methods",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry:         "registry.example.com",
						Username:         strPtr("user"),
						Password:         strPtr("pass"),
						Token:            strPtr("token"),
						CredentialHelper: strPtr("osxkeychain"),
						TokenCommand:     []string{"echo", "token"},
					},
				},
			},
			expectError: false, // Multiple auth methods are allowed and tried in priority order
		},
	}

	for _, test := range tests {
		// Capture range variable to avoid it changing during test execution
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.config.Validate()

			if test.expectError {
				assert.Error(t, err)
				if test.errorMsg != "" {
					assert.Contains(t, err.Error(), test.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOCICredentialsConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      OCICredentialsConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with username/password",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Username: strPtr("user"),
				Password: strPtr("pass"),
			},
			expectError: false,
		},
		{
			name: "valid config with token",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Token:    strPtr("token"),
			},
			expectError: false,
		},
		{
			name: "valid config with credential helper",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				CredentialHelper: strPtr("osxkeychain"),
			},
			expectError: false,
		},
		{
			name: "valid config with token command",
			config: OCICredentialsConfig{
				Registry:     "registry.example.com",
				TokenCommand: []string{"echo", "token"},
			},
			expectError: false,
		},
		{
			name: "valid config with disable auth",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: boolPtr(true),
			},
			expectError: false,
		},
		{
			name: "valid config with wildcard registry",
			config: OCICredentialsConfig{
				Registry:    "*.example.com",
				DisableAuth: boolPtr(true),
			},
			expectError: false,
		},
		{
			name: "empty registry",
			config: OCICredentialsConfig{
				Registry: "",
				Token:    strPtr("token"),
			},
			expectError: true,
			errorMsg:    "registry hostname cannot be empty",
		},
		{
			name: "username without password",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Username: strPtr("user"),
			},
			expectError: true,
			errorMsg:    "username and password must be specified together",
		},
		{
			name: "password without username",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Password: strPtr("pass"),
			},
			expectError: true,
			errorMsg:    "username and password must be specified together",
		},
	}

	for _, test := range tests {
		// Capture range variable to avoid it changing during test execution
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.config.Validate()

			if test.expectError {
				assert.Error(t, err)
				if test.errorMsg != "" {
					assert.Contains(t, err.Error(), test.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFindCredentialsForRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *OCIConfig
		registry       string
		expectedResult *OCICredentialsConfig
	}{
		{
			name: "exact match takes precedence over wildcard",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.example.com",
						Username: strPtr("wildcard-user"),
						Password: strPtr("wildcard-pass"),
					},
					{
						Registry: "exact.example.com",
						Username: strPtr("exact-user"),
						Password: strPtr("exact-pass"),
					},
				},
			},
			registry: "exact.example.com",
			expectedResult: &OCICredentialsConfig{
				Registry: "exact.example.com",
				Username: strPtr("exact-user"),
				Password: strPtr("exact-pass"),
			},
		},
		{
			name: "wildcard match when no exact match",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.example.com",
						Username: strPtr("wildcard-user"),
						Password: strPtr("wildcard-pass"),
					},
					{
						Registry: "another.registry.com",
						Username: strPtr("another-user"),
						Password: strPtr("another-pass"),
					},
				},
			},
			registry: "foo.example.com",
			expectedResult: &OCICredentialsConfig{
				Registry: "*.example.com",
				Username: strPtr("wildcard-user"),
				Password: strPtr("wildcard-pass"),
			},
		},
		{
			name: "no match returns nil",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "exact.example.com",
						Username: strPtr("exact-user"),
						Password: strPtr("exact-pass"),
					},
					{
						Registry: "*.example.com",
						Username: strPtr("wildcard-user"),
						Password: strPtr("wildcard-pass"),
					},
				},
			},
			registry:       "no-match.com",
			expectedResult: nil,
		},
		{
			name: "multiple wildcard patterns - first match wins",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.example.com",
						Username: strPtr("first-wildcard"),
						Password: strPtr("first-pass"),
					},
					{
						Registry: "*.example.com", // Duplicate pattern
						Username: strPtr("second-wildcard"),
						Password: strPtr("second-pass"),
					},
				},
			},
			registry: "foo.example.com",
			expectedResult: &OCICredentialsConfig{
				Registry: "*.example.com",
				Username: strPtr("first-wildcard"),
				Password: strPtr("first-pass"),
			},
		},
		{
			name: "complex wildcard matching",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.company.com",
						Username: strPtr("company-user"),
						Password: strPtr("company-pass"),
					},
					{
						Registry: "*.internal.company.com",
						Username: strPtr("internal-user"),
						Password: strPtr("internal-pass"),
					},
				},
			},
			registry: "registry.company.com",
			expectedResult: &OCICredentialsConfig{
				Registry: "*.company.com",
				Username: strPtr("company-user"),
				Password: strPtr("company-pass"),
			},
		},
		{
			name: "subdomain wildcard matching",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.company.com",
						Token:    strPtr("company-token"),
					},
				},
			},
			registry: "foo.bar.baz.company.com",
			expectedResult: &OCICredentialsConfig{
				Registry: "*.company.com",
				Token:    strPtr("company-token"),
			},
		},
		{
			name:           "nil config returns nil",
			config:         nil,
			registry:       "any.registry.com",
			expectedResult: nil,
		},
		{
			name: "empty credentials list returns nil",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{},
			},
			registry:       "any.registry.com",
			expectedResult: nil,
		},
		{
			name: "exact match with different auth methods",
			config: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry:         "registry.example.com",
						CredentialHelper: strPtr("osxkeychain"),
					},
				},
			},
			registry: "registry.example.com",
			expectedResult: &OCICredentialsConfig{
				Registry:         "registry.example.com",
				CredentialHelper: strPtr("osxkeychain"),
			},
		},
	}

	for _, test := range tests {
		// Capture range variable to avoid it changing during test execution
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := test.config.FindCredentialsForRegistry(test.registry)

			if test.expectedResult == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, test.expectedResult.Registry, result.Registry)

				// Check username if expected
				if test.expectedResult.Username != nil {
					assert.NotNil(t, result.Username)
					assert.Equal(t, *test.expectedResult.Username, *result.Username)
				} else {
					assert.Nil(t, result.Username)
				}

				// Check password if expected
				if test.expectedResult.Password != nil {
					assert.NotNil(t, result.Password)
					assert.Equal(t, *test.expectedResult.Password, *result.Password)
				} else {
					assert.Nil(t, result.Password)
				}

				// Check token if expected
				if test.expectedResult.Token != nil {
					assert.NotNil(t, result.Token)
					assert.Equal(t, *test.expectedResult.Token, *result.Token)
				} else {
					assert.Nil(t, result.Token)
				}

				// Check credential helper if expected
				if test.expectedResult.CredentialHelper != nil {
					assert.NotNil(t, result.CredentialHelper)
					assert.Equal(t, *test.expectedResult.CredentialHelper, *result.CredentialHelper)
				} else {
					assert.Nil(t, result.CredentialHelper)
				}
			}
		})
	}
}

func TestGetPrimaryAuthMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         OCICredentialsConfig
		expectedMethod string
	}{
		{
			name: "username/password (highest priority) - overrides all others",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				Username:         strPtr("user"),
				Password:         strPtr("pass"),
				Token:            strPtr("token"),
				CredentialHelper: strPtr("helper"),
				TokenCommand:     []string{"echo", "token"},
				DisableAuth:      boolPtr(true),
			},
			expectedMethod: "basic",
		},
		{
			name: "token (second priority) - overrides lower priority methods",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				Token:            strPtr("token"),
				CredentialHelper: strPtr("helper"),
				TokenCommand:     []string{"echo", "token"},
				DisableAuth:      boolPtr(true),
			},
			expectedMethod: "token",
		},
		{
			name: "credential helper (third priority) - overrides lower priority methods",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				CredentialHelper: strPtr("helper"),
				TokenCommand:     []string{"echo", "token"},
				DisableAuth:      boolPtr(true),
			},
			expectedMethod: "credential_helper",
		},
		{
			name: "token command (fourth priority) - overrides disable auth",
			config: OCICredentialsConfig{
				Registry:     "registry.example.com",
				TokenCommand: []string{"echo", "token"},
				DisableAuth:  boolPtr(true),
			},
			expectedMethod: "token_command",
		},
		{
			name: "disable auth (lowest priority)",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: boolPtr(true),
			},
			expectedMethod: "disabled",
		},
		{
			name: "no auth method configured",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
			},
			expectedMethod: "none",
		},
		{
			name: "empty username/password not considered basic auth",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Username: strPtr(""),
				Password: strPtr(""),
				Token:    strPtr("token"),
			},
			expectedMethod: "token",
		},
		{
			name: "empty token not considered token auth",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				Token:            strPtr(""),
				CredentialHelper: strPtr("helper"),
			},
			expectedMethod: "credential_helper",
		},
		{
			name: "empty credential helper not considered credential helper auth",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				CredentialHelper: strPtr(""),
				TokenCommand:     []string{"echo", "token"},
			},
			expectedMethod: "token_command",
		},
		{
			name: "empty token command not considered token command auth",
			config: OCICredentialsConfig{
				Registry:     "registry.example.com",
				TokenCommand: []string{},
				DisableAuth:  boolPtr(true),
			},
			expectedMethod: "disabled",
		},
		{
			name: "disable auth false not considered disabled",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: boolPtr(false),
			},
			expectedMethod: "none",
		},
		{
			name: "username without password not basic auth",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Username: strPtr("user"),
				Token:    strPtr("token"),
			},
			expectedMethod: "token",
		},
		{
			name: "password without username not basic auth",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Password: strPtr("pass"),
				Token:    strPtr("token"),
			},
			expectedMethod: "token",
		},
	}

	for _, test := range tests {
		// Capture range variable to avoid it changing during test execution
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			method := test.config.GetPrimaryAuthMethod()
			assert.Equal(t, test.expectedMethod, method)
		})
	}
}

func TestCredentialLookupIntegration(t *testing.T) {
	t.Parallel()

	// Test the complete credential lookup workflow
	config := &OCIConfig{
		Credentials: []OCICredentialsConfig{
			{
				Registry: "exact.example.com",
				Username: strPtr("exact-user"),
				Password: strPtr("exact-pass"),
				Token:    strPtr("exact-token"), // Should be ignored due to priority
			},
			{
				Registry:         "*.example.com",
				CredentialHelper: strPtr("osxkeychain"),
			},
			{
				Registry:     "token-cmd.example.com",
				TokenCommand: []string{"echo", "command-token"},
			},
			{
				Registry:    "disabled.example.com",
				DisableAuth: boolPtr(true),
			},
			{
				Registry: "no-auth.example.com",
				// No auth methods configured
			},
		},
	}

	tests := []struct {
		name               string
		registry           string
		expectedFound      bool
		expectedAuthMethod string
	}{
		{
			name:               "exact match uses basic auth (highest priority)",
			registry:           "exact.example.com",
			expectedFound:      true,
			expectedAuthMethod: "basic",
		},
		{
			name:               "wildcard match uses credential helper",
			registry:           "foo.example.com",
			expectedFound:      true,
			expectedAuthMethod: "credential_helper",
		},
		{
			name:               "token command registry",
			registry:           "token-cmd.example.com",
			expectedFound:      true,
			expectedAuthMethod: "token_command",
		},
		{
			name:               "disabled auth registry",
			registry:           "disabled.example.com",
			expectedFound:      true,
			expectedAuthMethod: "disabled",
		},
		{
			name:               "no auth methods configured",
			registry:           "no-auth.example.com",
			expectedFound:      true,
			expectedAuthMethod: "none",
		},
		{
			name:               "no matching registry",
			registry:           "unknown.registry.com",
			expectedFound:      false,
			expectedAuthMethod: "",
		},
	}

	for _, test := range tests {
		// Capture range variable to avoid it changing during test execution
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			creds := config.FindCredentialsForRegistry(test.registry)

			if !test.expectedFound {
				assert.Nil(t, creds)
				return
			}

			assert.NotNil(t, creds)
			authMethod := creds.GetPrimaryAuthMethod()
			assert.Equal(t, test.expectedAuthMethod, authMethod)

			// Verify HasAnyAuthMethod consistency
			hasAuth := creds.HasAnyAuthMethod()
			expectedHasAuth := authMethod != "none"
			assert.Equal(t, expectedHasAuth, hasAuth)

			// Verify IsAuthDisabled consistency
			isDisabled := creds.IsAuthDisabled()
			expectedDisabled := authMethod == "disabled"
			assert.Equal(t, expectedDisabled, isDisabled)
		})
	}
}

// Helper functions for creating pointers to primitive types
func boolPtr(b bool) *bool {
	return &b
}

func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
