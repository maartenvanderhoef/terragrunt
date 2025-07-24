package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetDiscoverAmbientCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *OCIConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: DefaultOCIDiscoverAmbientCredentials,
		},
		{
			name:     "nil value",
			config:   &OCIConfig{},
			expected: DefaultOCIDiscoverAmbientCredentials,
		},
		{
			name:     "true value",
			config:   &OCIConfig{DiscoverAmbientCredentials: boolPtr(true)},
			expected: true,
		},
		{
			name:     "false value",
			config:   &OCIConfig{DiscoverAmbientCredentials: boolPtr(false)},
			expected: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetDiscoverAmbientCredentials()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetCacheCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *OCIConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: DefaultOCICacheCredentials,
		},
		{
			name:     "nil value",
			config:   &OCIConfig{},
			expected: DefaultOCICacheCredentials,
		},
		{
			name:     "true value",
			config:   &OCIConfig{CacheCredentials: boolPtr(true)},
			expected: true,
		},
		{
			name:     "false value",
			config:   &OCIConfig{CacheCredentials: boolPtr(false)},
			expected: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetCacheCredentials()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetCacheCredentialsForRegistry(t *testing.T) {
	t.Parallel()

	registry := "registry.example.com"
	otherRegistry := "other.example.com"

	tests := []struct {
		name     string
		config   *OCIConfig
		registry string
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			registry: registry,
			expected: DefaultOCICacheCredentials,
		},
		{
			name:     "no registry-specific config",
			config:   &OCIConfig{CacheCredentials: boolPtr(true)},
			registry: registry,
			expected: true,
		},
		{
			name: "registry-specific config",
			config: &OCIConfig{
				CacheCredentials: boolPtr(true),
				Credentials: []OCICredentialsConfig{
					{
						Registry:         registry,
						CacheCredentials: boolPtr(false),
					},
				},
			},
			registry: registry,
			expected: false,
		},
		{
			name: "registry-specific config for different registry",
			config: &OCIConfig{
				CacheCredentials: boolPtr(true),
				Credentials: []OCICredentialsConfig{
					{
						Registry:         otherRegistry,
						CacheCredentials: boolPtr(false),
					},
				},
			},
			registry: registry,
			expected: true,
		},
		{
			name: "wildcard registry match",
			config: &OCIConfig{
				CacheCredentials: boolPtr(true),
				Credentials: []OCICredentialsConfig{
					{
						Registry:         "*.example.com",
						CacheCredentials: boolPtr(false),
					},
				},
			},
			registry: registry,
			expected: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetCacheCredentialsForRegistry(test.registry)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetRetryAttempts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *OCIConfig
		expected int
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: DefaultOCIRetryAttempts,
		},
		{
			name:     "nil value",
			config:   &OCIConfig{},
			expected: DefaultOCIRetryAttempts,
		},
		{
			name:     "custom value",
			config:   &OCIConfig{RetryAttempts: intPtr(5)},
			expected: 5,
		},
		{
			name:     "zero value",
			config:   &OCIConfig{RetryAttempts: intPtr(0)},
			expected: 0,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetRetryAttempts()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetRetryAttemptsForRegistry(t *testing.T) {
	t.Parallel()

	registry := "registry.example.com"
	otherRegistry := "other.example.com"

	tests := []struct {
		name     string
		config   *OCIConfig
		registry string
		expected int
	}{
		{
			name:     "nil config",
			config:   nil,
			registry: registry,
			expected: DefaultOCIRetryAttempts,
		},
		{
			name:     "no registry-specific config",
			config:   &OCIConfig{RetryAttempts: intPtr(5)},
			registry: registry,
			expected: 5,
		},
		{
			name: "registry-specific config",
			config: &OCIConfig{
				RetryAttempts: intPtr(3),
				Credentials: []OCICredentialsConfig{
					{
						Registry:      registry,
						RetryAttempts: intPtr(7),
					},
				},
			},
			registry: registry,
			expected: 7,
		},
		{
			name: "registry-specific config for different registry",
			config: &OCIConfig{
				RetryAttempts: intPtr(3),
				Credentials: []OCICredentialsConfig{
					{
						Registry:      otherRegistry,
						RetryAttempts: intPtr(7),
					},
				},
			},
			registry: registry,
			expected: 3,
		},
		{
			name: "wildcard registry match",
			config: &OCIConfig{
				RetryAttempts: intPtr(3),
				Credentials: []OCICredentialsConfig{
					{
						Registry:      "*.example.com",
						RetryAttempts: intPtr(1),
					},
				},
			},
			registry: registry,
			expected: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetRetryAttemptsForRegistry(test.registry)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetTimeoutDuration(t *testing.T) {
	t.Parallel()

	defaultDuration, _ := time.ParseDuration(DefaultOCITimeout)
	customDuration, _ := time.ParseDuration("1m30s")

	tests := []struct {
		name     string
		config   *OCIConfig
		expected time.Duration
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: defaultDuration,
		},
		{
			name:     "nil value",
			config:   &OCIConfig{},
			expected: defaultDuration,
		},
		{
			name:     "empty string",
			config:   &OCIConfig{Timeout: stringPtr("")},
			expected: defaultDuration,
		},
		{
			name:     "valid duration",
			config:   &OCIConfig{Timeout: stringPtr("1m30s")},
			expected: customDuration,
		},
		{
			name:     "invalid duration",
			config:   &OCIConfig{Timeout: stringPtr("not-a-duration")},
			expected: defaultDuration, // Should fall back to default
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetTimeoutDuration()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetTimeoutDurationForRegistry(t *testing.T) {
	t.Parallel()

	registry := "registry.example.com"
	otherRegistry := "other.example.com"
	defaultDuration, _ := time.ParseDuration(DefaultOCITimeout)
	globalDuration, _ := time.ParseDuration("2m")
	registryDuration, _ := time.ParseDuration("45s")

	tests := []struct {
		name     string
		config   *OCIConfig
		registry string
		expected time.Duration
	}{
		{
			name:     "nil config",
			config:   nil,
			registry: registry,
			expected: defaultDuration,
		},
		{
			name:     "no registry-specific config",
			config:   &OCIConfig{Timeout: stringPtr("2m")},
			registry: registry,
			expected: globalDuration,
		},
		{
			name: "registry-specific config",
			config: &OCIConfig{
				Timeout: stringPtr("2m"),
				Credentials: []OCICredentialsConfig{
					{
						Registry: registry,
						Timeout:  stringPtr("45s"),
					},
				},
			},
			registry: registry,
			expected: registryDuration,
		},
		{
			name: "registry-specific config for different registry",
			config: &OCIConfig{
				Timeout: stringPtr("2m"),
				Credentials: []OCICredentialsConfig{
					{
						Registry: otherRegistry,
						Timeout:  stringPtr("45s"),
					},
				},
			},
			registry: registry,
			expected: globalDuration,
		},
		{
			name: "wildcard registry match",
			config: &OCIConfig{
				Timeout: stringPtr("2m"),
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.example.com",
						Timeout:  stringPtr("45s"),
					},
				},
			},
			registry: registry,
			expected: registryDuration,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.GetTimeoutDurationForRegistry(test.registry)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestHasAnyAuthMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   OCICredentialsConfig
		expected bool
	}{
		{
			name:     "empty config",
			config:   OCICredentialsConfig{Registry: "registry.example.com"},
			expected: false,
		},
		{
			name: "has username/password",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Username: stringPtr("user"),
				Password: stringPtr("pass"),
			},
			expected: true,
		},
		{
			name: "has token",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Token:    stringPtr("token"),
			},
			expected: true,
		},
		{
			name: "has credential helper",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				CredentialHelper: stringPtr("helper"),
			},
			expected: true,
		},
		{
			name: "has token command",
			config: OCICredentialsConfig{
				Registry:     "registry.example.com",
				TokenCommand: []string{"echo", "token"},
			},
			expected: true,
		},
		{
			name: "has disable auth",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: boolPtr(true),
			},
			expected: true,
		},
		{
			name: "empty values don't count as auth methods",
			config: OCICredentialsConfig{
				Registry:         "registry.example.com",
				Username:         stringPtr(""),
				Password:         stringPtr(""),
				Token:            stringPtr(""),
				CredentialHelper: stringPtr(""),
				TokenCommand:     []string{},
				DisableAuth:      boolPtr(false),
			},
			expected: false,
		},
		{
			name: "username without password doesn't count",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Username: stringPtr("user"),
			},
			expected: false,
		},
		{
			name: "password without username doesn't count",
			config: OCICredentialsConfig{
				Registry: "registry.example.com",
				Password: stringPtr("pass"),
			},
			expected: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.HasAnyAuthMethod()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestIsAuthDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   OCICredentialsConfig
		expected bool
	}{
		{
			name:     "empty config",
			config:   OCICredentialsConfig{Registry: "registry.example.com"},
			expected: false,
		},
		{
			name: "auth disabled true",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: boolPtr(true),
			},
			expected: true,
		},
		{
			name: "auth disabled false",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: boolPtr(false),
			},
			expected: false,
		},
		{
			name: "auth not specified (nil)",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				DisableAuth: nil,
			},
			expected: false,
		},
		{
			name: "has other auth methods",
			config: OCICredentialsConfig{
				Registry:    "registry.example.com",
				Username:    stringPtr("user"),
				Password:    stringPtr("pass"),
				DisableAuth: boolPtr(true), // Should still return true even with other methods
			},
			expected: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := test.config.IsAuthDisabled()
			assert.Equal(t, test.expected, result)
		})
	}
}

// Helper functions for creating pointers
func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}