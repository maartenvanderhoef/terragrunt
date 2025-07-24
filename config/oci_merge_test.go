package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeOciConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		parent   *OCIConfig
		child    *OCIConfig
		expected *OCIConfig
	}{
		{
			name:     "nil parent",
			parent:   nil,
			child:    &OCIConfig{DiscoverAmbientCredentials: boolPtr(false)},
			expected: &OCIConfig{DiscoverAmbientCredentials: boolPtr(false)},
		},
		{
			name:     "nil child",
			parent:   &OCIConfig{DiscoverAmbientCredentials: boolPtr(true)},
			child:    nil,
			expected: &OCIConfig{DiscoverAmbientCredentials: boolPtr(true)},
		},
		{
			name:     "nil both",
			parent:   nil,
			child:    nil,
			expected: nil,
		},
		{
			name: "merge scalar values with child precedence",
			parent: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(true),
				CacheCredentials:           boolPtr(true),
				RetryAttempts:              intPtr(3),
				Timeout:                    strPtr("30s"),
				DefaultCredentialHelper:    strPtr("parent-helper"),
			},
			child: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),
				RetryAttempts:              intPtr(5),
				// CacheCredentials and Timeout not set in child
			},
			expected: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),           // From child
				CacheCredentials:           boolPtr(true),            // From parent
				RetryAttempts:              intPtr(5),                // From child
				Timeout:                    strPtr("30s"),            // From parent
				DefaultCredentialHelper:    strPtr("parent-helper"),  // From parent
				Credentials:                []OCICredentialsConfig{}, // Empty slice
			},
		},
		{
			name: "merge scalar values with empty child values",
			parent: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(true),
				CacheCredentials:           boolPtr(true),
				RetryAttempts:              intPtr(3),
				Timeout:                    strPtr("30s"),
			},
			child: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),
				CacheCredentials:           boolPtr(false),
				RetryAttempts:              intPtr(0),
				Timeout:                    strPtr(""),
			},
			expected: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),           // From child
				CacheCredentials:           boolPtr(false),           // From child
				RetryAttempts:              intPtr(0),                // From child
				Timeout:                    strPtr(""),               // From child
				Credentials:                []OCICredentialsConfig{}, // Empty slice
			},
		},
		{
			name: "merge slices with complete replacement",
			parent: &OCIConfig{
				DockerConfigFiles: []string{"parent1", "parent2"},
				CredentialHelpers: []string{"parent-helper1", "parent-helper2"},
			},
			child: &OCIConfig{
				DockerConfigFiles: []string{"child1", "child2"},
				// CredentialHelpers not set in child
			},
			expected: &OCIConfig{
				DockerConfigFiles: []string{"child1", "child2"},                 // From child
				CredentialHelpers: []string{"parent-helper1", "parent-helper2"}, // From parent
				Credentials:       []OCICredentialsConfig{},                     // Empty slice
			},
		},
		{
			name: "merge slices with empty child slices",
			parent: &OCIConfig{
				DockerConfigFiles: []string{"parent1", "parent2"},
				CredentialHelpers: []string{"parent-helper1", "parent-helper2"},
			},
			child: &OCIConfig{
				DockerConfigFiles: []string{},
				CredentialHelpers: []string{},
			},
			expected: &OCIConfig{
				DockerConfigFiles: []string{},               // Empty slice from child
				CredentialHelpers: []string{},               // Empty slice from child
				Credentials:       []OCICredentialsConfig{}, // Empty slice
			},
		},
		{
			name: "merge credentials by registry name",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "parent-only.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
					{
						Registry: "both.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
			child: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "child-only.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "both.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
				},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "both.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "child-only.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "parent-only.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
		},
		{
			name: "merge credentials with different auth methods",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "basic-auth.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
					{
						Registry: "token-auth.com",
						Token:    strPtr("parent-token"),
					},
				},
			},
			child: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry:         "helper-auth.com",
						CredentialHelper: strPtr("child-helper"),
					},
					{
						Registry:     "command-auth.com",
						TokenCommand: []string{"echo", "token"},
					},
					{
						Registry:     "token-auth.com",
						TokenCommand: []string{"echo", "child-token"},
					},
				},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "basic-auth.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
					{
						Registry:     "command-auth.com",
						TokenCommand: []string{"echo", "token"},
					},
					{
						Registry:         "helper-auth.com",
						CredentialHelper: strPtr("child-helper"),
					},
					{
						Registry:     "token-auth.com",
						TokenCommand: []string{"echo", "child-token"},
					},
				},
			},
		},
		{
			name: "merge credentials with empty child credentials",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "parent-registry.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
			child: &OCIConfig{
				Credentials: []OCICredentialsConfig{},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "parent-registry.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
		},
		{
			name: "merge credentials with nil child credentials",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "parent-registry.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
			child: &OCIConfig{},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "parent-registry.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
		},
		{
			name: "merge complex config",
			parent: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(true),
				DockerConfigFiles:          []string{"parent1", "parent2"},
				CredentialHelpers:          []string{"parent-helper1", "parent-helper2"},
				DefaultCredentialHelper:    strPtr("parent-helper"),
				CacheCredentials:           boolPtr(true),
				RetryAttempts:              intPtr(3),
				Timeout:                    strPtr("30s"),
				Credentials: []OCICredentialsConfig{
					{
						Registry: "parent-only.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
					{
						Registry: "both.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
			child: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),
				DockerConfigFiles:          []string{"child1", "child2"},
				DefaultCredentialHelper:    strPtr("child-helper"),
				RetryAttempts:              intPtr(5),
				Credentials: []OCICredentialsConfig{
					{
						Registry: "child-only.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "both.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
				},
			},
			expected: &OCIConfig{
				DiscoverAmbientCredentials: boolPtr(false),
				DockerConfigFiles:          []string{"child1", "child2"},
				CredentialHelpers:          []string{"parent-helper1", "parent-helper2"},
				DefaultCredentialHelper:    strPtr("child-helper"),
				CacheCredentials:           boolPtr(true),
				RetryAttempts:              intPtr(5),
				Timeout:                    strPtr("30s"),
				Credentials: []OCICredentialsConfig{
					{
						Registry: "both.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "child-only.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "parent-only.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
		},
		{
			name: "merge with wildcard registry patterns",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.parent.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
			child: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.child.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
				},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "*.child.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
					},
					{
						Registry: "*.parent.com",
						Username: strPtr("parent-user"),
						Password: strPtr("parent-pass"),
					},
				},
			},
		},
		{
			name: "merge with all authentication methods",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry:         "registry.com",
						Username:         strPtr("parent-user"),
						Password:         strPtr("parent-pass"),
						Token:            strPtr("parent-token"),
						CredentialHelper: strPtr("parent-helper"),
						TokenCommand:     []string{"echo", "parent-token"},
						DisableAuth:      boolPtr(false),
					},
				},
			},
			child: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "registry.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
						// Other auth methods not specified in child
					},
				},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "registry.com",
						Username: strPtr("child-user"),
						Password: strPtr("child-pass"),
						// Child completely replaces parent for this registry
					},
				},
			},
		},
		{
			name: "merge with deterministic ordering",
			parent: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "z-registry.com",
						Username: strPtr("z-user"),
						Password: strPtr("z-pass"),
					},
					{
						Registry: "a-registry.com",
						Username: strPtr("a-user"),
						Password: strPtr("a-pass"),
					},
				},
			},
			child: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "m-registry.com",
						Username: strPtr("m-user"),
						Password: strPtr("m-pass"),
					},
				},
			},
			expected: &OCIConfig{
				Credentials: []OCICredentialsConfig{
					{
						Registry: "a-registry.com",
						Username: strPtr("a-user"),
						Password: strPtr("a-pass"),
					},
					{
						Registry: "m-registry.com",
						Username: strPtr("m-user"),
						Password: strPtr("m-pass"),
					},
					{
						Registry: "z-registry.com",
						Username: strPtr("z-user"),
						Password: strPtr("z-pass"),
					},
				},
			},
		},
	}

	for _, test := range tests {
		// Capture range variable to avoid it changing during test execution
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := MergeOciConfig(test.parent, test.child)

			if test.expected == nil {
				assert.Nil(t, result)
				return
			}

			assert.NotNil(t, result)

			// Check scalar values
			if test.expected.DiscoverAmbientCredentials != nil {
				assert.Equal(t, *test.expected.DiscoverAmbientCredentials, *result.DiscoverAmbientCredentials)
			} else {
				assert.Nil(t, result.DiscoverAmbientCredentials)
			}

			if test.expected.CacheCredentials != nil {
				assert.Equal(t, *test.expected.CacheCredentials, *result.CacheCredentials)
			} else {
				assert.Nil(t, result.CacheCredentials)
			}

			if test.expected.RetryAttempts != nil {
				assert.Equal(t, *test.expected.RetryAttempts, *result.RetryAttempts)
			} else {
				assert.Nil(t, result.RetryAttempts)
			}

			if test.expected.Timeout != nil {
				assert.Equal(t, *test.expected.Timeout, *result.Timeout)
			} else {
				assert.Nil(t, result.Timeout)
			}

			if test.expected.DefaultCredentialHelper != nil {
				assert.Equal(t, *test.expected.DefaultCredentialHelper, *result.DefaultCredentialHelper)
			} else {
				assert.Nil(t, result.DefaultCredentialHelper)
			}

			// Check slices
			assert.Equal(t, test.expected.DockerConfigFiles, result.DockerConfigFiles)
			assert.Equal(t, test.expected.CredentialHelpers, result.CredentialHelpers)

			// Check credentials
			assert.Equal(t, len(test.expected.Credentials), len(result.Credentials))

			// Create maps for easier comparison
			expectedCredMap := make(map[string]OCICredentialsConfig)
			for _, cred := range test.expected.Credentials {
				expectedCredMap[cred.Registry] = cred
			}

			resultCredMap := make(map[string]OCICredentialsConfig)
			for _, cred := range result.Credentials {
				resultCredMap[cred.Registry] = cred
			}

			assert.Equal(t, len(expectedCredMap), len(resultCredMap))

			for registry, expectedCred := range expectedCredMap {
				resultCred, ok := resultCredMap[registry]
				assert.True(t, ok, "Missing credential for registry %s", registry)

				assert.Equal(t, expectedCred.Registry, resultCred.Registry)

				// Compare username
				if expectedCred.Username != nil {
					assert.NotNil(t, resultCred.Username)
					assert.Equal(t, *expectedCred.Username, *resultCred.Username)
				} else {
					assert.Nil(t, resultCred.Username)
				}

				// Compare password
				if expectedCred.Password != nil {
					assert.NotNil(t, resultCred.Password)
					assert.Equal(t, *expectedCred.Password, *resultCred.Password)
				} else {
					assert.Nil(t, resultCred.Password)
				}

				// Compare token
				if expectedCred.Token != nil {
					assert.NotNil(t, resultCred.Token)
					assert.Equal(t, *expectedCred.Token, *resultCred.Token)
				} else {
					assert.Nil(t, resultCred.Token)
				}

				// Compare credential helper
				if expectedCred.CredentialHelper != nil {
					assert.NotNil(t, resultCred.CredentialHelper)
					assert.Equal(t, *expectedCred.CredentialHelper, *resultCred.CredentialHelper)
				} else {
					assert.Nil(t, resultCred.CredentialHelper)
				}

				// Compare token command
				assert.Equal(t, expectedCred.TokenCommand, resultCred.TokenCommand)

				// Compare disable auth
				if expectedCred.DisableAuth != nil {
					assert.NotNil(t, resultCred.DisableAuth)
					assert.Equal(t, *expectedCred.DisableAuth, *resultCred.DisableAuth)
				} else {
					assert.Nil(t, resultCred.DisableAuth)
				}
			}
		})
	}
}
