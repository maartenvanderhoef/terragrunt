package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultDockerConfigFiles(t *testing.T) {
	// Save original environment variables
	origXdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	origXdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
	
	// Restore environment variables after test
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", origXdgConfigHome)
		os.Setenv("XDG_RUNTIME_DIR", origXdgRuntimeDir)
	}()
	
	// Test with XDG variables set
	os.Setenv("XDG_CONFIG_HOME", "/test/config")
	os.Setenv("XDG_RUNTIME_DIR", "/test/runtime")
	
	paths := DefaultDockerConfigFiles()
	
	// Should have at least 3 paths
	if len(paths) < 3 {
		t.Errorf("Expected at least 3 default paths, got %d", len(paths))
	}
	
	// Check for expected paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("Could not determine home directory: %v", err)
	}
	
	expectedPaths := map[string]bool{
		filepath.Join(homeDir, ".docker", "config.json"):      false,
		filepath.Join("/test/config", "containers", "auth.json"): false,
		filepath.Join("/test/runtime", "containers", "auth.json"): false,
	}
	
	for _, path := range paths {
		if _, exists := expectedPaths[path]; exists {
			expectedPaths[path] = true
		}
	}
	
	for path, found := range expectedPaths {
		if !found {
			t.Errorf("Expected path %s not found in default paths", path)
		}
	}
	
	// Test with XDG variables unset
	os.Unsetenv("XDG_CONFIG_HOME")
	os.Unsetenv("XDG_RUNTIME_DIR")
	
	paths = DefaultDockerConfigFiles()
	
	// Should have at least 2 paths (Docker and fallback XDG_CONFIG_HOME)
	if len(paths) < 2 {
		t.Errorf("Expected at least 2 default paths with XDG vars unset, got %d", len(paths))
	}
	
	// Should include fallback XDG_CONFIG_HOME path
	fallbackXdgPath := filepath.Join(homeDir, ".config", "containers", "auth.json")
	foundFallback := false
	for _, path := range paths {
		if path == fallbackXdgPath {
			foundFallback = true
			break
		}
	}
	
	if !foundFallback {
		t.Errorf("Expected fallback XDG_CONFIG_HOME path %s not found in default paths", fallbackXdgPath)
	}
}

func TestExpandPath(t *testing.T) {
	// Save original environment variables
	origHome := os.Getenv("HOME")
	origTestVar := os.Getenv("TEST_VAR")
	
	// Restore environment variables after test
	defer func() {
		os.Setenv("HOME", origHome)
		os.Setenv("TEST_VAR", origTestVar)
	}()
	
	// Set test environment variables
	os.Setenv("HOME", "/test/home")
	os.Setenv("TEST_VAR", "/test/var")
	
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Home directory expansion",
			input:    "~/config/file.json",
			expected: filepath.Join("/test/home", "config/file.json"),
		},
		{
			name:     "Environment variable expansion",
			input:    "$TEST_VAR/config/file.json",
			expected: "/test/var/config/file.json",
		},
		{
			name:     "Combined expansion",
			input:    "~/$TEST_VAR/file.json",
			expected: "/test/home//test/var/file.json", // Note: Double slash is expected due to how filepath.Join works with absolute paths
		},
		{
			name:     "No expansion needed",
			input:    "/absolute/path/file.json",
			expected: "/absolute/path/file.json",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExpandPath(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestExpandPaths(t *testing.T) {
	// Save original environment variables
	origHome := os.Getenv("HOME")
	
	// Restore environment variables after test
	defer func() {
		os.Setenv("HOME", origHome)
	}()
	
	// Set test environment variables
	os.Setenv("HOME", "/test/home")
	
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Mixed paths",
			input:    []string{"~/file1.json", "/absolute/file2.json", "$HOME/file3.json"},
			expected: []string{filepath.Join("/test/home", "file1.json"), "/absolute/file2.json", "/test/home/file3.json"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExpandPaths(tc.input)
			
			if tc.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
				return
			}
			
			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d paths, got %d", len(tc.expected), len(result))
				return
			}
			
			for i, path := range result {
				if path != tc.expected[i] {
					t.Errorf("Path %d: expected %s, got %s", i, tc.expected[i], path)
				}
			}
		})
	}
}

func TestOCIConfigGetDockerConfigFiles(t *testing.T) {
	// Save original environment variables
	origHome := os.Getenv("HOME")
	
	// Restore environment variables after test
	defer func() {
		os.Setenv("HOME", origHome)
	}()
	
	// Set test environment variables
	os.Setenv("HOME", "/test/home")
	
	testCases := []struct {
		name           string
		config         *OCIConfig
		expectedLength int
		checkPaths     map[string]bool
	}{
		{
			name:           "Nil config",
			config:         nil,
			expectedLength: 2, // At least Docker and fallback XDG paths
			checkPaths: map[string]bool{
				filepath.Join("/test/home", ".docker", "config.json"): true,
			},
		},
		{
			name:           "Nil DockerConfigFiles",
			config:         &OCIConfig{DockerConfigFiles: nil},
			expectedLength: 2, // At least Docker and fallback XDG paths
			checkPaths: map[string]bool{
				filepath.Join("/test/home", ".docker", "config.json"): true,
			},
		},
		{
			name:           "Empty DockerConfigFiles",
			config:         &OCIConfig{DockerConfigFiles: []string{}},
			expectedLength: 0,
			checkPaths:     map[string]bool{},
		},
		{
			name:           "Custom DockerConfigFiles",
			config:         &OCIConfig{DockerConfigFiles: []string{"~/custom.json", "/absolute/path.json"}},
			expectedLength: 2,
			checkPaths: map[string]bool{
				filepath.Join("/test/home", "custom.json"): true,
				"/absolute/path.json":                      true,
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.config.GetDockerConfigFiles()
			
			if len(result) != tc.expectedLength {
				t.Errorf("Expected %d paths, got %d", tc.expectedLength, len(result))
			}
			
			for path, shouldExist := range tc.checkPaths {
				found := false
				for _, resultPath := range result {
					if resultPath == path {
						found = true
						break
					}
				}
				
				if found != shouldExist {
					if shouldExist {
						t.Errorf("Expected path %s not found in result", path)
					} else {
						t.Errorf("Unexpected path %s found in result", path)
					}
				}
			}
		})
	}
}