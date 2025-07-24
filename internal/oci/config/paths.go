package config

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultDockerConfigFiles returns the default paths to search for Docker config files.
// This follows the standard Docker and OCI container tool conventions:
// - ~/.docker/config.json (standard Docker location)
// - $XDG_CONFIG_HOME/containers/auth.json (podman/buildah location)
// - $XDG_RUNTIME_DIR/containers/auth.json (podman/buildah runtime location)
// - $HOME/.config/containers/auth.json (fallback if XDG_CONFIG_HOME not set)
func DefaultDockerConfigFiles() []string {
	var paths []string
	
	// Standard Docker config location
	homeDir, err := os.UserHomeDir()
	if err == nil {
		paths = append(paths, filepath.Join(homeDir, ".docker", "config.json"))
	}
	
	// XDG_CONFIG_HOME location (podman/buildah)
	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfigHome == "" && homeDir != "" {
		// Default to $HOME/.config if XDG_CONFIG_HOME not set
		xdgConfigHome = filepath.Join(homeDir, ".config")
	}
	
	if xdgConfigHome != "" {
		paths = append(paths, filepath.Join(xdgConfigHome, "containers", "auth.json"))
	}
	
	// XDG_RUNTIME_DIR location (podman/buildah runtime)
	if xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntimeDir != "" {
		paths = append(paths, filepath.Join(xdgRuntimeDir, "containers", "auth.json"))
	}
	
	return paths
}

// ExpandPath expands a path with environment variables and ~ for home directory.
// This allows users to specify paths like "~/my/path" or "$HOME/my/path" in config.
func ExpandPath(path string) string {
	// Replace ~ with home directory
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			// Handle ~ at the beginning of the path
			if len(path) > 1 && path[1] == '/' {
				path = filepath.Join(homeDir, path[2:])
			} else {
				path = filepath.Join(homeDir, path[1:])
			}
		}
	}
	
	// Expand environment variables
	return os.ExpandEnv(path)
}

// ExpandPaths expands a list of paths with environment variables and ~ for home directory.
func ExpandPaths(paths []string) []string {
	if paths == nil {
		return nil
	}
	
	expanded := make([]string, len(paths))
	for i, path := range paths {
		expanded[i] = ExpandPath(path)
	}
	
	return expanded
}