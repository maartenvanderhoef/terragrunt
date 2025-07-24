// Package oci provides common functionality for interacting with OCI (Open Container Initiative) registries.
//
// This package contains shared code for authentication, repository operations, and error handling
// that can be used by different components of Terragrunt that need to interact with OCI registries.
// It is designed to be a common foundation for features like module sources and potential future
// features like remote state backends.
//
// The main components of this package are:
//
// - Authentication: Code for authenticating with OCI registries using various credential sources
// - Repository Operations: Interfaces and implementations for interacting with OCI repositories
// - Error Types: Common error types for OCI operations to ensure consistent error reporting
//
// This package follows the principle of separation of concerns, providing a clean abstraction
// for OCI operations while allowing different components to use this functionality in a
// consistent way.
package oci