// Portions derived from OpenTofu's OCI distribution implementation
// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0

package oci

import (
	"context"
	"io"
	"time"

	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	orasRegistry "oras.land/oras-go/v2/registry"

	"github.com/gruntwork-io/terragrunt/pkg/log"
	"github.com/gruntwork-io/terragrunt/telemetry"
)

// contextAwareSleep sleeps for the specified duration while respecting context cancellation
func contextAwareSleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RepositoryStore defines the interface for interacting with OCI repositories.
// It provides methods for resolving references and fetching content from OCI registries.
type RepositoryStore interface {
	// Resolve finds the descriptor associated with the given tag name or digest.
	// This method translates the reference into an OCI descriptor that contains the
	// metadata needed to fetch the actual content from the registry.
	//
	// The reference can be:
	//   - A tag name (e.g., "v1.0.0", "latest")
	//   - A digest (e.g., "sha256:abc123...")
	//
	// The returned descriptor includes the content's digest, media type, and size,
	// which are used by subsequent operations to fetch and validate the content.
	Resolve(ctx context.Context, reference string) (ociv1.Descriptor, error)

	// Fetch retrieves the content of a specific blob from the repository.
	// This method downloads the actual bytes for manifests, layers, or other OCI artifacts
	// identified by their content digest.
	//
	// The descriptor must contain a valid digest that exists in the registry. The returned
	// ReadCloser provides streaming access to the content, allowing efficient handling
	// of large blobs without loading everything into memory.
	//
	// The caller is responsible for closing the returned ReadCloser to avoid resource leaks.
	Fetch(ctx context.Context, target ociv1.Descriptor) (io.ReadCloser, error)
}

// orasRepositoryStore implements the RepositoryStore interface using the ORAS-Go
// library. This provides a concrete implementation for interacting with OCI registries
// while abstracting the ORAS-specific details from the rest of the OCI code.
//
// The store wraps an ORAS repository instance and adds Terragrunt-specific logging
// and error handling. It serves as an adapter between Terragrunt's RepositoryStore
// interface and the ORAS library's repository interface.
//
// All operations are logged at the debug level to help with troubleshooting
// authentication and network issues during operations.
type orasRepositoryStore struct {
	repository     orasRegistry.Repository
	registry       string
	repositoryName string
	logger         log.Logger
	telemeter      *telemetry.Telemeter
}

// Ensure orasRepositoryStore implements RepositoryStore
var _ RepositoryStore = (*orasRepositoryStore)(nil)

// Resolve finds the descriptor associated with the given reference (tag name or digest).
// This method translates the reference into an OCI descriptor that contains the
// metadata needed to fetch the actual content from the registry.
//
// The reference can be:
//   - A tag name (e.g., "v1.0.0", "latest")
//   - A digest (e.g., "sha256:abc123...")
//
// The returned descriptor includes the content's digest, media type, and size,
// which are used by subsequent operations to fetch and validate the content.
//
// Parameters:
//   - ctx: Context for the resolution operation
//   - reference: Tag name or digest to resolve
//
// Returns the OCI descriptor for the reference, or an error if resolution fails.
func (r *orasRepositoryStore) Resolve(ctx context.Context, reference string) (ociv1.Descriptor, error) {
	requestID := OCIRequestIDFromContext(ctx)
	r.logger.Debugf("[%s] Resolving OCI reference: %s", requestID, reference)

	var desc ociv1.Descriptor

	// Wrap resolve operation with telemetry
	err := WithOCITelemetry(ctx, r.telemeter, "resolve", r.registry, r.repositoryName, func(ctx context.Context) error {
		var resolveErr error
		desc, resolveErr = r.resolveWithRetry(ctx, reference)
		return resolveErr
	})

	if err != nil {
		return ociv1.Descriptor{}, OCIReferenceResolutionError{registry: r.registry, details: err.Error(), requestID: requestID}
	}

	r.logger.Debugf("[%s] Resolved OCI reference %s to descriptor: %s", requestID, reference, desc.Digest.String())
	return desc, nil
}

// resolveWithRetry implements the retry logic for resolve operations
func (r *orasRepositoryStore) resolveWithRetry(ctx context.Context, reference string) (ociv1.Descriptor, error) {
	requestID := OCIRequestIDFromContext(ctx)
	retryAttempts := OCIRetryAttemptsFromContext(ctx)

	var desc ociv1.Descriptor
	var err error
	var lastErr error

	// Implement retry logic
	for attempt := 0; attempt <= retryAttempts; attempt++ {
		if attempt > 0 {
			r.logger.Tracef("[%s] Retry attempt %d/%d for resolving OCI reference: %s", requestID, attempt, retryAttempts, reference)

			// Check if context is cancelled before retrying
			select {
			case <-ctx.Done():
				requestID := OCIRequestIDFromContext(ctx)
				return ociv1.Descriptor{}, OCITimeoutError{Registry: r.registry, Reason: "resolve: context cancelled", RequestID: requestID}
			default:
				// Add exponential backoff delay between retries with context-aware sleep
				backoffDuration := time.Duration(attempt*attempt) * 100 * time.Millisecond
				if err := contextAwareSleep(ctx, backoffDuration); err != nil {
					requestID := OCIRequestIDFromContext(ctx)
					return ociv1.Descriptor{}, OCITimeoutError{Registry: r.registry, Reason: "resolve: timeout " + backoffDuration.String(), RequestID: requestID}
				}
			}
		}

		desc, err = r.repository.Resolve(ctx, reference)
		if err == nil {
			// Success, no need to retry
			break
		}

		lastErr = err
		r.logger.Tracef("[%s] Error resolving OCI reference (attempt %d/%d): %v", requestID, attempt+1, retryAttempts+1, err)
	}

	return desc, lastErr
}

// Fetch retrieves the content of a specific blob from the repository using its descriptor.
// This method downloads the actual bytes for manifests, layers, or other OCI artifacts
// identified by their content digest.
//
// The descriptor must contain a valid digest that exists in the registry. The returned
// ReadCloser provides streaming access to the content, allowing efficient handling
// of large blobs without loading everything into memory.
//
// The caller is responsible for closing the returned ReadCloser to avoid resource leaks.
//
// Parameters:
//   - ctx: Context for the fetch operation
//   - target: OCI descriptor identifying the content to fetch
//
// Returns a ReadCloser for the blob content, or an error if the fetch fails.
func (r *orasRepositoryStore) Fetch(ctx context.Context, target ociv1.Descriptor) (io.ReadCloser, error) {
	requestID := OCIRequestIDFromContext(ctx)
	r.logger.Debugf("[%s] Fetching OCI blob: digest=%s, mediaType=%s, size=%d",
		requestID, target.Digest.String(), target.MediaType, target.Size)

	var reader io.ReadCloser

	// Wrap fetch operation with telemetry
	err := WithOCITelemetry(ctx, r.telemeter, "fetch", r.registry, r.repositoryName, func(ctx context.Context) error {
		var fetchErr error
		reader, fetchErr = r.fetchWithRetry(ctx, target)
		return fetchErr
	})

	if err != nil {
		return nil, OCIBlobDownloadError{registry: r.registry, details: err.Error(), requestID: requestID}
	}

	return reader, nil
}

// fetchWithRetry implements the retry logic for fetch operations
func (r *orasRepositoryStore) fetchWithRetry(ctx context.Context, target ociv1.Descriptor) (io.ReadCloser, error) {
	requestID := OCIRequestIDFromContext(ctx)
	retryAttempts := OCIRetryAttemptsFromContext(ctx)

	var reader io.ReadCloser
	var err error
	var lastErr error

	// Implement retry logic
	for attempt := 0; attempt <= retryAttempts; attempt++ {
		if attempt > 0 {
			r.logger.Tracef("[%s] Retry attempt %d/%d for fetching OCI blob: digest=%s",
				requestID, attempt, retryAttempts, target.Digest.String())

			// Check if context is cancelled before retrying
			select {
			case <-ctx.Done():
				requestID := OCIRequestIDFromContext(ctx)
				return nil, OCITimeoutError{Registry: r.registry, Reason: "fetch: context cancelled", RequestID: requestID}
			default:
				// Add exponential backoff delay between retries with context-aware sleep
				backoffDuration := time.Duration(attempt*attempt) * 100 * time.Millisecond
				if err := contextAwareSleep(ctx, backoffDuration); err != nil {
					requestID := OCIRequestIDFromContext(ctx)
					return nil, OCITimeoutError{Registry: r.registry, Reason: "fetch: timeout " + backoffDuration.String(), RequestID: requestID}
				}
			}
		}

		reader, err = r.repository.Fetch(ctx, target)
		if err == nil {
			// Success, no need to retry
			break
		}

		lastErr = err
		r.logger.Tracef("[%s] Error fetching OCI blob (attempt %d/%d): %v", requestID, attempt+1, retryAttempts+1, err)
	}

	return reader, lastErr
}
