// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
// Portions adapted for Terragrunt

package tf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	getter "github.com/hashicorp/go-getter"
	ociDigest "github.com/opencontainers/go-digest"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	orasRegistry "oras.land/oras-go/v2/registry"

	"github.com/gruntwork-io/terragrunt/internal/errors"
	"github.com/gruntwork-io/terragrunt/internal/oci"
	"github.com/gruntwork-io/terragrunt/options"
	"github.com/gruntwork-io/terragrunt/pkg/log"
)

// Constants for OCI module packages
const (
	ociAuthTokenEnvName              = "TG_OCI_REGISTRY_TOKEN"
	ociImageManifestArtifactType     = "application/vnd.opentofu.modulepkg"
	ociImageManifestSizeLimitMiB     = 4
)


// ociBlobMediaTypePreference describes our preference order for the media
// types of OCI blobs representing module packages.
//
// All elements of this slice must correspond to keys in
// [goGetterDecompressorMediaTypes], which in turn define which go-getter
// decompressor to use to extract an archive of each type. Furthermore,
// this must contain an element for every key in that map.
var ociBlobMediaTypePreference = []string{
	"archive/zip",
}

// ociDecompressorMediaTypes maps OCI media types to go-getter decompressor keys
var ociDecompressorMediaTypes = map[string]string{
	"archive/zip": "zip",
}

// OCIGetter is a Getter implementation that downloads Terraform/OpenTofu modules
// from OCI distribution registries. It implements the go-getter.Getter interface
// to seamlessly integrate with Terragrunt's existing module download infrastructure.
//
// This getter supports URLs in the format:
//   oci://REGISTRY_DOMAIN/REPOSITORY_PATH?tag=TAG
//   oci://REGISTRY_DOMAIN/REPOSITORY_PATH?digest=DIGEST
//
// Where:
//   - REGISTRY_DOMAIN is the OCI registry endpoint (e.g., registry.example.com)
//   - REPOSITORY_PATH is the repository path (e.g., namespace/module-name)
//   - TAG specifies a version tag (e.g., v1.0.0, latest)
//   - DIGEST specifies a content digest (e.g., sha256:abc123...)
//
// Authentication is handled through multiple methods in priority order:
//   1. Terraform CLI configuration (~/.terraformrc or equivalent)
//   2. TG_OCI_REGISTRY_TOKEN environment variable
//   3. No authentication (for public registries)
//
// The getter validates OCI manifests, downloads module packages, and extracts
// them to the destination directory following the same patterns as other
// Terragrunt getters.
type OCIGetter struct {
	client            *getter.Client
	TerragruntOptions *options.TerragruntOptions
	Logger            log.Logger
}

// OCIRepositoryStore is an alias for oci.RepositoryStore for backward compatibility
type OCIRepositoryStore = oci.RepositoryStore

var _ getter.Getter = (*OCIGetter)(nil)


// SetClient configures the getter with a go-getter client for progress tracking
// and context management. This method is called automatically by go-getter
// when the getter is registered and used.
//
// The client provides access to the execution context, progress callbacks,
// and configuration options that control the download behavior.
func (og *OCIGetter) SetClient(client *getter.Client) {
	og.client = client
}

// ClientMode returns the download mode for this getter. Since OCI registries
// distribute complete module packages, this always returns getter.ClientModeDir
// to indicate that entire directories should be downloaded rather than individual files.
//
// This is consistent with other module-oriented getters in Terragrunt that
// download complete Terraform configurations.
func (og *OCIGetter) ClientMode(u *url.URL) (getter.ClientMode, error) {
	return getter.ClientModeDir, nil
}

// Context returns the go context to use for all OCI operations including
// registry authentication, manifest resolution, and blob downloads.
//
// The context is derived from the configured client, or defaults to
// context.Background() if no client is available. This context carries
// cancellation signals and deadlines through the entire download process.
func (og *OCIGetter) Context() context.Context {
	if og == nil || og.client == nil {
		return context.Background()
	}
	return og.client.Ctx
}

// Get downloads a Terraform module from an OCI registry to the specified destination.
// This is the main entry point for the getter and orchestrates the entire download process.
//
// The method performs these steps:
//   1. Parse and validate the OCI URL
//   2. Create an authenticated repository store
//   3. Resolve the tag or digest to a manifest descriptor
//   4. Fetch and validate the OCI image manifest
//   5. Select the appropriate layer blob containing the module
//   6. Download the blob to a temporary file
//   7. Extract the module contents to the destination directory
//
// Parameters:
//   - dstPath: Local filesystem path where the module should be extracted
//   - srcURL: OCI URL in the format oci://registry/repository?tag=version
//
// Returns an error if any step fails, including network issues, authentication
// failures, invalid manifests, or filesystem problems.
func (og *OCIGetter) Get(dstPath string, srcURL *url.URL) error {
	ctx := og.Context()
	startTime := time.Now()

	// Add request ID for tracing
	requestID := fmt.Sprintf("oci-get-%d", time.Now().UnixNano())
	ctx = oci.ContextWithOCIRequestID(ctx, requestID)

	og.Logger.Debugf("[%s] Fetching OCI module from %s to %s", requestID, srcURL.String(), dstPath)

	// Validate that we have an OCI store factory (dependency injection)
	if og.TerragruntOptions.OCIRepositoryStoreFactory == nil {
		return OCIConfigurationErr{
			Issue:     "OCI repository store factory not configured",
			RequestID: requestID,
		}
	}

	ref, err := og.resolveRepositoryRef(srcURL, requestID)
	if err != nil {
		return err
	}

	og.Logger.Debugf("[%s] Creating repository store for %s/%s", requestID, ref.Registry, ref.Repository)
	store, err := og.TerragruntOptions.OCIRepositoryStoreFactory.CreateRepositoryStore(ctx, ref.Registry, ref.Repository)
	if err != nil {
		og.Logger.Errorf("[%s] Failed to create repository store: %v", requestID, err)
		return errors.New(fmt.Errorf("configuring OCI client for %s: %w", ref, err))
	}

	og.Logger.Debugf("[%s] Resolving manifest descriptor", requestID)
	manifestDesc, err := og.resolveManifestDescriptor(ctx, ref, srcURL.Query(), store, requestID)
	if err != nil {
		og.Logger.Errorf("[%s] Failed to resolve manifest descriptor: %v", requestID, err)
		return err
	}

	og.Logger.Debugf("[%s] Fetching OCI image manifest", requestID)
	manifest, err := og.fetchOCIImageManifest(ctx, manifestDesc, store, requestID)
	if err != nil {
		og.Logger.Errorf("[%s] Failed to fetch OCI image manifest: %v", requestID, err)
		return err
	}

	og.Logger.Debugf("[%s] Selecting layer blob from %d layers", requestID, len(manifest.Layers))
	pkgDesc, err := og.selectOCILayerBlob(manifest.Layers, requestID)
	if err != nil {
		og.Logger.Errorf("[%s] Failed to select layer blob: %v", requestID, err)
		return err
	}

	decompKey := ociDecompressorMediaTypes[pkgDesc.MediaType]
	decomp := getter.Decompressors[decompKey]

	if decomp == nil {
		return OCIModuleExtractionErr{
			Registry:    ref.Registry,
			Repository:  ref.Repository,
			MediaType:   pkgDesc.MediaType,
			Destination: dstPath,
			Issue:       fmt.Sprintf("no decompressor available for media type %q", pkgDesc.MediaType),
			RequestID:   requestID,
		}
	}

	og.Logger.Debugf("[%s] Downloading blob to temporary file (size: %d bytes)", requestID, pkgDesc.Size)
	tempFile, err := og.fetchOCIBlobToTemporaryFile(ctx, pkgDesc, store, requestID)
	if err != nil {
		og.Logger.Errorf("[%s] Failed to download blob: %v", requestID, err)
		return err
	}
	defer os.Remove(tempFile)

	var umask os.FileMode
	if og.client != nil {
		umask = og.client.Umask
	}

	og.Logger.Debugf("[%s] Decompressing package to %s", requestID, dstPath)
	err = decomp.Decompress(dstPath, tempFile, true, umask)
	if err != nil {
		return OCIModuleExtractionErr{
			Registry:    ref.Registry,
			Repository:  ref.Repository,
			MediaType:   pkgDesc.MediaType,
			Destination: dstPath,
			Issue:       "decompression failed",
			Cause:       err,
			RequestID:   requestID,
		}
	}

	duration := time.Since(startTime)
	og.Logger.Debugf("[%s] Successfully fetched OCI module to %s in %v", requestID, dstPath, duration)
	return nil
}

// GetFile is not implemented for the OCI getter since OCI registries distribute
// complete module packages rather than individual files. Attempting to use this
// method will return an error directing users to use the directory-based Get method.
//
// This follows the same pattern as the Terraform Registry getter, which also
// only supports downloading complete modules.
func (og *OCIGetter) GetFile(dst string, src *url.URL) error {
	return OCIUnsupportedOperationErr{
		Operation: "GetFile",
		Reason:    "OCI getter only supports directory-based downloads, not individual files",
	}
}

// resolveRepositoryRef parses an OCI URL into a registry reference that can be
// used with the ORAS library. It validates the URL format and extracts the
// registry domain and repository path components.
//
// The URL must be absolute with the "oci" scheme. The host becomes the registry
// domain, and the path becomes the repository name after removing the leading slash.
//
// Returns a validated ORAS registry reference or an error if the URL format is invalid.
func (og *OCIGetter) resolveRepositoryRef(srcURL *url.URL, requestID string) (*orasRegistry.Reference, error) {
	og.Logger.Tracef("[%s] Parsing OCI URL: %s", requestID, srcURL.String())
	
	if !srcURL.IsAbs() {
		return nil, OCIURLParseErr{
			URL:       srcURL.String(),
			Reason:    "oci source type requires an absolute URL",
			RequestID: requestID,
		}
	}
	if srcURL.Scheme != "oci" {
		return nil, OCIURLParseErr{
			URL:       srcURL.String(),
			Reason:    "oci source type only supports oci URL scheme",
			RequestID: requestID,
		}
	}

	registryDomain := srcURL.Host
	repositoryName := strings.TrimPrefix(srcURL.Path, "/")

	og.Logger.Tracef("[%s] Parsed registry=%s, repository=%s", requestID, registryDomain, repositoryName)

	ref := &orasRegistry.Reference{
		Registry:   registryDomain,
		Repository: repositoryName,
	}
	if err := ref.Validate(); err != nil {
		return nil, OCIURLParseErr{
			URL:       srcURL.String(),
			Reason:    fmt.Sprintf("invalid OCI reference: %v", err),
			RequestID: requestID,
		}
	}
	return ref, nil
}

// resolveManifestDescriptor resolves a tag name or digest from the URL query parameters
// to an OCI manifest descriptor. This method handles both tag-based and digest-based
// references, with "latest" as the default tag if neither is specified.
//
// The method validates query parameters to ensure only one reference type is provided
// and that the reference format is valid according to OCI specifications.
//
// Parameters:
//   - ctx: Context for the resolution operation
//   - ref: Registry reference containing domain and repository
//   - query: URL query parameters containing tag or digest
//   - store: Repository store for performing the resolution
//
// Returns the resolved manifest descriptor with media type validation, or an error
// if the reference cannot be resolved or is not a valid OCI image manifest.
func (og *OCIGetter) resolveManifestDescriptor(ctx context.Context, ref *orasRegistry.Reference, query url.Values, store OCIRepositoryStore, requestID string) (ociv1.Descriptor, error) {
	og.Logger.Tracef("[%s] Resolving OCI reference for registry=%s, repository=%s", requestID, ref.Registry, ref.Repository)

	var unsupportedArgs []string
	var wantTag string
	var wantDigest ociDigest.Digest

	for name, values := range query {
		if len(values) > 1 {
			return ociv1.Descriptor{}, OCIURLParseErr{
				URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
				Reason:    fmt.Sprintf("too many %q arguments", name),
				RequestID: requestID,
			}
		}
		value := values[0]
		switch name {
		case "tag":
			if value == "" {
				return ociv1.Descriptor{}, OCIURLParseErr{
					URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
					Reason:    "tag argument must not be empty",
					RequestID: requestID,
				}
			}
			tagRef := *ref
			tagRef.Reference = value
			if err := tagRef.ValidateReferenceAsTag(); err != nil {
				return ociv1.Descriptor{}, errors.New(err)
			}
			wantTag = value
		case "digest":
			if value == "" {
				return ociv1.Descriptor{}, OCIURLParseErr{
					URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
					Reason:    "digest argument must not be empty",
					RequestID: requestID,
				}
			}
			d, err := ociDigest.Parse(value)
			if err != nil {
				return ociv1.Descriptor{}, OCIURLParseErr{
					URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
					Reason:    fmt.Sprintf("invalid digest: %s", err),
					RequestID: requestID,
				}
			}
			wantDigest = d
		default:
			unsupportedArgs = append(unsupportedArgs, name)
		}
	}

	if len(unsupportedArgs) == 1 {
		return ociv1.Descriptor{}, OCIURLParseErr{
			URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
			Reason:    fmt.Sprintf("unsupported argument %q", unsupportedArgs[0]),
			RequestID: requestID,
		}
	} else if len(unsupportedArgs) >= 2 {
		return ociv1.Descriptor{}, OCIURLParseErr{
			URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
			Reason:    fmt.Sprintf("unsupported arguments: %s", strings.Join(unsupportedArgs, ", ")),
			RequestID: requestID,
		}
	}

	if wantTag != "" && wantDigest != "" {
		return ociv1.Descriptor{}, OCIURLParseErr{
			URL:       fmt.Sprintf("%s/%s", ref.Registry, ref.Repository),
			Reason:    "cannot set both \"tag\" and \"digest\" arguments",
			RequestID: requestID,
		}
	}

	if wantTag == "" && wantDigest == "" {
		og.Logger.Warnf("[%s] No tag or digest specified for OCI module %s. Defaulting to 'latest', which is not recommended for production.", requestID, ref.Repository)
		wantTag = "latest"
	}

	var desc ociv1.Descriptor
	var err error

	if wantTag != "" {
		og.Logger.Debugf("[%s] Resolving OCI tag: %s", requestID, wantTag)
		desc, err = store.Resolve(ctx, wantTag)
		if err != nil {
			return ociv1.Descriptor{}, errors.New(fmt.Errorf("[%s] resolving tag %q: %w", requestID, wantTag, err))
		}
	} else {
		og.Logger.Debugf("[%s] Resolving OCI digest: %s", requestID, wantDigest.String())
		desc, err = store.Resolve(ctx, wantDigest.String())
		if err != nil {
			return ociv1.Descriptor{}, errors.New(fmt.Errorf("[%s] resolving digest %q: %w", requestID, wantDigest, err))
		}
	}

	if desc.MediaType != ociv1.MediaTypeImageManifest {
		return ociv1.Descriptor{}, OCIManifestErr{
			Registry:   ref.Registry,
			Repository: ref.Repository,
			Reference:  wantTag + wantDigest.String(),
			Issue:      "selected object is not an OCI image manifest",
			RequestID:  requestID,
		}
	}

	desc.ArtifactType = ociImageManifestArtifactType
	return desc, nil
}

// fetchOCIImageManifest downloads and validates an OCI image manifest from the registry.
// This method ensures the manifest is properly formatted JSON and contains the expected
// artifact type for Terraform/OpenTofu modules.
//
// The method performs size validation, content integrity checking, and format validation
// to ensure the manifest can be safely processed. It also handles special cases like
// index manifests and provides helpful error messages for common issues.
//
// Returns the parsed and validated manifest, or an error if the manifest is invalid,
// too large, or cannot be downloaded.
func (og *OCIGetter) fetchOCIImageManifest(ctx context.Context, desc ociv1.Descriptor, store OCIRepositoryStore, requestID string) (*ociv1.Manifest, error) {
	og.Logger.Tracef("[%s] Fetching OCI manifest: digest=%s, size=%d", requestID, desc.Digest.String(), desc.Size)

	manifestSrc, err := og.fetchOCIManifestBlob(ctx, desc, store, requestID)
	if err != nil {
		return nil, err
	}

	var manifest ociv1.Manifest
	err = json.Unmarshal(manifestSrc, &manifest)
	if err != nil {
		// Check if we got an index manifest instead
		var indexManifest ociv1.Index
		if err := json.Unmarshal(manifestSrc, &indexManifest); err == nil && indexManifest.MediaType == ociv1.MediaTypeImageIndex {
			return nil, OCIManifestErr{
				Registry:   "unknown", // We don't have ref context here
				Repository: "unknown",
				Issue:      "found an OCI image index but an image manifest is required. This can happen with multi-platform modules. Please specify a more precise tag or digest that points directly to a manifest for your platform.",
				RequestID:  requestID,
			}
		}
		return nil, OCIManifestErr{
			Registry:   "unknown",
			Repository: "unknown", 
			Issue:      fmt.Sprintf("invalid manifest content: %v", err),
			RequestID:  requestID,
		}
	}

	if manifest.MediaType != desc.MediaType {
		return nil, OCIManifestErr{
			Registry:   "unknown",
			Repository: "unknown",
			Issue:      fmt.Sprintf("unexpected manifest media type %q", manifest.MediaType),
			RequestID:  requestID,
		}
	}
	if manifest.ArtifactType != desc.ArtifactType {
		return nil, OCIManifestErr{
			Registry:   "unknown",
			Repository: "unknown",
			Issue:      fmt.Sprintf("unexpected artifact type %q", manifest.ArtifactType),
			RequestID:  requestID,
		}
	}

	return &manifest, nil
}

// fetchOCIManifestBlob downloads the raw manifest content and verifies its integrity
// against the provided descriptor. This method handles size limits, content validation,
// and ensures the downloaded content matches the expected digest.
//
// The manifest size is limited to prevent resource exhaustion attacks, and the content
// is verified using cryptographic hashes to ensure it hasn't been tampered with during transit.
//
// Returns the raw manifest bytes or an error if download fails or content is invalid.
func (og *OCIGetter) fetchOCIManifestBlob(ctx context.Context, desc ociv1.Descriptor, store OCIRepositoryStore, requestID string) ([]byte, error) {
	if (desc.Size / 1024 / 1024) > ociImageManifestSizeLimitMiB {
		return nil, errors.New(fmt.Errorf("[%s] manifest size exceeds limit of %d MiB", requestID, ociImageManifestSizeLimitMiB))
	}

	readCloser, err := store.Fetch(ctx, desc)
	if err != nil {
		return nil, errors.New(err)
	}
	defer readCloser.Close()

	manifestReader := io.LimitReader(readCloser, desc.Size)
	manifestSrc, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, errors.New(fmt.Errorf("[%s] reading manifest content: %w", requestID, err))
	}

	gotDigest := desc.Digest.Algorithm().FromBytes(manifestSrc)
	if gotDigest != desc.Digest {
		return nil, errors.New(fmt.Errorf("[%s] manifest content does not match digest %s", requestID, desc.Digest))
	}

	return manifestSrc, nil
}

// selectOCILayerBlob chooses the most appropriate layer from an OCI manifest
// for use as a Terraform module package. This method implements a preference
// system that prioritizes certain archive formats over others.
//
// The selection process:
//   1. Filters layers to only those with supported media types
//   2. Validates that there's only one layer per supported media type
//   3. Selects the highest-priority supported layer based on preferences
//
// Returns the selected layer descriptor or an error if no suitable layer is found.
func (og *OCIGetter) selectOCILayerBlob(descs []ociv1.Descriptor, requestID string) (ociv1.Descriptor, error) {
	foundBlobs := make(map[string]ociv1.Descriptor, len(ociDecompressorMediaTypes))
	foundWrongMediaTypeBlobs := 0
	var availableTypes []string

	for _, desc := range descs {
		if _, ok := ociDecompressorMediaTypes[desc.MediaType]; ok {
			if _, exists := foundBlobs[desc.MediaType]; exists {
				return ociv1.Descriptor{}, errors.New(fmt.Errorf("[%s] multiple layers with media type %q", requestID, desc.MediaType))
			}
			foundBlobs[desc.MediaType] = desc
			availableTypes = append(availableTypes, desc.MediaType)
		} else {
			foundWrongMediaTypeBlobs++
		}
	}

	if len(foundBlobs) == 0 {
		var supportedTypes []string
		for mediaType := range ociDecompressorMediaTypes {
			supportedTypes = append(supportedTypes, mediaType)
		}

		return ociv1.Descriptor{}, OCILayerSelectionErr{
			Registry:       "unknown",
			Repository:     "unknown",
			AvailableTypes: availableTypes,
			SupportedTypes: supportedTypes,
			RequestID:      requestID,
		}
	}

	for _, maybeType := range ociBlobMediaTypePreference {
		ret, ok := foundBlobs[maybeType]
		if ok {
			og.Logger.Debugf("[%s] Selected layer with media type %s", requestID, maybeType)
			return ret, nil
		}
	}

	return ociv1.Descriptor{}, errors.New(fmt.Errorf("[%s] no suitable layer found despite having supported types", requestID))
}

// fetchOCIBlobToTemporaryFile downloads an OCI blob to a temporary file for extraction.
// This method handles the download of module package archives from the registry,
// providing progress feedback and proper cleanup on errors.
//
// The method creates a temporary file, downloads the blob content, and returns the
// file path. The caller is responsible for deleting the temporary file when done.
//
// Returns the temporary file path or an error if the download fails.
func (og *OCIGetter) fetchOCIBlobToTemporaryFile(ctx context.Context, desc ociv1.Descriptor, store OCIRepositoryStore, requestID string) (tempFile string, err error) {
	f, err := os.CreateTemp("", "terragrunt-oci-module")
	if err != nil {
		return "", errors.New(fmt.Errorf("[%s] failed to open temporary file: %w", requestID, err))
	}
	tempFile = f.Name()
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()

	og.Logger.Tracef("[%s] Fetching blob content from registry", requestID)
	readCloser, err := store.Fetch(ctx, desc)
	if err != nil {
		return "", errors.New(fmt.Errorf("[%s] failed to fetch blob: %w", requestID, err))
	}
	defer readCloser.Close()

	_, err = getter.Copy(ctx, f, readCloser)
	f.Close()
	if err != nil {
		return "", errors.New(fmt.Errorf("[%s] failed to copy blob to temporary file: %w", requestID, err))
	}

	return tempFile, nil
}
