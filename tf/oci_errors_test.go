package tf

import (
	"testing"
)

// TestOCIErrorTypes verifies that all OCI error types are accessible and can be instantiated
func TestOCIErrorTypes(t *testing.T) {
	// Test OCIConfigurationErr
	configErr := OCIConfigurationErr{
		Issue:     "test issue",
		RequestID: "test-123",
	}
	if configErr.Error() == "" {
		t.Error("OCIConfigurationErr.Error() should not be empty")
	}

	// Test OCIURLParseErr
	urlErr := OCIURLParseErr{
		URL:       "oci://invalid",
		Reason:    "test reason",
		RequestID: "test-123",
	}
	if urlErr.Error() == "" {
		t.Error("OCIURLParseErr.Error() should not be empty")
	}

	// Test OCIManifestErr
	manifestErr := OCIManifestErr{
		Registry:   "registry.com",
		Repository: "repo",
		Issue:      "test issue",
		RequestID:  "test-123",
	}
	if manifestErr.Error() == "" {
		t.Error("OCIManifestErr.Error() should not be empty")
	}

	// Test OCILayerSelectionErr
	layerErr := OCILayerSelectionErr{
		Registry:       "registry.com",
		Repository:     "repo",
		AvailableTypes: []string{"type1"},
		SupportedTypes: []string{"type2"},
		RequestID:      "test-123",
	}
	if layerErr.Error() == "" {
		t.Error("OCILayerSelectionErr.Error() should not be empty")
	}

	// Test OCIModuleExtractionErr
	extractErr := OCIModuleExtractionErr{
		Registry:    "registry.com",
		Repository:  "repo",
		Issue:       "test issue",
		RequestID:   "test-123",
	}
	if extractErr.Error() == "" {
		t.Error("OCIModuleExtractionErr.Error() should not be empty")
	}

	// Test OCIUnsupportedOperationErr
	unsupportedErr := OCIUnsupportedOperationErr{
		Operation: "test",
		Reason:    "test reason",
	}
	if unsupportedErr.Error() == "" {
		t.Error("OCIUnsupportedOperationErr.Error() should not be empty")
	}
}