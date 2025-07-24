package tf

import "fmt"

// MalformedRegistryURLErr is returned if the Terraform Registry URL passed to the Getter is malformed.
type MalformedRegistryURLErr struct {
	reason string
}

func (err MalformedRegistryURLErr) Error() string {
	return "tfr getter URL is malformed: " + err.reason
}

// ServiceDiscoveryErr is returned if Terragrunt failed to identify the module API endpoint through the service
// discovery protocol.
type ServiceDiscoveryErr struct {
	reason string
}

func (err ServiceDiscoveryErr) Error() string {
	return "Error identifying module registry API location: " + err.reason
}

// ModuleDownloadErr is returned if Terragrunt failed to download the module.
type ModuleDownloadErr struct {
	sourceURL string
	details   string
}

func (err ModuleDownloadErr) Error() string {
	return fmt.Sprintf("Error downloading module from %s: %s", err.sourceURL, err.details)
}

// RegistryAPIErr is returned if we get an unsuccessful HTTP return code from the registry.
type RegistryAPIErr struct {
	url        string
	statusCode int
}

func (err RegistryAPIErr) Error() string {
	return fmt.Sprintf("Failed to fetch url %s: status code %d", err.url, err.statusCode)
}

// OCIURLParseErr is returned when an OCI URL cannot be parsed or is invalid.
type OCIURLParseErr struct {
	URL       string
	Reason    string
	RequestID string
}

func (err OCIURLParseErr) Error() string {
	msg := fmt.Sprintf("Invalid OCI URL %s: %s", err.URL, err.Reason)
	if err.RequestID != "" {
		msg += fmt.Sprintf(" [request: %s]", err.RequestID)
	}
	return msg
}

// OCIManifestErr is returned when there are issues with OCI manifest processing.
type OCIManifestErr struct {
	Registry   string
	Repository string
	Reference  string
	Issue      string
	RequestID  string
}

func (err OCIManifestErr) Error() string {
	msg := fmt.Sprintf("OCI manifest error for %s/%s", err.Registry, err.Repository)
	if err.Reference != "" {
		msg += fmt.Sprintf("@%s", err.Reference)
	}
	msg += fmt.Sprintf(": %s", err.Issue)
	if err.RequestID != "" {
		msg += fmt.Sprintf(" [request: %s]", err.RequestID)
	}
	return msg
}

// OCILayerSelectionErr is returned when no suitable layer can be found in an OCI manifest.
type OCILayerSelectionErr struct {
	Registry       string
	Repository     string
	Reference      string
	AvailableTypes []string
	SupportedTypes []string
	RequestID      string
}

func (err OCILayerSelectionErr) Error() string {
	msg := fmt.Sprintf("No suitable layer found in OCI manifest for %s/%s", err.Registry, err.Repository)
	if err.Reference != "" {
		msg += fmt.Sprintf("@%s", err.Reference)
	}

	if len(err.AvailableTypes) > 0 {
		msg += fmt.Sprintf(". Available types: %v", err.AvailableTypes)
	}
	if len(err.SupportedTypes) > 0 {
		msg += fmt.Sprintf(". Supported types: %v", err.SupportedTypes)
	}

	if err.RequestID != "" {
		msg += fmt.Sprintf(" [request: %s]", err.RequestID)
	}
	return msg
}

// OCIModuleExtractionErr is returned when module extraction or decompression fails.
type OCIModuleExtractionErr struct {
	Registry    string
	Repository  string
	Reference   string
	MediaType   string
	Destination string
	Issue       string // Specific issue description
	Cause       error  // Optional underlying error
	RequestID   string
}

func (err OCIModuleExtractionErr) Error() string {
	msg := fmt.Sprintf("Failed to extract OCI module %s/%s", err.Registry, err.Repository)
	if err.Reference != "" {
		msg += fmt.Sprintf("@%s", err.Reference)
	}
	if err.MediaType != "" {
		msg += fmt.Sprintf(" (media type: %s)", err.MediaType)
	}
	if err.Destination != "" {
		msg += fmt.Sprintf(" to %s", err.Destination)
	}

	// Add specific issue description
	if err.Issue != "" {
		msg += fmt.Sprintf(": %s", err.Issue)
	}

	// Add underlying cause if present
	if err.Cause != nil {
		if err.Issue != "" {
			msg += fmt.Sprintf(" (%v)", err.Cause)
		} else {
			msg += fmt.Sprintf(": %v", err.Cause)
		}
	}

	if err.RequestID != "" {
		msg += fmt.Sprintf(" [request: %s]", err.RequestID)
	}
	return msg
}

func (err OCIModuleExtractionErr) Unwrap() error {
	return err.Cause
}

// OCIConfigurationErr is returned when OCI getter configuration is invalid or missing.
type OCIConfigurationErr struct {
	Issue     string
	RequestID string
}

func (err OCIConfigurationErr) Error() string {
	msg := fmt.Sprintf("OCI getter configuration error: %s", err.Issue)
	if err.RequestID != "" {
		msg += fmt.Sprintf(" [request: %s]", err.RequestID)
	}
	return msg
}

// OCIUnsupportedOperationErr is returned when an unsupported operation is attempted.
type OCIUnsupportedOperationErr struct {
	Operation string
	Reason    string
}

func (err OCIUnsupportedOperationErr) Error() string {
	msg := fmt.Sprintf("Unsupported OCI operation: %s", err.Operation)
	if err.Reason != "" {
		msg += fmt.Sprintf(" (%s)", err.Reason)
	}
	return msg
}
