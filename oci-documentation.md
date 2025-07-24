### oci

The `oci` block is used to configure authentication and connection settings for OCI (Open Container Initiative) registries when downloading modules from OCI distribution endpoints.

The `oci` block supports the following arguments:

- `discover_ambient_credentials` (attribute): When `true` (default), enables automatic discovery of credentials from environment variables, Docker config files, and credential helpers.

- `docker_config_files` (attribute): A list of paths to Docker-style config files to search for credentials. If not specified, uses default discovery locations. If set to an empty list, disables Docker config file discovery entirely.

- `credential_helpers` (attribute): A list of Docker credential helpers to try in order of preference. Common values include "desktop", "osxkeychain", "wincred", "pass", and "secretservice".

- `default_credential_helper` (attribute): Specifies a default credential helper to use for any registry that doesn't have specific credentials configured.

- `cache_credentials` (attribute): When `true` (default), enables caching of authentication tokens to avoid repeated authentication requests during a single Terragrunt run.

- `timeout` (attribute): Specifies the maximum time to wait for registry operations. Supports duration strings like "30s", "1m", "5m30s". Defaults to "30s".

- `retry_attempts` (attribute): Specifies the number of retry attempts for failed registry operations. Defaults to 3.

- `credentials` (block): Nested blocks used to specify registry-specific authentication configurations. Each block is labeled with the registry hostname or pattern (e.g., "registry.io", "*.company.com") and supports the following arguments:

  - `username` (attribute): Username for basic authentication.
  - `password` (attribute): Password for basic authentication (must be paired with username).
  - `token` (attribute): Token for bearer token authentication.
  - `credential_helper` (attribute): Specifies a Docker credential helper to use for this registry.
  - `token_command` (attribute): A list containing a command and arguments to run to get an authentication token. The command output (stdout) will be used as the bearer token.
  - `disable_auth` (attribute): When `true`, explicitly disables authentication for this registry. Useful for public registries or to override global settings.

Authentication methods are tried in the following priority order:
1. Username/Password (basic auth)
2. Token (bearer token auth)
3. CredentialHelper (Docker credential helper)
4. TokenCommand (execute command for token)
5. DisableAuth (explicit opt-out)

Example:

```hcl
oci {
  # Enable automatic credential discovery from environment and Docker config
  discover_ambient_credentials = true
  
  # Specify explicit Docker config files to check
  docker_config_files = ["~/.docker/config.json", "/path/to/other/config.json"]
  
  # Configure credential helpers to try
  credential_helpers = ["osxkeychain", "desktop"]
  
  # Set a default credential helper for registries without specific configuration
  default_credential_helper = "osxkeychain"
  
  # Configure connection settings
  timeout = "1m"
  retry_attempts = 5
  
  # Registry-specific credentials
  credentials {
    # This is the registry hostname or pattern
    registry = "registry.example.com"
    
    # Basic auth credentials
    username = "username"
    password = "password"
  }
  
  credentials {
    registry = "private.registry.io"
    
    # Use a bearer token for authentication
    token = "my-auth-token"
  }
  
  credentials {
    registry = "gcr.io"
    
    # Use a credential helper for this registry
    credential_helper = "gcloud"
  }
  
  credentials {
    registry = "ecr.aws"
    
    # Run a command to get the authentication token
    token_command = ["aws", "ecr", "get-login-password", "--region", "us-west-2"]
  }
  
  credentials {
    registry = "public.registry.io"
    
    # Explicitly disable authentication for this registry
    disable_auth = true
  }
}
```

When using OCI registries with Terragrunt, you can reference OCI modules in your `terraform.source` attribute using the standard OCI URL format:

```hcl
terraform {
  source = "oci://registry.example.com/namespace/module:1.0.0"
}
```

The OCI configuration allows you to authenticate with private OCI registries and customize connection behavior when downloading modules from OCI distribution endpo