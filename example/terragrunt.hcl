oci {
  # Enable automatic credential discovery from environment and Docker config
  discover_ambient_credentials = true

  # Specify explicit Docker config files to check
  #docker_config_files = ["~/.docker/config.json", "/path/to/other/config.json"]
  docker_config_files = []

  # Configure credential helpers to try
  credential_helpers = ["osxkeychain", "desktop"]

  # Set a default credential helper for registries without specific configuration
  default_credential_helper = "osxkeychain"

  # Configure connection settings
  timeout        = "1m"
  retry_attempts = 5

  # Registry-specific credentials
  credentials {
    # This is the registry hostname or pattern
    registry = "ghcr.io"

    # Use a credential helper for this registry
    credential_helper = "osxkeychain"
  }

  credentials {
    # This is the registry hostname or pattern
    registry = "registry.example.com"

    # Use a credential helper for this registry instead of basic auth
    credential_helper = "osxkeychain"
  }

  # credentials {
  #   registry = "private.registry.io"
  #   
  #   # Use a bearer token for authentication
  #   token = "my-auth-token"
  # }
  # 
  # credentials {
  #   registry = "gcr.io"
  #   
  #   # Use a credential helper for this registry
  #   credential_helper = "gcloud"
  # }
  # 
  # credentials {
  #   registry = "ecr.aws"
  #   
  #   # Run a command to get the authentication token
  #   token_command = ["aws", "ecr", "get-login-password", "--region", "us-west-2"]
  # }
  # 
  # credentials {
  #   registry = "public.registry.io"
  #   
  #   # Explicitly disable authentication for this registry
  #   disable_auth = true
  # }
}

terraform {
  source = "oci://ghcr.io/maartenvanderhoef/my-tf-module?tag=4"
  #source = "oci://ghcr.io/maartenvanderhoef/my-tf-module"
  #source = "tfr://registry.terraform.io/terraform-aws-modules/vpc/aws?version=3.3.0"
}
