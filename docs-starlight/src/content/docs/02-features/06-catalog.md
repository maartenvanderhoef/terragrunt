---
title: Catalog
description: Learn how to search and use your module catalog with Terragrunt.
slug: docs/features/catalog
sidebar:
  order: 6
---

Launch the user interface for searching and managing your module catalog.

```bash
terragrunt catalog <repo-url> [--no-include-root] [--root-file-name] [--enable-shell] [--enable-hooks]
```

![screenshot](../../../assets/img/screenshots/catalog-screenshot.png)

If `<repo-url>` is provided, the repository will be cloned into a temporary directory, otherwise:

1. The repository list are searched in the config file `terragrunt.hcl`. if `terragrunt.hcl` does not exist in the current directory, the config are searched in the parent directories.
1. If the repository list is not found in the configuration file, the modules are looked for in the current directory.

An example of how to define the optional default template and the list of repositories for the `catalog` command in the `terragrunt.hcl` configuration file:

``` hcl
# terragrunt.hcl
catalog {
  default_template = "git@github.com/acme/example.git//path/to/template"  # Optional default template to use for scaffolding
  urls = [
    "relative/path/to/repo", # will be converted to the absolute path, relative to the path of the configuration file.
    "/absolute/path/to/repo",
    "github.com/gruntwork-io/terraform-aws-lambda", # url to remote repository
    "http://github.com/gruntwork-io/terraform-aws-lambda", # same as above
  ]
  
  # Optional scaffold configuration - these can be overridden by CLI flags
  enable_shell = true   # Enable shell functions in scaffold templates (default: false for security)
  enable_hooks = false  # Enable hooks in scaffold templates (default: false for security)
}
```

This will recursively search for OpenTofu/Terraform modules in the root of the repo and the `modules` directory and show a table with all the modules. You can then:

1. Search and filter the table: `/` and start typing.
1. Select a module in the table: use the arrow keys to go up and down and next/previous page.
1. See the docs for a selected module: `ENTER`.
1. Use [`terragrunt scaffold`](/docs/features/scaffold/) to render a `terragrunt.hcl` for using the module: `S`.

## Scaffold Configuration

The catalog configuration supports scaffold-specific settings that control the behavior when scaffolding modules:

- **`enable_shell`** - Enables shell functions in boilerplate templates. When `true`, templates can execute shell commands using `{{shell "command" "args"}}` syntax.
- **`enable_hooks`** - Enables hooks in boilerplate templates. When `true`, templates can define `before` and `after` hooks in their `boilerplate.yml` configuration.

**Security Note**: Both shell functions and hooks can execute arbitrary commands on your system. Only enable these features when using trusted templates from trusted sources.

### Configuration Precedence

Scaffold configuration follows this precedence order (highest to lowest):

1. **CLI flags** - `--enable-shell` and `--enable-hooks` flags override all other settings
2. **Catalog configuration** - Settings in the `catalog` block in your `terragrunt.hcl`
3. **Default values** - Both features are disabled by default for security

## Custom templates for scaffolding

Terragrunt has a basic template built-in for rendering `terragrunt.hcl` files, but you can provide your own templates to customize how code is generated! Scaffolding is done via [boilerplate](https://github.com/gruntwork-io/boilerplate), and Terragrunt allows you to specify custom boilerplate templates via two mechanisms while using catalog:

1. You can define a custom Boilerplate template in a `.boilerplate` sub-directory of any OpenTofu/Terraform module.
2. You can specify a custom Boilerplate template in the catalog configuration using the `default_template` option.

## Scaffolding Flags

The following `catalog` flags control behavior of the underlying `scaffold` command when the `S` key is pressed in a catalog entry:

- `--enable-shell` - Enable shell functions in scaffold templates. Overrides catalog configuration.
- `--enable-hooks` - Enable hooks in scaffold templates. Overrides catalog configuration.
- `--no-include-root` - Do not include the root configuration file in any generated `terragrunt.hcl` during scaffolding.
- `--root-file-name` - The name of the root configuration file to include in any generated `terragrunt.hcl` during scaffolding. This value also controls the name of the root configuration file to search for when trying to determine Catalog urls.
