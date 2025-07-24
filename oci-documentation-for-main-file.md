---
layout: collection-browser-doc
title: Configuration Blocks and Attributes
category: reference
categories_url: reference
excerpt: >-
  Learn about all the blocks and attributes supported in the terragrunt configuration file.
tags: ["config"]
order: 404
nav_title: Documentation
nav_title_link: /docs/
slug: config-blocks-and-attributes
---

The Terragrunt configuration file uses the same HCL syntax as OpenTofu/Terraform itself in `terragrunt.hcl`.
Terragrunt also supports [JSON-serialized HCL](https://github.com/hashicorp/hcl/blob/hcl2/json/spec.md) in a `terragrunt.hcl.json` file:
where `terragrunt.hcl` is mentioned you can always use `terragrunt.hcl.json` instead.

The following is a reference of all the supported blocks and attributes in the configuration file:

- [Blocks](#blocks)
  - [terraform](#terraform)
    - [A note about using modules from the registry](#a-note-about-using-modules-from-the-registry)
  - [remote\_state](#remote_state)
    - [backend](#backend)
    - [encryption](#encryption)
  - [include](#include)
    - [Single include](#single-include)
    - [Multiple includes](#multiple-includes)
    - [Limitations on accessing exposed config](#limitations-on-accessing-exposed-config)
  - [locals](#locals)
    - [Complex locals](#complex-locals)
    - [Computed locals](#computed-locals)
  - [dependency](#dependency)
  - [dependencies](#dependencies)
  - [generate](#generate)
  - [engine](#engine)
  - [feature](#feature)
  - [exclude](#exclude)
  - [errors](#errors)
    - [Retry Configuration](#retry-configuration)
    - [Ignore Configuration](#ignore-configuration)
    - [Combined Example](#combined-example)
    - [Errors during source fetching](#errors-during-source-fetching)
  - [oci](#oci)
  - [unit](#unit)
  - [stack](#stack)
- [Attributes](#attributes)
  - [inputs](#inputs)
    - [Variable Precedence](#variable-precedence)
  - [download\_dir](#download_dir)