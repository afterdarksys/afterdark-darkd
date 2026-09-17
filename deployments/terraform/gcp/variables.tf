variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "darkapi_key" {
  description = "DarkAPI.io API key"
  type        = string
  sensitive   = true
}

variable "network" {
  description = "VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Subnetwork name"
  type        = string
  default     = "default"
}

variable "machine_type" {
  description = "GCE machine type"
  type        = string
  default     = "e2-micro"
}

variable "afterdark_version" {
  description = "AfterDark-DarkD version"
  type        = string
  default     = "0.1.0"
}

variable "enable_mig" {
  description = "Enable Managed Instance Group"
  type        = bool
  default     = false
}

variable "mig_size" {
  description = "MIG target size"
  type        = number
  default     = 1
}

variable "daemon_binaries" {
  description = "Verified standalone Linux daemon artifact URL and SHA-256, keyed by amd64 or arm64. Required: no unverified downloads."
  type        = map(object({ url = string, sha256 = string }))
  validation {
    condition     = length(var.daemon_binaries) > 0 && alltrue([for arch, binary in var.daemon_binaries : contains(["amd64", "arm64"], arch) && can(regex("^https://", binary.url)) && can(regex("^[a-fA-F0-9]{64}$", binary.sha256))])
    error_message = "Supply HTTPS daemon artifacts with exact SHA-256 checksums for supported architectures."
  }
}
