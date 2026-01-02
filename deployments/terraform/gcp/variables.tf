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
