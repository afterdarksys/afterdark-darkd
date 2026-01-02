variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
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

variable "subnet_id" {
  description = "Subnet ID for VMSS"
  type        = string
  default     = ""
}

variable "vm_size" {
  description = "VM size"
  type        = string
  default     = "Standard_B1s"
}

variable "afterdark_version" {
  description = "AfterDark-DarkD version"
  type        = string
  default     = "0.1.0"
}

variable "enable_vmss" {
  description = "Enable VM Scale Set"
  type        = bool
  default     = false
}

variable "vmss_instances" {
  description = "VMSS instance count"
  type        = number
  default     = 1
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
  default     = ""
}
