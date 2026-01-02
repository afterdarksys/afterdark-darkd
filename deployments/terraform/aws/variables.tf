variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "darkapi_key" {
  description = "DarkAPI.io API key"
  type        = string
  sensitive   = true
}

variable "vpc_id" {
  description = "VPC ID for security group"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for ASG"
  type        = list(string)
  default     = []
}

variable "ami_id" {
  description = "AMI ID for instances (Amazon Linux 2 or Ubuntu)"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "afterdark_version" {
  description = "AfterDark-DarkD version to deploy"
  type        = string
  default     = "0.1.0"
}

variable "enable_asg" {
  description = "Enable Auto Scaling Group"
  type        = bool
  default     = false
}

variable "asg_min" {
  description = "ASG minimum size"
  type        = number
  default     = 1
}

variable "asg_max" {
  description = "ASG maximum size"
  type        = number
  default     = 10
}

variable "asg_desired" {
  description = "ASG desired capacity"
  type        = number
  default     = 1
}
