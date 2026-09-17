terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  common_tags = {
    Project     = "afterdark-darkd"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "After Dark Systems, LLC"
  }
}

# SSM Parameter for API Key (secure storage)
resource "aws_ssm_parameter" "darkapi_key" {
  name        = "/afterdark/${var.environment}/darkapi-key"
  description = "DarkAPI.io API key for AfterDark-DarkD"
  type        = "SecureString"
  value       = var.darkapi_key

  tags = local.common_tags
}

# IAM Role for EC2 instances
resource "aws_iam_role" "darkd_instance" {
  name = "afterdark-darkd-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "darkd_ssm" {
  name = "ssm-parameter-access"
  role = aws_iam_role.darkd_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = aws_ssm_parameter.darkapi_key.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "darkd" {
  name = "afterdark-darkd-${var.environment}"
  role = aws_iam_role.darkd_instance.name
}

# Security Group
resource "aws_security_group" "darkd" {
  name        = "afterdark-darkd-${var.environment}"
  description = "Security group for AfterDark-DarkD endpoints"
  vpc_id      = var.vpc_id

  # Outbound HTTPS for API calls
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for API calls"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "OS package repositories during bootstrap"
  }

  # Outbound DNS
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS"
  }

  tags = merge(local.common_tags, {
    Name = "afterdark-darkd-${var.environment}"
  })
}

# User data script for Linux instances
locals {
  linux_userdata = templatefile("${path.module}/../shared/bootstrap.sh.tftpl", {
    settings = base64encode(jsonencode({ provider = "aws", region = var.aws_region, secret = aws_ssm_parameter.darkapi_key.name, binaries = var.daemon_binaries }))
  })
}

# Launch Template
resource "aws_launch_template" "darkd" {
  name          = "afterdark-darkd-${var.environment}"
  image_id      = var.ami_id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.darkd.arn
  }

  vpc_security_group_ids = [aws_security_group.darkd.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = base64encode(local.linux_userdata)

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "afterdark-darkd-${var.environment}"
    })
  }

  tags = local.common_tags
}

# Auto Scaling Group (optional)
resource "aws_autoscaling_group" "darkd" {
  count = var.enable_asg ? 1 : 0

  name                = "afterdark-darkd-${var.environment}"
  desired_capacity    = var.asg_desired
  max_size            = var.asg_max
  min_size            = var.asg_min
  vpc_zone_identifier = var.subnet_ids

  launch_template {
    id      = aws_launch_template.darkd.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "afterdark-darkd-${var.environment}"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

output "security_group_id" {
  value       = aws_security_group.darkd.id
  description = "Security group ID for AfterDark-DarkD instances"
}

output "instance_profile_arn" {
  value       = aws_iam_instance_profile.darkd.arn
  description = "Instance profile ARN for AfterDark-DarkD"
}

output "launch_template_id" {
  value       = aws_launch_template.darkd.id
  description = "Launch template ID for AfterDark-DarkD"
}
