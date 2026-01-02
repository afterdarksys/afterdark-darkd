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
  linux_userdata = <<-EOF
    #!/bin/bash
    set -e

    # Install dependencies
    yum install -y curl jq || apt-get update && apt-get install -y curl jq

    # Create directories
    mkdir -p /etc/afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark

    # Download binaries
    ARCH=$(uname -m)
    case $ARCH in
      x86_64) ARCH="amd64" ;;
      aarch64) ARCH="arm64" ;;
    esac

    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/afterdark-darkd-linux-$ARCH" -o /usr/local/bin/afterdark-darkd
    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/afterdark-darkdadm-linux-$ARCH" -o /usr/local/bin/afterdark-darkdadm
    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/darkapi-linux-$ARCH" -o /usr/local/bin/darkapi

    chmod +x /usr/local/bin/afterdark-darkd /usr/local/bin/afterdark-darkdadm /usr/local/bin/darkapi

    # Get API key from SSM
    DARKAPI_KEY=$(aws ssm get-parameter --name "/afterdark/${var.environment}/darkapi-key" --with-decryption --query "Parameter.Value" --output text --region ${var.aws_region})

    # Create configuration
    cat > /etc/afterdark/darkd.yaml <<YAML
    daemon:
      log_level: info
      data_dir: /var/lib/afterdark
      pid_file: /var/run/afterdark/darkd.pid

    api:
      darkapi:
        url: https://api.darkapi.io
        api_key: $DARKAPI_KEY
        timeout: 30s

    services:
      patch_monitor:
        enabled: true
        scan_interval: 1h
      threat_intel:
        enabled: true
        sync_interval: 6h
      network_monitor:
        enabled: true
        dns_servers:
          - cache01.dnsscience.io
          - cache02.dnsscience.io
    YAML

    # Create systemd service
    cat > /etc/systemd/system/afterdark-darkd.service <<SERVICE
    [Unit]
    Description=After Dark Systems Endpoint Security Daemon
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart=/usr/local/bin/afterdark-darkd --config /etc/afterdark/darkd.yaml
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable afterdark-darkd
    systemctl start afterdark-darkd
  EOF
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
