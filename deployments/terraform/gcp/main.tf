terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  common_labels = {
    project     = "afterdark-darkd"
    environment = var.environment
    managed-by  = "terraform"
  }
}

# Secret Manager for API key
resource "google_secret_manager_secret" "darkapi_key" {
  secret_id = "afterdark-darkapi-key-${var.environment}"

  labels = local.common_labels

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "darkapi_key" {
  secret      = google_secret_manager_secret.darkapi_key.id
  secret_data = var.darkapi_key
}

# Service Account
resource "google_service_account" "darkd" {
  account_id   = "afterdark-darkd-${var.environment}"
  display_name = "AfterDark-DarkD Service Account"
}

# IAM binding for Secret Manager access
resource "google_secret_manager_secret_iam_member" "darkd" {
  secret_id = google_secret_manager_secret.darkapi_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.darkd.email}"
}

# Firewall rule
resource "google_compute_firewall" "darkd_egress" {
  name    = "afterdark-darkd-egress-${var.environment}"
  network = var.network

  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  target_service_accounts = [google_service_account.darkd.email]
}

# Instance Template
resource "google_compute_instance_template" "darkd" {
  name_prefix  = "afterdark-darkd-${var.environment}-"
  machine_type = var.machine_type
  region       = var.region

  disk {
    source_image = "ubuntu-os-cloud/ubuntu-2204-lts"
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork
  }

  service_account {
    email  = google_service_account.darkd.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -e

    apt-get update && apt-get install -y curl jq

    mkdir -p /etc/afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark

    ARCH=$(dpkg --print-architecture)
    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/afterdark-darkd-linux-$ARCH" -o /usr/local/bin/afterdark-darkd
    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/afterdark-darkdadm-linux-$ARCH" -o /usr/local/bin/afterdark-darkdadm
    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/darkapi-linux-$ARCH" -o /usr/local/bin/darkapi
    chmod +x /usr/local/bin/afterdark-darkd /usr/local/bin/afterdark-darkdadm /usr/local/bin/darkapi

    # Get API key from Secret Manager
    DARKAPI_KEY=$(gcloud secrets versions access latest --secret="${google_secret_manager_secret.darkapi_key.secret_id}")

    cat > /etc/afterdark/darkd.yaml <<YAML
    daemon:
      log_level: info
      data_dir: /var/lib/afterdark
    api:
      darkapi:
        url: https://api.darkapi.io
        api_key: $DARKAPI_KEY
    services:
      patch_monitor:
        enabled: true
      threat_intel:
        enabled: true
      network_monitor:
        enabled: true
    YAML

    cat > /etc/systemd/system/afterdark-darkd.service <<SERVICE
    [Unit]
    Description=After Dark Systems Endpoint Security Daemon
    After=network-online.target

    [Service]
    Type=simple
    ExecStart=/usr/local/bin/afterdark-darkd --config /etc/afterdark/darkd.yaml
    Restart=always

    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable afterdark-darkd
    systemctl start afterdark-darkd
  EOF

  labels = local.common_labels

  lifecycle {
    create_before_destroy = true
  }
}

# Managed Instance Group
resource "google_compute_instance_group_manager" "darkd" {
  count = var.enable_mig ? 1 : 0

  name               = "afterdark-darkd-${var.environment}"
  base_instance_name = "afterdark-darkd"
  zone               = var.zone

  version {
    instance_template = google_compute_instance_template.darkd.id
  }

  target_size = var.mig_size
}

output "service_account_email" {
  value = google_service_account.darkd.email
}

output "instance_template_id" {
  value = google_compute_instance_template.darkd.id
}

output "secret_id" {
  value = google_secret_manager_secret.darkapi_key.secret_id
}
