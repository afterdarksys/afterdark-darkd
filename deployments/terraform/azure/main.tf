terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

locals {
  common_tags = {
    Project     = "afterdark-darkd"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "After Dark Systems, LLC"
  }
}

# Resource Group
resource "azurerm_resource_group" "darkd" {
  name     = "rg-afterdark-darkd-${var.environment}"
  location = var.location

  tags = local.common_tags
}

# Key Vault for secrets
resource "azurerm_key_vault" "darkd" {
  name                = "kv-darkd-${var.environment}"
  location            = azurerm_resource_group.darkd.location
  resource_group_name = azurerm_resource_group.darkd.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  tags = local.common_tags
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault_secret" "darkapi_key" {
  name         = "darkapi-key"
  value        = var.darkapi_key
  key_vault_id = azurerm_key_vault.darkd.id
}

# Network Security Group
resource "azurerm_network_security_group" "darkd" {
  name                = "nsg-afterdark-darkd-${var.environment}"
  location            = azurerm_resource_group.darkd.location
  resource_group_name = azurerm_resource_group.darkd.name

  security_rule {
    name                       = "AllowHTTPSOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowDNSOutbound"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# User Assigned Identity
resource "azurerm_user_assigned_identity" "darkd" {
  name                = "id-afterdark-darkd-${var.environment}"
  location            = azurerm_resource_group.darkd.location
  resource_group_name = azurerm_resource_group.darkd.name

  tags = local.common_tags
}

# Key Vault access policy for identity
resource "azurerm_key_vault_access_policy" "darkd" {
  key_vault_id = azurerm_key_vault.darkd.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.darkd.principal_id

  secret_permissions = ["Get", "List"]
}

# VM Scale Set
resource "azurerm_linux_virtual_machine_scale_set" "darkd" {
  count = var.enable_vmss ? 1 : 0

  name                = "vmss-afterdark-darkd-${var.environment}"
  location            = azurerm_resource_group.darkd.location
  resource_group_name = azurerm_resource_group.darkd.name
  sku                 = var.vm_size
  instances           = var.vmss_instances

  admin_username = "azureuser"

  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  network_interface {
    name    = "nic-darkd"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = var.subnet_id
    }

    network_security_group_id = azurerm_network_security_group.darkd.id
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.darkd.id]
  }

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    apt-get update && apt-get install -y curl jq

    mkdir -p /etc/afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark

    ARCH=$(dpkg --print-architecture)
    curl -fsSL "https://releases.afterdarksys.com/darkd/${var.afterdark_version}/afterdark-darkd-linux-$ARCH" -o /usr/local/bin/afterdark-darkd
    chmod +x /usr/local/bin/afterdark-darkd

    # Get API key from Key Vault using managed identity
    DARKAPI_KEY=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" -H Metadata:true | jq -r .access_token | xargs -I {} curl -s "${azurerm_key_vault.darkd.vault_uri}secrets/darkapi-key?api-version=7.0" -H "Authorization: Bearer {}" | jq -r .value)

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
    YAML

    systemctl enable afterdark-darkd
    systemctl start afterdark-darkd
  EOF
  )

  tags = local.common_tags
}

output "resource_group_name" {
  value = azurerm_resource_group.darkd.name
}

output "key_vault_name" {
  value = azurerm_key_vault.darkd.name
}

output "identity_id" {
  value = azurerm_user_assigned_identity.darkd.id
}
