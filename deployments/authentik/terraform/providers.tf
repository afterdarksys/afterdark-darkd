terraform {
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2024.8.0"
    }
  }
}

provider "authentik" {
  url   = "http://localhost:9000"
  token = var.authentik_token
}
