# IDs for existing resources
locals {
  authorization_flow_id = "21bbd613-ebe5-46e5-aff1-8d2ef1909a5d"
  signing_key_id        = "ff0e3d04-0e87-4a06-9029-45f5641bf715"
}

# AfterDark Security Suite
resource "authentik_provider_oauth2" "security_suite" {
  name               = "AfterDark Security Suite Provider"
  client_id          = "afterdark-security-suite"
  client_type        = "confidential"
  authorization_flow = local.authorization_flow_id

  redirect_uris = [
    "http://localhost:9090/oauth/callback",
    "https://security.afterdark.local/oauth/callback"
  ]

  signing_key = local.signing_key_id

  property_mappings = []

  sub_mode                     = "hashed_user_id"
  include_claims_in_id_token   = true
  issuer_mode                  = "per_provider"
}

resource "authentik_application" "security_suite" {
  name              = "AfterDark Security Suite"
  slug              = "afterdark-security-suite"
  protocol_provider = authentik_provider_oauth2.security_suite.id
  meta_launch_url   = "http://localhost:9090/"
}

# AfterDark HTTP Proxy
resource "authentik_provider_oauth2" "http_proxy" {
  name               = "AfterDark HTTP Proxy Provider"
  client_id          = "ads-httpproxy-client"
  client_type        = "confidential"
  authorization_flow = local.authorization_flow_id

  redirect_uris = [
    "http://localhost:8080/oauth/callback",
    "https://proxy.afterdark.local/oauth/callback"
  ]

  signing_key = local.signing_key_id

  property_mappings = []

  sub_mode                     = "hashed_user_id"
  include_claims_in_id_token   = true
  issuer_mode                  = "per_provider"
}

resource "authentik_application" "http_proxy" {
  name              = "AfterDark HTTP Proxy"
  slug              = "ads-httpproxy"
  protocol_provider = authentik_provider_oauth2.http_proxy.id
  meta_launch_url   = "http://localhost:8080/"
}

# AfterDark Management Console
resource "authentik_provider_oauth2" "management_console" {
  name               = "AfterDark Management Console Provider"
  client_id          = "ads-management-console"
  client_type        = "confidential"
  authorization_flow = local.authorization_flow_id

  redirect_uris = [
    "http://localhost:9100/oauth/callback",
    "https://console.afterdark.local/oauth/callback"
  ]

  signing_key = local.signing_key_id

  property_mappings = []

  sub_mode                     = "hashed_user_id"
  include_claims_in_id_token   = true
  issuer_mode                  = "per_provider"
}

resource "authentik_application" "management_console" {
  name              = "AfterDark Management Console"
  slug              = "ads-management"
  protocol_provider = authentik_provider_oauth2.management_console.id
  meta_launch_url   = "http://localhost:9100/"
}

# Outputs
output "security_suite_client_secret" {
  value     = authentik_provider_oauth2.security_suite.client_secret
  sensitive = true
}

output "http_proxy_client_secret" {
  value     = authentik_provider_oauth2.http_proxy.client_secret
  sensitive = true
}

output "management_console_client_secret" {
  value     = authentik_provider_oauth2.management_console.client_secret
  sensitive = true
}
