#!/usr/bin/env python3
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()

from authentik.core.models import Application
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.flows.models import Flow
from authentik.crypto.models import CertificateKeyPair

auth_flow = Flow.objects.filter(designation="authorization").first()
cert = CertificateKeyPair.objects.filter(name="authentik Self-signed Certificate").first()

providers_config = [
    ("afterdark-security-suite", "AfterDark Security Suite", "afterdark-security-suite",
     "http://localhost:9090/oauth/callback\nhttps://security.afterdark.local/oauth/callback",
     "http://localhost:9090/"),
    ("ads-httpproxy-client", "AfterDark HTTP Proxy", "ads-httpproxy",
     "http://localhost:8080/oauth/callback\nhttps://proxy.afterdark.local/oauth/callback",
     "http://localhost:8080/"),
    ("ads-management-console", "AfterDark Management Console", "ads-management",
     "http://localhost:9100/oauth/callback\nhttps://console.afterdark.local/oauth/callback",
     "http://localhost:9100/"),
]

print("# OAuth Client Secrets")
print("# Add these to your .env file\n")

for client_id, app_name, app_slug, redirects, launch_url in providers_config:
    try:
        provider, created = OAuth2Provider.objects.get_or_create(
            client_id=client_id,
            defaults={
                "name": f"{app_name} Provider",
                "authorization_flow": auth_flow,
                "client_type": "confidential",
                "redirect_uris": redirects,
                "signing_key": cert,
                "sub_mode": "hashed_user_id",
                "include_claims_in_id_token": True
            }
        )

        app, app_created = Application.objects.get_or_create(
            slug=app_slug,
            defaults={
                "name": app_name,
                "provider": provider,
                "meta_launch_url": launch_url
            }
        )
        if not app_created and not app.provider:
            app.provider = provider
            app.save()

        env_name = client_id.upper().replace('-', '_')
        print(f"{env_name}_CLIENT_ID={client_id}")
        print(f"{env_name}_CLIENT_SECRET={provider.client_secret}")
        print()

    except Exception as e:
        print(f"ERROR creating {client_id}: {e}")
        continue

print("✓ All OAuth apps configured")
