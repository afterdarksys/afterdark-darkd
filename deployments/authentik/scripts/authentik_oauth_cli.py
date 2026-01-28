#!/usr/bin/env python3
"""
Authentik OAuth Provider CLI Tool
Extracted from Authentik's Django admin bootstrap logic
Uses Django ORM directly - bypasses API permission issues
"""

import os
import sys
import json
from typing import Optional

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()

from authentik.core.models import Application
from authentik.providers.oauth2.models import (
    OAuth2Provider,
    ClientTypes,
    RedirectURIMatchingMode,
)
from authentik.flows.models import Flow, FlowDesignation
from authentik.crypto.models import CertificateKeyPair


class AuthentikOAuthCLI:
    """CLI tool for managing OAuth providers using Django ORM"""

    def __init__(self):
        self.default_flow = Flow.objects.filter(
            designation=FlowDesignation.AUTHORIZATION
        ).first()
        self.default_cert = CertificateKeyPair.objects.filter(
            name="authentik Self-signed Certificate"
        ).first()

        if not self.default_flow:
            raise Exception("No authorization flow found")
        if not self.default_cert:
            raise Exception("No signing certificate found")

    def create_provider(
        self,
        name: str,
        client_id: str,
        redirect_uris: list,
        client_type: str = "confidential",
        authorization_flow: Optional[Flow] = None,
        signing_key: Optional[CertificateKeyPair] = None,
    ) -> OAuth2Provider:
        """
        Create OAuth2 provider using Django ORM
        Same logic as Authentik's admin interface
        """

        # Check if exists
        try:
            provider = OAuth2Provider.objects.get(client_id=client_id)
            print(f"Provider {client_id} already exists", file=sys.stderr)
            return provider
        except OAuth2Provider.DoesNotExist:
            pass

        # Convert redirect_uris list to internal format (list of dicts)
        # Bypass the property setter which expects dataclass instances
        redirect_uris_data = [
            {
                "matching_mode": "strict",
                "url": uri,
            }
            for uri in redirect_uris
        ]

        # Create provider without redirect_uris first
        provider = OAuth2Provider.objects.create(
            name=name,
            authorization_flow=authorization_flow or self.default_flow,
            client_id=client_id,
            client_type=client_type,
            signing_key=signing_key or self.default_cert,
            sub_mode="hashed_user_id",
            include_claims_in_id_token=True,
            issuer_mode="per_provider",
        )

        # Set redirect_uris directly on internal field
        provider._redirect_uris = redirect_uris_data
        provider.save()

        return provider

    def create_application(
        self,
        name: str,
        slug: str,
        provider: OAuth2Provider,
        launch_url: Optional[str] = None,
    ) -> Application:
        """Create application linked to provider"""

        try:
            app = Application.objects.get(slug=slug)
            # Update provider if different
            if app.provider != provider:
                app.provider = provider
                app.save()
            print(f"Application {slug} already exists", file=sys.stderr)
            return app
        except Application.DoesNotExist:
            pass

        app = Application.objects.create(
            name=name,
            slug=slug,
            provider=provider,
            meta_launch_url=launch_url or "",
        )

        return app

    def create_oauth_app(
        self,
        app_name: str,
        app_slug: str,
        client_id: str,
        redirect_uris: list,
        launch_url: str,
    ) -> dict:
        """
        Complete OAuth app creation (provider + application)
        Returns dict with all details including client_secret
        """

        provider = self.create_provider(
            name=f"{app_name} Provider",
            client_id=client_id,
            redirect_uris=redirect_uris,
        )

        app = self.create_application(
            name=app_name,
            slug=app_slug,
            provider=provider,
            launch_url=launch_url,
        )

        return {
            "app_name": app.name,
            "app_slug": app.slug,
            "provider_name": provider.name,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "redirect_uris": redirect_uris,
            "launch_url": launch_url,
        }

    def list_providers(self) -> list:
        """List all OAuth2 providers"""
        providers = []
        for p in OAuth2Provider.objects.all():
            providers.append({
                "name": p.name,
                "client_id": p.client_id,
                "client_secret": p.client_secret[:20] + "...",
                "redirect_uris": p.redirect_uris.split("\n") if p.redirect_uris else [],
            })
        return providers

    def list_applications(self) -> list:
        """List all applications"""
        apps = []
        for app in Application.objects.all():
            apps.append({
                "name": app.name,
                "slug": app.slug,
                "provider": app.provider.name if app.provider else None,
                "launch_url": app.meta_launch_url,
            })
        return apps


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Authentik OAuth Provider CLI - Direct Django ORM access"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create OAuth app")
    create_parser.add_argument("--name", required=True, help="Application name")
    create_parser.add_argument("--slug", required=True, help="Application slug")
    create_parser.add_argument("--client-id", required=True, help="OAuth client ID")
    create_parser.add_argument("--redirect-uri", action="append", required=True, help="Redirect URI (can specify multiple)")
    create_parser.add_argument("--launch-url", required=True, help="Launch URL")
    create_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # List command
    list_parser = subparsers.add_parser("list", help="List providers or applications")
    list_parser.add_argument("resource", choices=["providers", "applications"])
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Bootstrap command - create all AfterDark apps
    bootstrap_parser = subparsers.add_parser("bootstrap", help="Bootstrap all AfterDark OAuth apps")
    bootstrap_parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = AuthentikOAuthCLI()

    if args.command == "create":
        result = cli.create_oauth_app(
            app_name=args.name,
            app_slug=args.slug,
            client_id=args.client_id,
            redirect_uris=args.redirect_uri,
            launch_url=args.launch_url,
        )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"✓ Created OAuth app: {result['app_name']}")
            print(f"  Client ID: {result['client_id']}")
            print(f"  Client Secret: {result['client_secret']}")

    elif args.command == "list":
        if args.resource == "providers":
            results = cli.list_providers()
        else:
            results = cli.list_applications()

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for item in results:
                print(json.dumps(item, indent=2))

    elif args.command == "bootstrap":
        apps_config = [
            {
                "app_name": "AfterDark HTTP Proxy",
                "app_slug": "ads-httpproxy",
                "client_id": "ads-httpproxy-client",
                "redirect_uris": [
                    "http://localhost:8080/oauth/callback",
                    "https://proxy.afterdark.local/oauth/callback"
                ],
                "launch_url": "http://localhost:8080/",
            },
            {
                "app_name": "AfterDark Management Console",
                "app_slug": "ads-management",
                "client_id": "ads-management-console",
                "redirect_uris": [
                    "http://localhost:9100/oauth/callback",
                    "https://console.afterdark.local/oauth/callback"
                ],
                "launch_url": "http://localhost:9100/",
            },
        ]

        results = []
        for app_config in apps_config:
            result = cli.create_oauth_app(**app_config)
            results.append(result)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("✓ Bootstrap complete!")
            print("\nCreated OAuth apps:")
            for result in results:
                print(f"\n{result['app_name']}:")
                print(f"  Client ID: {result['client_id']}")
                print(f"  Client Secret: {result['client_secret']}")


if __name__ == "__main__":
    main()
