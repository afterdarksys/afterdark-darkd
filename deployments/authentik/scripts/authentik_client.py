#!/usr/bin/env python3
"""
Authentik API Client for Configuration Management
Provides utilities to export/import/sync Authentik configuration as code
"""
import requests
import json
import sys
import os
from typing import Dict, List, Optional
from pathlib import Path


class AuthentikClient:
    """Client for Authentik API configuration management"""

    def __init__(self, base_url: str = "http://localhost:9000", token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token or os.getenv('AUTHENTIK_TOKEN')
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Make API request with error handling"""
        url = f"{self.base_url}/api/v3/{path.lstrip('/')}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def get_api_token(self, username: str, password: str) -> str:
        """Get API token by authenticating with username/password"""
        # Create token via API
        response = self.session.post(
            f"{self.base_url}/api/v3/core/tokens/",
            auth=(username, password),
            json={
                "identifier": "config-management-token",
                "intent": "api",
                "expiring": False,
                "description": "Configuration management automation token"
            }
        )
        response.raise_for_status()
        token_data = response.json()
        self.token = token_data.get('key')
        self.session.headers.update({'Authorization': f'Bearer {self.token}'})
        return self.token

    # Applications
    def list_applications(self) -> List[Dict]:
        """List all applications"""
        response = self._request('GET', '/core/applications/')
        return response.json().get('results', [])

    def export_application(self, slug: str) -> Dict:
        """Export single application configuration"""
        response = self._request('GET', f'/core/applications/{slug}/')
        return response.json()

    # Providers
    def list_providers(self) -> List[Dict]:
        """List all providers (OAuth2, SAML, etc)"""
        response = self._request('GET', '/providers/all/')
        return response.json().get('results', [])

    def export_oauth2_providers(self) -> List[Dict]:
        """Export OAuth2 provider configurations"""
        response = self._request('GET', '/providers/oauth2/')
        return response.json().get('results', [])

    # Flows
    def list_flows(self) -> List[Dict]:
        """List all authentication flows"""
        response = self._request('GET', '/flows/instances/')
        return response.json().get('results', [])

    def export_flow(self, slug: str) -> Dict:
        """Export single flow configuration"""
        response = self._request('GET', f'/flows/instances/{slug}/')
        return response.json()

    # Blueprints
    def list_blueprints(self) -> List[Dict]:
        """List all blueprints"""
        response = self._request('GET', '/managed/blueprints/')
        return response.json().get('results', [])

    def apply_blueprint(self, blueprint_path: str) -> Dict:
        """Apply a blueprint file"""
        response = self._request('POST', '/managed/blueprints/apply/',
                                json={"path": blueprint_path})
        return response.json()

    # Users & Groups
    def list_users(self) -> List[Dict]:
        """List all users"""
        response = self._request('GET', '/core/users/')
        return response.json().get('results', [])

    def list_groups(self) -> List[Dict]:
        """List all groups"""
        response = self._request('GET', '/core/groups/')
        return response.json().get('results', [])

    # Tenants
    def list_tenants(self) -> List[Dict]:
        """List all tenants"""
        response = self._request('GET', '/core/tenants/')
        return response.json().get('results', [])

    def export_tenant(self, domain: str) -> Dict:
        """Export tenant configuration"""
        response = self._request('GET', f'/core/tenants/{domain}/')
        return response.json()

    # Full Export
    def export_full_config(self, output_dir: str = "./config"):
        """Export complete Authentik configuration to JSON files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        config = {
            "applications": self.list_applications(),
            "providers": self.list_providers(),
            "oauth2_providers": self.export_oauth2_providers(),
            "flows": self.list_flows(),
            "users": self.list_users(),
            "groups": self.list_groups(),
            "tenants": self.list_tenants(),
            "blueprints": self.list_blueprints()
        }

        # Save each category separately
        for category, data in config.items():
            file_path = output_path / f"{category}.json"
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✓ Exported {len(data)} {category} to {file_path}")

        # Save full config
        full_config_path = output_path / "authentik_config.json"
        with open(full_config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\n✓ Full configuration exported to {full_config_path}")

        return config

    # Import/Sync
    def import_config(self, config_dir: str = "./config"):
        """Import configuration from JSON files"""
        config_path = Path(config_dir)

        if not config_path.exists():
            raise FileNotFoundError(f"Config directory not found: {config_path}")

        # Load full config
        full_config_file = config_path / "authentik_config.json"
        if full_config_file.exists():
            with open(full_config_file, 'r') as f:
                config = json.load(f)
            print(f"✓ Loaded configuration from {full_config_file}")
            return config
        else:
            raise FileNotFoundError(f"Config file not found: {full_config_file}")


def main():
    """CLI interface for Authentik configuration management"""
    import argparse

    parser = argparse.ArgumentParser(description='Authentik Configuration Management')
    parser.add_argument('--url', default='http://localhost:9000', help='Authentik URL')
    parser.add_argument('--token', help='API token (or set AUTHENTIK_TOKEN env var)')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export configuration')
    export_parser.add_argument('--output', '-o', default='./config', help='Output directory')

    # Import command
    import_parser = subparsers.add_parser('import', help='Import configuration')
    import_parser.add_argument('--input', '-i', default='./config', help='Input directory')

    # List command
    list_parser = subparsers.add_parser('list', help='List resources')
    list_parser.add_argument('resource', choices=[
        'applications', 'providers', 'flows', 'users', 'groups', 'tenants', 'blueprints'
    ])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Initialize client
    client = AuthentikClient(base_url=args.url, token=args.token)

    # Authenticate if username/password provided
    if args.username and args.password:
        token = client.get_api_token(args.username, args.password)
        print(f"✓ Authenticated and created token: {token[:20]}...")
    elif not client.token:
        print("Error: No authentication provided. Use --token or --username/--password")
        sys.exit(1)

    # Execute command
    try:
        if args.command == 'export':
            client.export_full_config(output_dir=args.output)
        elif args.command == 'import':
            config = client.import_config(config_dir=args.input)
            print(f"✓ Loaded {len(config)} configuration categories")
        elif args.command == 'list':
            method = getattr(client, f'list_{args.resource}')
            results = method()
            print(json.dumps(results, indent=2))
    except requests.HTTPError as e:
        print(f"✗ API Error: {e}")
        if e.response is not None:
            print(f"  Response: {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
