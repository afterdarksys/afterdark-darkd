# Cloud endpoint deployment

The AWS, Azure and GCP modules provision endpoint infrastructure and bootstrap a
Linux daemon. They are not a multi-tenant SaaS management service.

Run `terraform init -backend=false` and `terraform validate` in each provider
directory before planning against your staging account. All three providers were
validated on 2026-09-17. The shared bootstrap is exercised with isolated filesystem
and cloud-response fixtures by:

```sh
python3 -m unittest discover -s shared -v
```

Provide an independently verified standalone daemon binary for every architecture
in the instance group (not a tar archive):

```hcl
daemon_binaries = {
  amd64 = {
    url    = "https://YOUR-ARTIFACT-HOST/afterdark-darkd-linux-amd64"
    sha256 = "REPLACE_WITH_64_HEX_DIGITS_FROM_YOUR_VERIFIED_BUILD"
  }
}
```

The bootstrap rejects missing/mismatched checksums before installing the daemon.
It installs cloud prerequisites, fetches the API key using the instance identity,
writes a mode-0600 JSON configuration (valid YAML), and starts the systemd unit
with `run --config ... --remote Disabled`. Existing daemon files are replaced only
after checksum and secret retrieval succeed. Provisioning does not expose remote
management ports. The legacy `afterdark_version` input is retained for compatibility;
artifact URLs and checksums now select the deployed version.

Use a private subnet with working outbound NAT/proxy/private service access.
OS package repositories need HTTP/HTTPS; DNS and cloud metadata endpoints must be
reachable. Network allow rules in these modules are not a complete egress-deny
policy. AWS requires IMDSv2; Azure selects the explicit user-assigned identity;
GCP fetches Secret Manager data through the metadata service token, without gcloud.
IAM propagation can delay first boot: inspect cloud-init logs and retry provisioning
only after permissions settle. Do not place credentials in artifact URLs.

The `darkapi_key` Terraform input remains in Terraform state even though marked
sensitive. Use an access-controlled encrypted remote state backend and keep plan,
state and tfvars files out of source control. No cloud account was applied during
local verification. Remaining acceptance: provider plan/apply, successful first
boot with real identity, authenticated daemon status, instance replacement and
destroy in the intended staging network. These modules do not establish endpoint
monitoring access to the Kubernetes host or certify an entire cloud environment.
