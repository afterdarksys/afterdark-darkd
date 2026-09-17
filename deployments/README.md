# Deployment Infrastructure

Infrastructure as code for deploying AfterDark-DarkD across your environment.

## Ansible

Ansible playbooks for deploying to physical/virtual machines.

```bash
cd ansible

# Edit inventory
vim inventory/hosts.yml

# Deploy to all hosts
ansible-playbook -i inventory/hosts.yml playbooks/deploy.yml

# Deploy to specific group
ansible-playbook -i inventory/hosts.yml playbooks/deploy.yml --limit linux

# Uninstall
ansible-playbook -i inventory/hosts.yml playbooks/uninstall.yml
```

### Inventory Example

```yaml
all:
  vars:
    darkapi_key: "{{ lookup('env', 'DARKAPI_API_KEY') }}"
  children:
    linux:
      hosts:
        server1.example.com:
        server2.example.com:
    macos:
      hosts:
        mac1.example.com:
    windows:
      hosts:
        win1.example.com:
          ansible_connection: winrm
```

## Terraform

Terraform modules for cloud deployment.

### AWS

```bash
cd terraform/aws

terraform init
terraform plan -var="darkapi_key=$DARKAPI_API_KEY"
terraform apply -var="darkapi_key=$DARKAPI_API_KEY"
```

### Azure

```bash
cd terraform/azure

terraform init
terraform plan -var="darkapi_key=$DARKAPI_API_KEY"
terraform apply -var="darkapi_key=$DARKAPI_API_KEY"
```

### GCP

```bash
cd terraform/gcp

terraform init
terraform plan -var="darkapi_key=$DARKAPI_API_KEY"
terraform apply -var="darkapi_key=$DARKAPI_API_KEY"
```

## Docker

For containerized deployments (testing/development):

```bash
cd docker

# Build image
docker build -t afterdark-darkd .

# Run container
docker run -d \
  -e DARKAPI_API_KEY=$DARKAPI_API_KEY \
  -v /var/lib/afterdark:/var/lib/afterdark \
  afterdark-darkd
```

---

After Dark Systems, LLC

## Kubernetes acceptance (2026-09-17)

A disposable kind cluster exercised chart installation, non-root startup,
authenticated IPC status, pod replacement and persistence of the authentication
credential. Runtime tests identified and fixed root-owned volume mountpoints
being chmod'ed by the non-root daemon: tokens and sockets now use owned child
directories. Optional credential files are omitted when telemetry is disabled;
configuration checksums trigger pod replacement on changes.

Reproduce with `bash deployments/tests/helm-acceptance.sh IMAGE:TAG` after building
the Docker image. The script owns a temporary kubeconfig and cluster, verifies
uninstall, and removes its test PVC. It never selects a pre-existing cluster.
Readiness means authenticated daemon IPC is available. Container-restricted
sensors can still report degraded health (eBPF privileges, host integrity paths,
unsupported registry monitoring); this is not host EDR or SaaS acceptance.
