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
