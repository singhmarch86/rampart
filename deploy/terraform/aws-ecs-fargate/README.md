# Rampart on AWS ECS Fargate

Provisions: an ECS cluster, a Fargate task/service running Rampart, an
Application Load Balancer (public proxy listener + a separately-restricted
dashboard listener), and least-privilege security groups (task only
reachable from the ALB; dashboard listener only reachable from
`dashboard_allowed_cidrs`).

```hcl
module "rampart" {
  source = "./deploy/terraform/aws-ecs-fargate"

  image               = "123456789.dkr.ecr.us-east-1.amazonaws.com/rampart:latest"
  vpc_id              = "vpc-xxxxxxxx"
  public_subnet_ids   = ["subnet-aaa", "subnet-bbb"]
  private_subnet_ids  = ["subnet-ccc", "subnet-ddd"]

  # Restrict this to your office/VPN CIDR. The dashboard has no auth of its own.
  dashboard_allowed_cidrs = ["203.0.113.0/24"]

  certificate_arn = "arn:aws:acm:us-east-1:123456789:certificate/xxxx" # optional
}
```

## What this module does NOT do

- **Build or push your image.** `image` must already exist in a registry
  ECS can pull from (ECR, typically). Build your own image FROM the
  Dockerfile in the repo root, with your `rampart.yaml`, WAF custom rules,
  and schemas baked in or fetched at container startup — this module
  provisions infrastructure, not your Rampart configuration.
- **Set up the VPC/subnets.** Bring your own — this module assumes you
  already have a VPC with public and private subnets (private subnets need
  a route to the internet, e.g. a NAT gateway, to pull the image and reach
  external services, unless you're using VPC endpoints for ECR).
- **Cloud-edge DDoS protection.** Put this behind AWS Shield if you need
  volumetric-attack protection ahead of the ALB — see
  `docs/NETWORK_HARDENING.md` in the main repo for why that's a separate
  concern from what Rampart itself does.

## Verification status

This module has been written carefully against the `hashicorp/aws ~> 5.0`
provider's documented resource schema, but **has not been run through
`terraform validate` or `terraform plan`** — the Terraform CLI wasn't
available (installable, but gated behind an untrusted-tap warning) in the
environment this was built in. Review it yourself, or run `terraform
validate` before applying, especially if you're not already familiar with
reading Terraform for correctness.
