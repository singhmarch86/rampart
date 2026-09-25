variable "name" {
  description = "Name prefix for all resources this module creates."
  type        = string
  default     = "rampart"
}

variable "image" {
  description = <<-EOT
    Container image to run, including tag (e.g. "123456789.dkr.ecr.us-east-1.amazonaws.com/rampart:latest").
    Must be YOUR OWN image with your config baked in (or fetched at startup via your own
    entrypoint changes) — this module provisions infrastructure, it doesn't manage your
    Rampart configuration. See ../../Dockerfile for the base image to build on top of.
  EOT
  type = string
}

variable "vpc_id" {
  description = "VPC to deploy into."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the Application Load Balancer."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnets for the Fargate tasks. Must have a route to the internet (NAT gateway) to pull the container image unless using a VPC endpoint for ECR."
  type        = list(string)
}

variable "proxy_port" {
  description = "Rampart's proxy port (must match your baked-in config's `listen` port)."
  type        = number
  default     = 8080
}

variable "dashboard_port" {
  description = "Rampart's dashboard port (must match your baked-in config's `dashboard.listen` port), or null to not expose it via the ALB at all."
  type        = number
  default     = 9090
}

variable "dashboard_allowed_cidrs" {
  description = <<-EOT
    CIDR blocks allowed to reach the dashboard listener. The dashboard has no
    authentication of its own yet (see docs/ROADMAP.md in the main repo), so this
    MUST be restricted — e.g. your office/VPN CIDR, not 0.0.0.0/0. Required if
    dashboard_port is set.
  EOT
  type    = list(string)
  default = []
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the proxy's HTTPS listener. If null, the proxy listens on HTTP only — fine for testing, not for anything handling real traffic."
  type        = string
  default     = null
}

variable "container_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 512
}

variable "container_memory" {
  description = "Fargate task memory, in MiB."
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of Rampart tasks to run."
  type        = number
  default     = 2
}

variable "tags" {
  description = "Tags applied to all resources this module creates."
  type        = map(string)
  default     = {}
}
