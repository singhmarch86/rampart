output "alb_dns_name" {
  description = "Public DNS name of the load balancer. Point your domain's CNAME/ALIAS here."
  value       = aws_lb.this.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service_name" {
  value = aws_ecs_service.this.name
}

output "task_security_group_id" {
  description = "Security group attached to the Rampart tasks. If `upstream` is another service in this VPC, add an ingress rule on ITS security group allowing traffic from this one."
  value       = aws_security_group.task.id
}
