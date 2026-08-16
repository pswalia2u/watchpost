variable "aws_region" {
  description = "AWS region for the Watchpost node"
  type        = string
  default     = "eu-west-2"
}

variable "project_name" {
  description = "Name prefix for AWS resources"
  type        = string
  default     = "watchpost"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "m7i-flex.large"
}

variable "ssh_public_key" {
  description = "SSH public key for admin access on port 2222"
  type        = string
}

variable "admin_cidr" {
  description = "CIDR allowed for admin SSH on port 2222 (use your IP/32 in production)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GiB"
  type        = number
  default     = 20
}
