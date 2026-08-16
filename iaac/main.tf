provider "aws" {
  region = var.aws_region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

resource "aws_key_pair" "deployer" {
  key_name   = "${var.project_name}-key"
  public_key = var.ssh_public_key
}

resource "aws_vpc" "honeypot_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.project_name}-vpc"
    Project = var.project_name
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.honeypot_vpc.id

  tags = {
    Name    = "${var.project_name}-igw"
    Project = var.project_name
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.honeypot_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_name}-public"
    Project = var.project_name
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.honeypot_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name    = "${var.project_name}-rt"
    Project = var.project_name
  }
}

resource "aws_route_table_association" "rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "honeypot_sg" {
  name        = "${var.project_name}-sg"
  description = "Watchpost decoy API + admin SSH"
  vpc_id      = aws_vpc.honeypot_vpc.id

  ingress {
    description = "Admin SSH"
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  ingress {
    description = "Decoy SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Decoy HTTP / Tor gateway"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS (reserved)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Canary / alert webhooks"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-sg"
    Project = var.project_name
  }
}

resource "aws_instance" "beelzebub_node" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]
  key_name               = aws_key_pair.deployer.key_name

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -euxo pipefail

              # Admin SSH on 2222 (port 22 reserved for decoy)
              systemctl disable --now ssh.socket || true
              echo "Port 2222" > /etc/ssh/sshd_config.d/99-watchpost.conf
              systemctl enable --now ssh.service
              systemctl restart ssh.service

              # Docker
              apt-get update -y
              apt-get install -y ca-certificates curl gnupg python3
              install -m 0755 -d /etc/apt/keyrings
              curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
              chmod a+r /etc/apt/keyrings/docker.asc
              echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
              apt-get update -y
              apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
              systemctl enable --now docker
              usermod -aG docker ubuntu

              mkdir -p /home/ubuntu/beelzebub/data /home/ubuntu/beelzebub/secrets
              chown -R ubuntu:ubuntu /home/ubuntu/beelzebub
              touch /var/lib/cloud/instance/watchpost-user-data-done
              EOF

  tags = {
    Name    = "${var.project_name}-node"
    Project = var.project_name
  }
}

output "public_ip" {
  value = aws_instance.beelzebub_node.public_ip
}

output "instance_id" {
  value = aws_instance.beelzebub_node.id
}

output "ssh_login_command" {
  value = "ssh -i <private-key> -p 2222 ubuntu@${aws_instance.beelzebub_node.public_ip}"
}

output "decoy_api" {
  value = "http://${aws_instance.beelzebub_node.public_ip}"
}

output "canary_webhook" {
  value = "http://${aws_instance.beelzebub_node.public_ip}:8080/hook/canary"
}
