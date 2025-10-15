# main.tf

# 1. Configure the AWS Provider
# This tells Terraform that we are going to work with AWS resources.
# It will automatically use the credentials you set up in your environment.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1" # You can change this to your preferred AWS region
}

# 2. Create the Lightsail Instance
# This creates the actual server using the cheapest ($3.50) plan.
resource "aws_lightsail_instance" "scambait_server" {
  name              = "scambait-c2-server"
  availability_zone = "us-east-1a"        # Make sure this matches the region above
  blueprint_id      = "ubuntu_22_04"      # The OS image (Ubuntu 22.04 LTS)
  bundle_id         = "nano_2_0"          # The $3.50/month plan
  
  tags = {
    project = "scambait-trap"
  }
}

# 3. Create and Attach a Static IP Address
# This gives your instance a permanent public IP that won't change on reboot.
resource "aws_lightsail_static_ip" "server_ip" {
  name = "scambait-server-ip"
}

resource "aws_lightsail_static_ip_attachment" "ip_attachment" {
  static_ip_name = aws_lightsail_static_ip.server_ip.name
  instance_name  = aws_lightsail_instance.scambait_server.name
}

# 4. Open the Firewall Ports
# This opens the necessary ports:
# - Port 22 (SSH) for remote management
# - Port 5555 (C2) for receiver connections
resource "aws_lightsail_instance_public_ports" "server_firewall" {
  instance_name = aws_lightsail_instance.scambait_server.name

  # SSH access (port 22)
  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
    cidrs     = ["0.0.0.0/0"] # Allows SSH from any IP
  }

  # C2 receiver connections (port 5555)
  port_info {
    protocol  = "tcp"
    from_port = 5555
    to_port   = 5555
    cidrs     = ["0.0.0.0/0"] # Allows receiver connections from any IP
  }
}

# 5. Output the Static IP Address
# After the script runs, this will print the public IP address you need
# to put into your receiver.py script.
output "server_public_ip" {
  value = aws_lightsail_static_ip.server_ip.ip_address
  description = "The public IP address of the Lightsail server."
}