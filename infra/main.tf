# Ejemplo de infraestructura AWS con configuraciones inseguras (NO USAR EN PRODUCCIÓN)
# Propósito: Demostración de incumplimiento del ENS (op.acc.1 y mp.com.1)

provider "aws" {
  region = "eu-west-1"
}

# Incumplimiento ENS-S3-01: Bucket sin Block Public Access
resource "aws_s3_bucket" "public_assets" {
  bucket = "atlantico-cloud-public-assets-demo"
}

# Incumplimiento ENS-VPC-01: Puerto 22 (SSH) abierto a 0.0.0.0/0
resource "aws_security_group" "web_prod_sg" {
  name        = "web-prod-sg"
  description = "Security Group inseguro con SSH expuesto"

  ingress {
    description = "SSH desde cualquier IP (NO CONFORME ENS)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}