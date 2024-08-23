provider "aws" {
  region = "eu-central-1"
}

provider "aws" {
  alias  = "global"
  region = "us-east-1"
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "tls_private_key" "fts_ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "fts_key_pair" {
  key_name   = "fts-ssh-key"
  public_key = tls_private_key.fts_ssh_key.public_key_openssh
}

resource "aws_secretsmanager_secret" "fts_private_key" {
  name = "fts-ssh-private-key"
}

resource "aws_secretsmanager_secret_version" "fts_private_key" {
  secret_id     = aws_secretsmanager_secret.fts_private_key.id
  secret_string = tls_private_key.fts_ssh_key.private_key_pem
}

# S3 Bucket
resource "aws_s3_bucket" "fts_website_bucket" {
  bucket = "finance-tech-solutions-website"
}

resource "aws_s3_bucket_versioning" "fts_website_bucket" {
  bucket = aws_s3_bucket.fts_website_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_website_configuration" "fts_website" {
  bucket = aws_s3_bucket.fts_website_bucket.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "fts_website_bucket" {
  bucket = aws_s3_bucket.fts_website_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "fts_index" {
  bucket       = aws_s3_bucket.fts_website_bucket.id
  key          = "index.html"
  source       = "index.html"
  content_type = "text/html"

  etag = filemd5("index.html")
}

# VPC und Subnets
resource "aws_vpc" "fts_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "fts-vpc"
  }
}

resource "aws_internet_gateway" "fts_igw" {
  vpc_id = aws_vpc.fts_vpc.id

  tags = {
    Name = "fts-igw"
  }
}

resource "aws_route_table" "fts_route_table" {
  vpc_id = aws_vpc.fts_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fts_igw.id
  }

  tags = {
    Name = "fts-route-table"
  }
}

resource "aws_subnet" "fts_subnet_1" {
  vpc_id                  = aws_vpc.fts_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "fts-subnet-1"
  }
}

resource "aws_subnet" "fts_subnet_2" {
  vpc_id                  = aws_vpc.fts_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "fts-subnet-2"
  }
}

resource "aws_route_table_association" "fts_rta_1" {
  subnet_id      = aws_subnet.fts_subnet_1.id
  route_table_id = aws_route_table.fts_route_table.id
}

resource "aws_route_table_association" "fts_rta_2" {
  subnet_id      = aws_subnet.fts_subnet_2.id
  route_table_id = aws_route_table.fts_route_table.id
}

# Security Groups
resource "aws_security_group" "fts_lb_sg" {
  name        = "fts-lb-sg"
  description = "Security group for FTS load balancer"
  vpc_id      = aws_vpc.fts_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "fts_ec2_sg" {
  name        = "fts-ec2-sg"
  description = "Security group for FTS EC2 instances"
  vpc_id      = aws_vpc.fts_vpc.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.fts_lb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Role
resource "aws_iam_role" "fts_ec2_role" {
  name = "fts_ec2_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "fts_s3_access_policy" {
  name = "fts_s3_access_policy"
  role = aws_iam_role.fts_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.fts_website_bucket.arn,
          "${aws_s3_bucket.fts_website_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.fts_private_key.arn
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "fts_ec2_profile" {
  name = "fts_ec2_profile"
  role = aws_iam_role.fts_ec2_role.name
}

# Load Balancer
resource "aws_lb" "fts_lb" {
  name               = "fts-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.fts_lb_sg.id]
  subnets            = [aws_subnet.fts_subnet_1.id, aws_subnet.fts_subnet_2.id]

  enable_deletion_protection = false
}

resource "aws_lb_listener" "fts_http_listener" {
  load_balancer_arn = aws_lb.fts_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group" "fts_target_group" {
  name     = "fts-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.fts_vpc.id

  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

# Temporärer Listener für HTTPS (wird später aktualisiert)
resource "aws_lb_listener" "fts_https_listener" {
  load_balancer_arn = aws_lb.fts_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.fts_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.fts_target_group.arn
  }
}

# Temporäres selbstsigniertes Zertifikat (wird später durch ein richtiges ersetzt)
resource "tls_private_key" "fts_private_key" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "fts_self_signed_cert" {
  private_key_pem = tls_private_key.fts_private_key.private_key_pem

  subject {
    common_name  = "financetechsolutions.com"
    organization = "Finance Tech Solutions, Inc"
  }

  validity_period_hours = 12

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "fts_cert" {
  private_key      = tls_private_key.fts_private_key.private_key_pem
  certificate_body = tls_self_signed_cert.fts_self_signed_cert.cert_pem
}

# Launch Template
resource "aws_launch_template" "fts_launch_template" {
  name_prefix   = "fts-launch-template"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = "t2.micro"

  key_name = aws_key_pair.fts_key_pair.key_name

  vpc_security_group_ids = [aws_security_group.fts_ec2_sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.fts_ec2_profile.name
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd jq awscli
              systemctl start httpd
              systemctl enable httpd

              # Kopieren der index.html aus dem S3-Bucket
              aws s3 cp s3://${aws_s3_bucket.fts_website_bucket.id}/index.html /var/www/html/index.html

              # Setzen der korrekten Berechtigungen
              chown apache:apache /var/www/html/index.html
              chmod 644 /var/www/html/index.html

              # Neustart des Apache-Servers, um Änderungen zu übernehmen
              systemctl restart httpd

              # Abrufen und Speichern des privaten Schlüssels
              aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.fts_private_key.id} --region eu-central-1 | jq -r .SecretString > /home/ec2-user/private_key.pem
              chmod 600 /home/ec2-user/private_key.pem
              chown ec2-user:ec2-user /home/ec2-user/private_key.pem
              EOF
  )
}

# Auto Scaling Group
resource "aws_autoscaling_group" "fts_asg" {
  desired_capacity    = 2
  max_size            = 4
  min_size            = 1
  target_group_arns   = [aws_lb_target_group.fts_target_group.arn]
  vpc_zone_identifier = [aws_subnet.fts_subnet_1.id, aws_subnet.fts_subnet_2.id]

  launch_template {
    id      = aws_launch_template.fts_launch_template.id
    version = "$Latest"
  }
}

# Auto Scaling Policies
resource "aws_autoscaling_policy" "fts_scale_up" {
  name                   = "fts-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.fts_asg.name
}

resource "aws_autoscaling_policy" "fts_scale_down" {
  name                   = "fts-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.fts_asg.name
}

# CloudWatch Alarms for Auto Scaling
resource "aws_cloudwatch_metric_alarm" "fts_high_cpu" {
  alarm_name          = "fts-high-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "70"
  alarm_description   = "This metric monitors ec2 cpu utilization for FTS"
  alarm_actions       = [aws_autoscaling_policy.fts_scale_up.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.fts_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "fts_low_cpu" {
  alarm_name          = "fts-low-cpu-utilization"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "30"
  alarm_description   = "This metric monitors ec2 cpu utilization for FTS"
  alarm_actions       = [aws_autoscaling_policy.fts_scale_down.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.fts_asg.name
  }
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "fts_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  origin {
    domain_name = aws_s3_bucket.fts_website_bucket.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.fts_website_bucket.id}"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.fts_oai.cloudfront_access_identity_path
    }
  }

  origin {
    domain_name = aws_lb.fts_lb.dns_name
    origin_id   = "ELB-${aws_lb.fts_lb.name}"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.fts_website_bucket.id}"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  ordered_cache_behavior {
    path_pattern     = "/api/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ELB-${aws_lb.fts_lb.name}"

    forwarded_values {
      query_string = true
      headers      = ["Origin"]
      cookies {
        forward = "all"
      }
    }

    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_cloudfront_origin_access_identity" "fts_oai" {
  comment = "OAI for Finance Tech Solutions"
}

# Update S3 Bucket Policy
resource "aws_s3_bucket_policy" "fts_public_read" {
  bucket = aws_s3_bucket.fts_website_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontServicePrincipal"
        Effect    = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.fts_oai.iam_arn
        }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.fts_website_bucket.arn}/*"
      }
    ]
  })
}

# Outputs
output "fts_cloudfront_url" {
  value       = aws_cloudfront_distribution.fts_distribution.domain_name
  description = "The CloudFront URL of the Finance Tech Solutions website"
}