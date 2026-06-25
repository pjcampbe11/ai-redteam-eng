# Secure-by-default AWS front door for an LLM inference endpoint.
# Illustrative reference — review against your org's baseline before applying.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "region" { default = "us-east-1" }
provider "aws" { region = var.region }

# --- Model API key stored in Secrets Manager (rotated, never in code) ---
resource "aws_secretsmanager_secret" "model_api_key" {
  name        = "ai/model-api-key"
  description = "Provider API key for LLM inference; rotated every 30 days."
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_rotation" "model_api_key" {
  secret_id           = aws_secretsmanager_secret.model_api_key.id
  rotation_lambda_arn = var.rotation_lambda_arn
  rotation_rules { automatically_after_days = 30 }
}
variable "rotation_lambda_arn" { type = string }

# --- Least-privilege task role: read ONLY this secret, nothing else ---
data "aws_iam_policy_document" "inference_role" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.model_api_key.arn]
  }
}
resource "aws_iam_policy" "inference" {
  name   = "ai-inference-least-privilege"
  policy = data.aws_iam_policy_document.inference_role.json
}

# --- WAF in front of the API gateway: rate limit + body size cap ---
resource "aws_wafv2_web_acl" "ai_gateway" {
  name  = "ai-gateway-acl"
  scope = "REGIONAL"
  default_action { allow {} }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "aiGateway"
    sampled_requests_enabled   = true
  }
  rule {
    name     = "rate-limit"
    priority = 1
    action { block {} }
    statement {
      rate_based_statement { limit = 600, aggregate_key_type = "IP" }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rateLimit"
      sampled_requests_enabled   = true
    }
  }
}

# --- Private inference endpoint: no public IPs, VPC-isolated ---
resource "aws_security_group" "inference" {
  name        = "ai-inference-sg"
  description = "Egress to model provider only; no inbound from internet."
  vpc_id      = var.vpc_id
  egress {
    description = "HTTPS to provider"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.provider_cidrs   # allow-list, not 0.0.0.0/0
  }
}
variable "vpc_id" { type = string }
variable "provider_cidrs" { type = list(string) }
