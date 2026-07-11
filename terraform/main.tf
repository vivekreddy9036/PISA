# PISA Terraform — Sprint 9 placeholder
# Provisions: DynamoDB tables, S3 bucket, Lambda functions, API Gateway, SNS, CloudWatch

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}
