terraform {
  # 1.10+ needed for S3-native state locking (use_lockfile), so we don't
  # need a separate DynamoDB lock table anymore.
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Remote state. The bucket name includes the account ID, so it's passed at
  # init time instead of hardcoded in a public repo:
  #   terraform init -backend-config="bucket=$(terraform -chdir=bootstrap output -raw state_bucket)"
  backend "s3" {
    key          = "cloud-security-baseline/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true # lock file in S3 stops two applies from colliding
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource gets these tags automatically. Tags are how you answer
  # "who created this and why" during an incident or a cost review.
  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
    }
  }
}
