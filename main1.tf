# Provider Configuration
provider "aws" {
  region = "us-west-2"
}

# Users, IAM policies and their groups

# Define IAM Groups
resource "aws_iam_group" "admin_group" {
  name = "AdminGroup"
}

resource "aws_iam_group" "developer_group" {
  name = "DeveloperGroup"
}

resource "aws_iam_group" "operations_group" {
  name = "OperationsGroup"
}

resource "aws_iam_group" "readonly_group" {
  name = "ReadonlyGroup"
}

resource "aws_iam_group" "billing_group" {
  name = "BillingGroup"
}

# Define IAM Users and attach them to groups
resource "aws_iam_user" "admin_user" {
  name = "admin_user"
}

resource "aws_iam_user_group_membership" "admin_user_group_membership" {
  user = aws_iam_user.admin_user.name
  groups = [aws_iam_group.admin_group.name]
}

resource "aws_iam_user" "developer_user" {
  name = "developer_user"
}

resource "aws_iam_user_group_membership" "developer_user_group_membership" {
  user = aws_iam_user.developer_user.name
  groups = [aws_iam_group.developer_group.name]
}

resource "aws_iam_user" "operations_user" {
  name = "operations_user"
}

resource "aws_iam_user_group_membership" "operations_user_group_membership" {
  user = aws_iam_user.operations_user.name
  groups = [aws_iam_group.operations_group.name]
}

resource "aws_iam_user" "readonly_user" {
  name = "readonly_user"
}

resource "aws_iam_user_group_membership" "readonly_user_group_membership" {
  user = aws_iam_user.readonly_user.name
  groups = [aws_iam_group.readonly_group.name]
}

resource "aws_iam_user" "billing_user" {
  name = "billing_user"
}

resource "aws_iam_user_group_membership" "billing_user_group_membership" {
  user = aws_iam_user.billing_user.name
  groups = [aws_iam_group.billing_group.name]
}

# Define IAM Policies for each group
resource "aws_iam_policy" "admin_policy" {
  name        = "AdminPolicy"
  description = "Admin access policy"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "*",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "developer_policy" {
  name        = "DeveloperPolicy"
  description = "Developer access policy"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:Describe*",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "s3:*",
          "lambda:*",
          "cloudwatch:*",
          "dynamodb:*",
          "rds:*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "operations_policy" {
  name        = "OperationsPolicy"
  description = "Operations access policy"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:*",
          "s3:*",
          "cloudwatch:*",
          "logs:*",
          "sns:*",
          "ses:*",
          "route53:*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "readonly_policy" {
  name        = "ReadonlyPolicy"
  description = "Readonly access policy"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:Describe*",
          "s3:Get*",
          "cloudwatch:Describe*",
          "logs:Describe*",
          "dynamodb:Describe*",
          "rds:Describe*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "billing_policy" {
  name        = "BillingPolicy"
  description = "Billing access policy"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "aws-portal:ViewBilling",
          "aws-portal:ViewUsage"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach policies to groups
resource "aws_iam_group_policy_attachment" "admin_policy_attachment" {
  group      = aws_iam_group.admin_group.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

resource "aws_iam_group_policy_attachment" "developer_policy_attachment" {
  group      = aws_iam_group.developer_group.name
  policy_arn = aws_iam_policy.developer_policy.arn
}

resource "aws_iam_group_policy_attachment" "operations_policy_attachment" {
  group      = aws_iam_group.operations_group.name
  policy_arn = aws_iam_policy.operations_policy.arn
}

resource "aws_iam_group_policy_attachment" "readonly_policy_attachment" {
  group      = aws_iam_group.readonly_group.name
  policy_arn = aws_iam_policy.readonly_policy.arn
}

resource "aws_iam_group_policy_attachment" "billing_policy_attachment" {
  group      = aws_iam_group.billing_group.name
  policy_arn = aws_iam_policy.billing_policy.arn
}




# Data Source: Caller Identity
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

# KMS Key
resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = "kms:*",
        Resource = "*"
      },
      {
        Effect = "Allow",
        Principal = {
          Service = [
            "cloudtrail.amazonaws.com",
            "config.amazonaws.com"
          ]
        },
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ],
        Resource = "*"
      }
    ]
  })
}

# Enable AWS Security Hub for the current AWS account
resource "aws_securityhub_account" "current" {}

# Subscribe to AWS Security Hub standards
resource "aws_securityhub_standards_subscription" "standard" {
  depends_on    = [aws_securityhub_account.current]
  standards_arn = "arn:aws:securityhub:us-west-2::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# S3 Buckets
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloudtrail-bucket-28-05-2024"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "Ct" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_policy.json
}

data "aws_iam_policy_document" "cloudtrail_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::cloudtrail-bucket-28-05-2024"]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::cloudtrail-bucket-28-05-2024/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/main-cloudtrail"]
    }
  }
}

# S3 Buckets and Policies
resource "aws_s3_bucket" "mybucket" {
  bucket = "mybucket-28-05-2024"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3" {
  bucket = aws_s3_bucket.mybucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Enable AWS Config Configuration Recorder
resource "aws_config_configuration_recorder" "example" {
  name     = "example-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
  }
}

# Enable AWS Config Delivery Channel
resource "aws_config_delivery_channel" "example" {
  name             = "example-delivery-channel"
  s3_bucket_name   = aws_s3_bucket.config_bucket.bucket
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "config-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "config.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

# IAM Role Policy for AWS Config
resource "aws_iam_role_policy" "config_policy" {
  name   = "config-role-policy"
  role   = aws_iam_role.config_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.config_bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.config_bucket.bucket}/*"
        ]
      }
    ]
  })
}

# S3 Bucket for AWS Config
resource "aws_s3_bucket" "config_bucket" {
  bucket = "config-bucket-example-28-05-2027"
}

# S3 Bucket Policy for AWS Config
resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = aws_s3_bucket.config_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = "s3:PutObject",
        Resource = "arn:aws:s3:::${aws_s3_bucket.config_bucket.bucket}/*"
      },
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = "s3:GetBucketAcl",
        Resource = "arn:aws:s3:::${aws_s3_bucket.config_bucket.bucket}"
      }
    ]
  })
}

# CloudWatch Logs and Metric Alarms
resource "aws_cloudwatch_log_group" "example_log_group" {
  name              = "/aws/example/log-group"
  retention_in_days = 7
}

resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "high-cpu-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80

  dimensions = {
    InstanceId = "i-12345678"
  }

  alarm_actions = [
    "arn:aws:sns:us-west-2:730335583982:examplealarm"
  ]
}

# Guard Duty
resource "aws_guardduty_detector" "MyDetector" {
  enable = true
}

# SSM Patch Management
resource "aws_ssm_patch_baseline" "example" {
  name        = "New-patch-baseline"
  description = "Example patch baseline"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"
    enable_non_security = true

    patch_filter {
      key    = "PRODUCT"
      values = ["AmazonLinux2"]
    }

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }
  }

  operating_system = "AMAZON_LINUX_2"
}

# AWS Budgets
resource "aws_budgets_budget" "ec2" {
  name              = "budget-ec2-monthly"
  budget_type       = "COST"
  limit_amount      = "1000"
  limit_unit        = "USD"
  time_period_end   = "2087-06-15_00:00"
  time_period_start = "2017-07-01_00:00"
  time_unit         = "MONTHLY"

  cost_filter {
    name = "Service"
    values = [
      "Amazon Elastic Compute Cloud - Compute",
    ]
  }

  notification {
    comparison_operator = "GREATER_THAN"
    notification_type   = "FORECASTED"
    threshold           = 80
    threshold_type      = "PERCENTAGE"

    subscriber_email_addresses = ["abdulrahman.abdullah@synectiks.com"]
  }
}

