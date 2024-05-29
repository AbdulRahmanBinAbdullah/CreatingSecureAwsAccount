# CreatingSecureAwsAccount
Creating AWS account secure


This Terraform code is provisioning various AWS resources and configuring their associated policies and settings. Let's break down each section step by step:

Provider Configuration
Defines the AWS provider with the specified region and access keys.

Data Source: Caller Identity
Retrieves information about the AWS account making the Terraform API request.

IAM Policies
Defines IAM policies for different roles within the AWS environment:

admin_policy: Provides full administrative access.
developer_policy: Grants permissions for S3 actions.
ops_policy: Grants permissions for EC2 actions.
readonly_policy: Grants read-only access to S3.
billing_policy: Grants permissions to view billing information.
IAM Users and Groups
Creates IAM users and groups and attaches policies to them based on their roles:

admin_user and admin_group: Admin user and group with full admin access.
dev_user and dev_group: Developer user and group with S3 permissions.
ops_user and ops_group: Operations user and group with EC2 permissions.
readonly_user and readonly_group: Read-only user and group with S3 read access.
billing_user and billing_group: Billing user and group with permissions to view billing information.
CloudTrail Configuration
Configures AWS CloudTrail to log API activity and store logs in an S3 bucket.

S3 Buckets and Policies
Creates S3 buckets with server-side encryption and defines bucket policies for access control.

CloudWatch Logs and Metric Alarms
Creates CloudWatch log groups and metric alarms for monitoring EC2 instance CPU utilization.

AWS Config Configuration Recorder
Sets up AWS Config to record resource configurations and compliance status.

AWS GuardDuty Detector
Enables AWS GuardDuty for threat detection in the AWS environment.

SSM Patch Management
Defines patch baselines and patch groups for AWS Systems Manager (SSM) patch management.

AWS Security Hub
Enables AWS Security Hub and subscribes to the AWS Foundational Security Best Practices standard.

AWS Budgets
Creates a budget for EC2 costs with notifications for cost thresholds.

Conclusion
This Terraform configuration automates the setup and management of various AWS resources, access controls, monitoring, security, and cost management features, providing a comprehensive infrastructure setup for an AWS environment.
