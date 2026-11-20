# Terraform secure baseline example

This optional example demonstrates secure-by-default Terraform patterns related to this scanner: private S3 public-access controls, bucket versioning, explicit default encryption, and a security group with no inbound access by default.

It is **not** required to run the Python scanner. The scanner currently audits live AWS resource configuration; it does not parse Terraform files.

Before running Terraform, review every resource and variable, select a disposable lab account, and run:

```powershell
terraform init
terraform fmt -check
terraform validate
terraform plan -var="bucket_name=your-globally-unique-test-bucket" -var="vpc_id=vpc-xxxxxxxx"
```

Only apply after reviewing the plan and confirming cost, account, and region. The sample creates AWS resources and may incur charges. Destroy lab resources when no longer needed, after checking dependencies and retaining anything important.
