# AWS Cloud Security Scanner

A beginner-friendly, **read-only** AWS configuration assessment project built with Python, Boto3, and Streamlit. It is designed as a portfolio project for cloud-security fundamentals: discover risky configurations, explain evidence, prioritize findings, and export reports.

## What it checks

| Area | Checks |
|---|---|
| Amazon S3 | Bucket-level Block Public Access, public bucket-policy status, public ACL grants, explicit encryption configuration, versioning, server access logging |
| AWS IAM | Root MFA, root access-key presence, obvious `Action: "*"` + `Resource: "*"` policies, service-wide wildcards such as `ec2:*` on `*` |
| VPC / EC2 | Security-group inbound rules open to `0.0.0.0/0` or `::/0`; unencrypted EBS volumes |
| Amazon RDS | Publicly accessible DB instances and storage encryption status |
| AWS CloudTrail | Presence of a multi-region trail, logging status, log-file validation |

The scanner creates JSON and CSV reports and includes a small unit-test suite for the detection rules.

## Safety and scope

- The scanner uses AWS read/list/describe APIs only. It does **not** create, modify, or delete AWS resources.
- It does not read S3 object contents, download secrets, exploit vulnerabilities, scan public IP ranges, or run commands on instances.
- Give it a dedicated read-only identity. Never run it with root credentials or an administrator profile.
- Findings are configuration signals, not proof that a resource is exploitable. Validate each finding in context.
- Access-denied and other failed checks are recorded as diagnostics. A scan with skipped checks is incomplete, not a clean result.
- The IAM policy detector is intentionally a simple rule-based indicator, not a complete IAM policy simulator or privilege-escalation analyzer.

## Windows setup (PowerShell)

### 1. Prerequisites

Install:
- Python 3.11 or newer
- AWS CLI v2
- Git (optional, for cloning/publishing)
- `uv` (recommended) or Python's `venv` and `pip`

Check installations:

```powershell
python --version
aws --version
uv --version
```

### 2. Create and install the Python environment

From the project directory:

```powershell
uv venv
.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
```

If PowerShell blocks activation, use the environment without activating it:

```powershell
uv run --with-requirements requirements.txt streamlit run app.py
```

Alternatively, use standard Python:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Create a dedicated AWS read-only identity

In your AWS lab account, create a dedicated IAM role or IAM user for this scanner and attach the policy in `policies/readonly-scanner-policy.json` as a customer-managed policy. The policy grants only the discovery and configuration-read actions used by the project. Review it against your organization's access policy before attaching it.

Prefer AWS IAM Identity Center / SSO for human use. Avoid long-lived access keys where possible. If your lab setup requires an IAM user's access keys, create them only for this dedicated read-only user, store them using the AWS CLI credential store, and never paste them into source code or commit them to Git.

### 4. Configure AWS CLI credentials

**Preferred: SSO profile** (your organization must have IAM Identity Center configured):

```powershell
aws configure sso --profile cloudsec-readonly
aws sso login --profile cloudsec-readonly
aws sts get-caller-identity --profile cloudsec-readonly
```

**Lab alternative: dedicated read-only access-key profile**:

```powershell
aws configure --profile cloudsec-readonly
aws sts get-caller-identity --profile cloudsec-readonly
```

Confirm the returned account ID is the intended test account. Never use root credentials.

### 5. Run the Streamlit dashboard

```powershell
.venv\Scripts\Activate.ps1
$env:AWS_PROFILE = "cloudsec-readonly"
streamlit run app.py
```

Open the local URL printed by Streamlit, normally `http://localhost:8501`. In the sidebar, use profile `cloudsec-readonly` and enter one or more regions, for example `us-east-1,us-west-2`. Click **Run security scan**.

You can also leave the profile field blank to use the default AWS credential chain.

### 6. Run from the command line

```powershell
python -m cloudsec_scanner.cli --profile cloudsec-readonly --regions us-east-1,us-west-2
```

Reports are written to the `reports` folder. To select a different output directory:

```powershell
python -m cloudsec_scanner.cli --profile cloudsec-readonly --regions ap-south-1 --output-dir output
```

### 7. Run tests without AWS credentials

```powershell
python -m pytest -q
```

The unit tests exercise the local detection rules and do not connect to AWS.

## Troubleshooting

- **Profile not found:** run `aws configure list-profiles` and check the profile name in the dashboard.
- **SSO token expired:** run `aws sso login --profile cloudsec-readonly` again.
- **AccessDenied:** confirm the dedicated identity has the policy in `policies/readonly-scanner-policy.json`. The dashboard lists checks that were skipped or incomplete.
- **No findings:** this is not a certification that the account is secure. Confirm the selected account, requested regions, identity, and diagnostics.
- **PowerShell activation is blocked:** use `uv run --with-requirements requirements.txt streamlit run app.py`, or use Command Prompt activation `\.venv\Scripts\activate.bat`.
- **Streamlit command not found:** activate `.venv` and reinstall requirements.

## Detection limitations / sensible next steps

1. S3 encryption check looks for an explicit bucket encryption configuration. S3 encrypts new objects by default with SSE-S3; absence of an explicit configuration is therefore a low-severity policy/configuration reminder, not proof that objects are stored unencrypted.
2. S3 ACL and policy checks do not fully model every account-level organization control or every possible access path.
3. IAM wildcard checks detect obvious patterns; they do not evaluate conditions, trust policies, permission boundaries, SCPs, session policies, or all privilege-escalation paths.
4. CloudTrail discovery is performed from the first selected region and does not independently validate an AWS Organizations organization trail or every log delivery destination.
5. Regional scans are limited to the regions the operator enters.
6. This is a learning/portfolio scanner, not a replacement for AWS Security Hub, AWS Config, GuardDuty, a CSPM platform, or a formal audit.

Useful extensions for a second version: AWS Config integration, Security Hub findings ingestion, Terraform scanning with Checkov, organization-wide role assumption, richer IAM analysis, and ticket creation for remediation workflows. An optional `terraform/secure-baseline/` folder demonstrates secure-by-default S3 and security-group configuration; it is a reference example, not part of the live scanner.

## Mapping to the Consultadd Associate Cybersecurity Engineer JD

- **Cloud security:** checks for public S3 configuration, over-broad IAM permissions, open security-group ingress, and encryption gaps.
- **Automation:** Python, Boto3, and CLI/dashboard workflows automate repetitive configuration reviews.
- **Data protection / audit:** checks selected encryption settings and CloudTrail coverage.
- **Security reporting:** severity-ranked findings, evidence, remediation advice, and JSON/CSV exports.

This project complements, but does not replace, practical labs in Microsoft Sentinel/Defender, Active Directory/Entra ID, vulnerability management, and server hardening that are also mentioned in the JD.
