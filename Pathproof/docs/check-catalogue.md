# Check catalogue

CIS references use AWS Foundations v3.0.0. Each ID denotes evidence contributing to the named control within the assessed scope. Project-only controls carry no numeric mapping. An unsubstantiated proposed ID must be labeled **unverified**. [AWS versioned crosswalk](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)

| Check | Scope | Severity | CIS v3.0.0 | Remediation |
|---|---|---|---|---|
| IAM01 | Root uses MFA | HIGH | 1.5 | Enable MFA for the root identity. |
| IAM02 | Root has no access key | CRITICAL | 1.4 | Remove any root access keys after reviewing dependencies. |
| IAM03 | Console login is absent or protected by MFA | HIGH | 1.10 | Require MFA for console users. |
| IAM04 | Password minimum is at least 14 | MEDIUM | 1.8 | Set the minimum to at least 14 characters. |
| IAM05 | Password history covers at least 24 passwords | MEDIUM | 1.9 | Set password reuse prevention to 24. |
| IAM06 | Named student lacks unintended trust | HIGH | Project | Remove the unapproved trust grant. |
| IAM07 | Named user lacks self policy-management authority | HIGH | Project | Remove the offending self-management grant. |
| S301 | Account has all four public-access blocks | HIGH | 2.1.4 | Review and enable the account-level blocks. |
| S302 | Bucket has all four public-access blocks | HIGH | 2.1.4 | Review and enable the bucket-level blocks. |
| S303 | Examined bucket policy lacks an anonymous canary read grant | CRITICAL | Project | Remove the isolated public canary statement. |
| S304 | Bucket versioning enabled | MEDIUM | Project | Enable versioning on the assessed bucket. |
| S305 | Bucket access logging configured | LOW | Project | Configure an appropriate access-log destination. |
| EC201 | Group restricts IPv4 SSH and RDP ingress | HIGH | 5.2 | Narrow the offending public IPv4 ingress rule. |
| EC202 | Group restricts IPv6 SSH and RDP ingress | HIGH | 5.3 | Narrow the offending public IPv6 ingress rule. |
| EC203 | Default group has no ingress or egress rules | HIGH | 5.4 | Remove rules from the default group after reviewing dependencies. |
| EC204 | Metadata disabled or IMDSv2 required | HIGH | 5.6 | Require metadata tokens on the instance. |
| EC205 | Regional default EBS encryption enabled | MEDIUM | 2.2.1 | Enable regional default EBS encryption. |
| EC206 | Volume encrypted | MEDIUM | Project | Migrate data to an encrypted volume. |
| CT01 | A trail is actively logging | HIGH | Project | Restore a logging trail. |
| CT02 | Active multi-region management read/write trail | HIGH | 3.1 | Configure an active multi-region trail with management read and write events. |
| CT03 | Log integrity validation enabled | MEDIUM | 3.2 | Enable trail log-file validation. |
| CT04 | Trail uses a KMS key | MEDIUM | 3.5 | Select the intended KMS key for trail encryption. |
| KMS01 | Eligible key rotates automatically | MEDIUM | 3.6 | Enable rotation on the eligible key. |
| KMS02 | Assessed key enabled | MEDIUM | Project | Review dependencies and enable keys designated for use. |
| KMS03 | Assessed key has no pending deletion | HIGH | Project | Review the scheduled deletion and its consumers. |
| RDS01 | Database storage encrypted | HIGH | 2.3.1 | Migrate to encrypted storage. |
| RDS02 | Database public accessibility disabled | HIGH | 2.3.3 | Disable public accessibility after validating connectivity. |
| RDS03 | Automatic minor upgrades enabled | MEDIUM | 2.3.2 | Enable automatic minor-version upgrades. |
| RDS04 | Backup retention at least seven days | MEDIUM | Project | Set the backup retention to at least seven days. |
| RDS05 | Deletion protection enabled | MEDIUM | Project | Enable deletion protection. |

| Scenario | Related ATT&CK behavior | Meaning |
|---|---|---|
| T1 | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from cloud storage, represented by the planted object. |
| T2 | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud accounts, contextual mapping for an unexecuted trust transition. |
| T3 | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | The ID exists. Its exact applicability to a policy-management decision without assigning a role is **unverified**. |
| T4 | [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | Instance metadata, modeled prerequisites only. |
| T5 | [T1685.002](https://attack.mitre.org/techniques/T1685/002/) | Cloud logging impairment. The observed gap has no attribution. |
