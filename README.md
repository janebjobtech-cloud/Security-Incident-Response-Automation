# Security-Incident-Response-Automation
Automated, event-driven AWS security incident response system using Python Lambda functions — detects, investigates, contains, and notifies on unauthorized access, unusual API activity, and S3 misconfigurations in under 20 minutes.
# 🛡️ Security Incident Response Automation
### CLCS 660 — AI-Based Cloud Automation and Scripting | Unit 7 Lab

> An event-driven, serverless security automation system built on AWS that reduces incident response time from **4–6 hours** to **under 20 minutes** using Python, Lambda, and cloud-native services.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Components](#system-components)
- [Detection Logic & Thresholds](#detection-logic--thresholds)
- [Project Structure](#project-structure)
- [Lambda Functions](#lambda-functions)
  - [Common Utilities](#a1-common-utilities)
  - [Detection: Unauthorized Access](#a2-detection--unauthorized-access)
  - [Detection: Unusual API Activity](#a3-detection--unusual-api-activity)
  - [Detection: S3 Misconfiguration](#a4-detection--s3-misconfiguration)
  - [Investigation Workflow](#a5-investigation-workflow)
  - [Containment Workflow](#a6-containment-workflow)
  - [Notification Handler](#a7-notification-handler)
- [Incident Response Playbooks](#incident-response-playbooks)
- [Deployment Overview](#deployment-overview)
- [Testing & Validation](#testing--validation)
- [Results](#results)
- [Future Enhancements](#future-enhancements)
- [References](#references)

---

## Overview

This lab implements a fully automated cloud security incident response system for a simulated financial services company. The system replaces slow, manual processes with a serverless, event-driven pipeline that detects, investigates, contains, and notifies on three high-priority incident types:

| Incident Type | Before Automation | After Automation |
|---|---|---|
| Unauthorized Access | 4–6 hours | < 20 minutes |
| Unusual API Activity | 4–6 hours | < 20 minutes |
| S3 Misconfiguration | 4–6 hours | < 20 minutes |

**Key technologies used:**
`Python 3.11` · `AWS Lambda` · `CloudTrail` · `AWS Config` · `Amazon SNS` · `EventBridge` · `IAM` · `S3` · `EC2` · `CloudWatch Logs`

---

## Architecture

The system follows a **modular, event-driven architecture** with four logical layers that move from detection through to notification:

```
CloudTrail Logs
      │
      ▼
┌─────────────────────┐
│   Detection Layer   │  ← Lambda + CloudWatch Logs + EventBridge + AWS Config
│  (3 Lambda Functions)│
└────────┬────────────┘
         │ Incident Event
         ▼
┌─────────────────────┐
│ Investigation Layer │  ← Lambda: collects user context, logs, metadata
│  (1 Lambda Function) │
└────────┬────────────┘
         │ Investigation Result
         ▼
┌─────────────────────┐
│ Containment Layer   │  ← Lambda: disables users, quarantines instances, blocks access
│  (1 Lambda Function) │
└────────┬────────────┘
         │ Actions Taken
         ▼
┌─────────────────────┐
│ Notification Layer  │  ← SNS: structured alert to security team
│  (SNS + Lambda)     │
└─────────────────────┘
```

> 📊 **Full LucidChart Architecture Diagram:**
> [View Interactive Diagram →](https://lucid.app/lucidchart/17340795-6220-4db8-a07f9c00af9cd871/edit?viewport_loc=226%2C779%2C2462%2C1401%2C0_0&invitationId=inv_632d8752-9e4c-4821-8830-eefbb1c8546e)

**Deployment Region:** `us-east-1`
**Runtime:** All Lambda functions use `Python 3.11`
**IAM Model:** Shared execution role with least-privilege permissions per service

---

## System Components

### Detection Layer
Identifies security events using three trigger mechanisms:

| Trigger | Mechanism | Target |
|---|---|---|
| Failed console logins | CloudWatch Logs subscription filter | `detect_unauthorized_access.py` |
| Sensitive API calls | EventBridge schedule (every 5 min) | `detect_unusual_api_activity.py` |
| S3 compliance violations | EventBridge rule on AWS Config change | `detect_public_s3_buckets.py` |

### Investigation Layer
Automatically gathers contextual evidence when an incident fires:
- User identity and IAM permission snapshot
- Last 30 minutes of CloudTrail activity
- Resource metadata (EC2, S3, etc.)
- Network traffic and event timeline
- CloudTrail log copy to forensic S3 bucket

### Containment Layer
Executes targeted remediation based on incident type:
- **Unauthorized Access** → Disable IAM user, force password reset
- **Unusual API Activity** → Restrict IAM role, quarantine EC2 instance, block suspicious IP
- **Misconfiguration** → Apply S3 Block Public Access, remove public ACLs

### Notification Layer
Amazon SNS delivers structured alerts including:
- Incident type and severity
- Investigation findings
- Containment actions taken
- Recommended next steps

High-severity incidents route to the on-call engineer. Lower-severity events queue to the security operations team.

---

## Detection Logic & Thresholds

| Incident Type | Detection Logic | Threshold | Automated Response |
|---|---|---|---|
| Unauthorized Access | Failed logins + geolocation anomalies | ≥ 5 failures in 10 minutes | Trigger investigation → disable user |
| Unusual API Activity | Sensitive APIs from new IPs or mass deletions | > 20 delete calls in 5 minutes | Flag potential compromise → restrict role |
| S3 Misconfiguration | Public bucket ACL or bucket policy | Any violation detected | Auto-revert to secure configuration |

---

## Project Structure

```
security-incident-response/
│
├── common_utils.py                   # Shared helpers: SNS, snapshots, CloudTrail queries
│
├── detection/
│   ├── detect_unauthorized_access.py # CloudWatch Logs trigger — failed logins
│   ├── detect_unusual_api_activity.py# EventBridge schedule — sensitive API calls
│   └── detect_public_s3_buckets.py   # AWS Config trigger — public bucket detection
│
├── workflows/
│   ├── investigation_workflow.py     # Collects evidence, user context, logs
│   └── containment_workflow.py       # Executes remediation actions
│
├── notification/
│   └── notification_handler.py       # Generic SNS notification dispatcher
│
└── playbooks/
    ├── playbook_unauthorized_access.md
    ├── playbook_unusual_api_activity.md
    └── playbook_s3_misconfiguration.md
```

---

## Lambda Functions

### A.1 Common Utilities
**File:** `common_utils.py`

Shared module imported by all Lambda functions. Initializes boto3 clients and provides reusable helpers.

**Key functions:**

| Function | Purpose |
|---|---|
| `publish_notification(message)` | Publishes structured incident data to SNS |
| `snapshot_instance(instance_id)` | Creates a forensic EC2 EBS snapshot |
| `get_root_volume_id(instance_id)` | Resolves root volume for snapshotting |
| `copy_cloudtrail_logs(start, end)` | Copies log range to forensic S3 bucket |
| `get_recent_user_activity(user, min)` | Queries CloudTrail for recent user events |
| `get_user_policies(username)` | Returns attached and inline IAM policies |

**Environment Variables required at runtime:**

```bash
SNS_TOPIC_ARN       = arn:aws:sns:us-east-1:<account-id>:SecurityIncidents
QUARANTINE_SG_ID    = sg-0<your-quarantine-sg-id>
FORENSIC_BUCKET     = <your-forensic-s3-bucket-name>
```

---

### A.2 Detection — Unauthorized Access
**File:** `detect_unauthorized_access.py`
**Trigger:** CloudWatch Logs subscription filter on CloudTrail `ConsoleLogin` events

**Logic:**
1. Receives `ConsoleLogin` records from CloudWatch
2. Filters for `Failure` responses
3. Calls `is_threshold_exceeded()` — queries CloudTrail for ≥ 5 failed logins in 10 minutes
4. If threshold is met → builds incident payload → publishes to SNS

**Configurable constants:**
```python
FAILED_THRESHOLD = 5    # Number of failures before alerting
WINDOW_MINUTES   = 10   # Lookback window in minutes
```

---

### A.3 Detection — Unusual API Activity
**File:** `detect_unusual_api_activity.py`
**Trigger:** EventBridge schedule rule — runs every 5 minutes

**Logic:**
1. Queries CloudTrail for the past 5 minutes of events
2. Flags any call to a sensitive API from a new/unknown IP address
3. Counts all delete-type operations; alerts if count exceeds threshold
4. Publishes separate incidents for sensitive API misuse vs. mass deletion

**Monitored APIs:**
```python
SENSITIVE_APIS = [
    "DeleteBucket", "DeleteObject",
    "TerminateInstances",
    "PutUserPolicy", "AttachUserPolicy"
]
```

**Configurable constants:**
```python
MASS_DELETE_THRESHOLD = 20   # Delete operations before alerting
WINDOW_MINUTES        = 5    # Lookback window in minutes
```

> **Note:** `is_new_ip_for_user()` is scaffolded to return `True` for all IPs. In production, wire this to a DynamoDB table tracking known-good IPs per user.

---

### A.4 Detection — S3 Misconfiguration
**File:** `detect_public_s3_buckets.py`
**Trigger:** AWS Config compliance change rule (EventBridge) or scheduled scan

**Logic:**
1. Lists all S3 buckets in the account
2. Checks each bucket's ACL for `AllUsers` or `AuthenticatedUsers` grants
3. Builds and publishes an incident for any publicly accessible bucket

---

### A.5 Investigation Workflow
**File:** `investigation_workflow.py`
**Trigger:** Invoked by detection functions via EventBridge or direct Lambda invocation

**Collects:**
- User IAM policies (attached and inline)
- Last 30 minutes of the user's CloudTrail activity
- Resource metadata (EC2 instance state, launch time, tags)
- Forensic CloudTrail log copy path in S3

**Output:** Publishes a structured investigation result notification to SNS with full context for the security analyst.

---

### A.6 Containment Workflow
**File:** `containment_workflow.py`
**Trigger:** Invoked after investigation completes

**Actions by incident type:**

| Incident Type | Containment Action |
|---|---|
| Unauthorized Access | `disable_user()` → forces password reset via IAM |
| Unusual API Activity | `quarantine_instance()` → reassigns EC2 to quarantine SG + creates forensic snapshot |
| S3 Misconfiguration | `remove_public_access()` → applies S3 Block Public Access on all four controls |

**Publishes:** Containment phase notification to SNS listing every action taken.

---

### A.7 Notification Handler
**File:** `notification_handler.py`
**Trigger:** EventBridge routing rule for all incident phases

A generic dispatcher that formats and forwards any phase event (Detection, Investigation, Containment) as a structured SNS alert. Serves as the centralized notification relay when using EventBridge to route across all Lambda stages.

---

## Incident Response Playbooks

### Playbook 1 — Unauthorized Access Attempts

| Step | Action |
|---|---|
| 1. Detection Trigger | ≥ 5 failed logins in 10 min OR login from unusual IP |
| 2. Investigation | Collect user identity, IAM permissions, source IP, MFA status, 30-min CloudTrail history |
| 3. Containment | Disable IAM login, revoke sessions, force password reset, apply temporary deny-all policy |
| 4. Evidence | Copy CloudTrail logs to forensic bucket; record timestamps, IPs, event IDs |
| 5. Notification | SNS alert: user, source IP, containment status, recommended remediation |
| 6. Escalation | Repeated attempts → escalate to Tier 2 security analyst |

---

### Playbook 2 — Unusual API Activity

| Step | Action |
|---|---|
| 1. Detection Trigger | Sensitive API from new IP OR ≥ 20 delete ops in 5 minutes |
| 2. Investigation | Identify user/role, retrieve CloudTrail events, check IP history, review IAM trust |
| 3. Containment | Restrict IAM role permissions, block suspicious IP via NACL/SG, pause destructive ops |
| 4. Evidence | Copy CloudTrail logs, capture IAM role policy state, save API event payload |
| 5. Notification | SNS alert: API call, user/role, IP address, containment actions |
| 6. Escalation | Continued destructive activity → disable IAM role entirely |

---

### Playbook 3 — Public S3 Bucket Misconfiguration

| Step | Action |
|---|---|
| 1. Detection Trigger | AWS Config rule violation OR Lambda detects public ACL/bucket policy |
| 2. Investigation | Retrieve bucket ACL and policy, identify last modifier, review CloudTrail for policy changes |
| 3. Containment | Apply S3 Block Public Access (all 4 controls), remove public ACLs, revert to secure baseline |
| 4. Evidence | Save previous bucket policy to forensic S3 bucket; record responsible user |
| 5. Notification | SNS alert: bucket name, misconfiguration details, containment status |
| 6. Escalation | If sensitive data was exposed → initiate data breach protocol |

---

## Deployment Overview

All six Lambda functions are deployed in `us-east-1` as independent Python 3.11 runtime containers with a **shared IAM execution role** scoped to least-privilege access across:

`CloudTrail` · `IAM` · `EC2` · `S3` · `SNS` · `CloudWatch Logs`

**Sensitive identifiers are injected as environment variables at runtime** — they are never hardcoded in the source:

```
SNS_TOPIC_ARN     → SNS topic for all incident alerts
FORENSIC_BUCKET   → S3 bucket for evidence storage
QUARANTINE_SG_ID  → Security group for EC2 isolation
```

This model means:
- **Zero infrastructure to manage** — fully serverless
- **Cost-efficient** — billed only on execution
- **Auto-scaling** — scales with AWS natively
- **No patching required**

---

## Testing & Validation

Each incident type was tested by simulating real-world attack scenarios:

| Test Scenario | Method |
|---|---|
| Unauthorized Access | Repeated failed console logins against a test IAM user |
| Unusual API Activity | Scripted sensitive API calls from a new IP address |
| S3 Misconfiguration | Intentional public ACL applied to a test bucket |

**Validation artifacts captured (see Appendix):**
- Lambda execution logs (CloudWatch)
- CloudTrail event matches
- S3 bucket policy before/after changes
- SNS notification delivery receipts

---

## Results

| Phase | Measured Time |
|---|---|
| Detection | 2–5 minutes |
| Investigation | ≤ 10 minutes |
| Containment | ≤ 5 minutes |
| **Total Response Time** | **< 20 minutes** |

**Improvement over manual process:** ~93% reduction in response time (from 4–6 hours to under 20 minutes).

---

## Future Enhancements

- [ ] **ML-based anomaly detection** — replace static thresholds with behavioral baselines per user/role
- [ ] **Known-IP tracking with DynamoDB** — make `is_new_ip_for_user()` production-ready
- [ ] **Multi-cloud integration** — extend detection and containment to Azure and GCP
- [ ] **SOAR platform adoption** — integrate with Splunk SOAR or Palo Alto XSOAR for full orchestration
- [ ] **Automated runbook execution** — close the loop on escalation with ticketing system integration (e.g., Jira, ServiceNow)

---

## References

- Gartner. (2023). *Market guide for security orchestration, automation and response solutions.* https://www.gartner.com/en/documents/security-orchestration-automation-response
- IBM Security. (2023). *Cost of a data breach report 2023.* https://www.ibm.com/reports/data-breach
- NIST. (2021). *SP 800-61 Rev. 2: Computer security incident handling guide.* https://doi.org/10.6028/NIST.SP.800-61r2
- Gogolin, G. (2021). Digital forensics tool kit. In *Digital forensics explained* (pp. 39–54). CRC Press. https://doi.org/10.1201/9781003049357-3
- Kharb, L., & Chahal, D. (2023). Cloud access security brokers: Strengthening cloud security. *International Journal of Research Publication and Reviews, 4*(8), 642–644. https://doi.org/10.55248/gengpi.4.823.50412
- Mujahid, B. (2023). *Cloud forensics: Investigating security incidents in cloud environments.* OSF Preprints. https://doi.org/10.31219/osf.io/4ty6u

---

<div align="center">

**CLCS 660 — AI-Based Cloud Automation and Scripting**
University of Maryland Global Campus · Unit 7 Lab Assignment
Student: Jane Buro · Submitted: April 28, 2026

</div>
