# MultiCloudSecurity

For a friend-friendly end-to-end explanation, folder map, methodology, and
flowchart images, see [the project walkthrough](docs/project_walkthrough.md).

MultiCloudSecurity is a multi-page cloud security workspace for AWS S3,
Azure Storage, Cisco Meraki, and Cloudflare. It collects provider configuration,
normalizes evidence, evaluates security rules and project benchmarks, ranks
risk, and tracks reviewed remediation through a fresh scan and verification.

## Workflow

```text
Provider APIs / local demo snapshots
                 ↓
  Multi-provider read-only collection
                 ↓
         Raw JSON snapshots
                 ↓
     Provider normalizers + evidence
                 ↓
 Findings + weighted risk + ML triage
                 ↓
 CIS/NIST project benchmark evaluation
                 ↓
      Multi-page security dashboard
                 ↓
 Admin approval + WebAuthn passkey
                 ↓
      Apply supported cloud fix
                 ↓
       Collect again + verify
```

## Install and start

Use Python 3.10 or later. In PowerShell, from this project directory:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m ml.train_model
python -m dashboard.admin create-admin
python -m dashboard.app
```

On Windows, after installing dependencies and creating the admin account, you
can start the local dashboard by double-clicking `host.bat`. It checks the
dashboard dependencies, installs `requirements.txt` if they are missing, starts
the complete multi-page project, waits for the server, then opens the browser.
The Cloud Security Assistant is part of the dashboard app, so it starts with the
project and does not need a separate service. Keep the **MultiCloudSecurity
Server** window open while using the app. The host is available on this computer
at `http://localhost:8000`; this launcher does not publish the app to the public
internet.

On desktop browsers, a soft cursor-following glow adds motion to the dashboard.
It is disabled on touch screens and when reduced motion is enabled.

Open <http://localhost:8000> and sign in with the admin account you created.
The first administrator is provisioned from the terminal; public sign-up is
disabled. Admins can create viewer, operator, and additional admin accounts in
Settings, and enroll a Windows Hello passkey for approving fixes.

For convenience the dashboard defaults to localhost. To run on another
interface, configure a strong persistent `FLASK_SECRET_KEY` and `MCS_HOST`.
For production, set `COOKIE_SECURE=1` and serve behind HTTPS. The app uses
Waitress, Argon2 password hashes, CSRF-protected forms and API requests, login
lockout, role checks, and a local audit log. Keep the SQLite database and
reports on a protected volume and back them up.

## Evaluator demo portfolio

Sign in as an admin, open **Cloud Resources**, and select **Load evaluator demo
portfolio**. It adds 88 fictional assets across Northstar Commerce, Asterion
Health Systems, Meridian Financial Group, and Cinder Cloud Services: 48 S3
buckets, 24 Azure storage accounts, 12 Meraki networks, and four Cloudflare
accounts with 16 zones. The inventory includes varied security states, risk,
ownership, data classification, and synthetic scale indicators.

Demo resources are marked `DEMO`, read only, and never call provider APIs. Use
**Remove demo data** when you want to show only the latest live scan.

## Live scans and multiple buckets

Select one or more providers with **Scan resources**. A scan reads all
resources visible to the configured API identity and updates the live
inventory. AWS paginates bucket results, Azure lists storage accounts, Meraki
lists organizations and networks, and Cloudflare lists accounts and zones. An
optional browser-tab setting repeats the selected scan every five minutes
while that tab stays open. This is polling, not an event-driven real-time feed.

On **Service Connections**, save credentials and use **Save & test** to check
API access. Secrets are encrypted in the local data directory. Each service
card has a **Login to…** button that opens its official portal in a new tab.
The app does not collect cloud-console passwords; it uses provider APIs.

### Connect real AWS S3 buckets

AWS is discovered from the authenticated account; there is no per-bucket API
address to enter. The AWS connection form supports static credentials, the
machine's standard AWS profile/environment/role credential chain, and an
optional cross-account role ARN. For cross-account access, configure the
target account role trust policy to trust the app's base AWS identity and
grant that role the permissions below. An External ID can be used when the
trust policy requires one. Click **Save & test**: the result reports the AWS
account identity and how many buckets had both security settings readable. Then choose AWS under
**Scan resources**.

Read-only discovery and posture checks need `s3:ListAllMyBuckets`,
`s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`, and
`s3:GetEncryptionConfiguration` on the account/buckets. The supported live
fix additionally needs `s3:PutBucketPublicAccessBlock` on the target bucket.
Keep those write permissions out of scan-only identities. Bucket-level
AccessDenied errors can mean the identity lists a bucket but cannot inspect
its settings; the scan records those fields as unevaluated rather than treating
them as secure.

### Connect the other live services

- **Azure Storage:** enter the subscription ID and a service principal's tenant,
  client ID, and secret. Alternatively, leave all three identity fields blank
  and configure `DefaultAzureCredential` on the app host. Assign Azure Reader
  to scan; the supported hardening fix needs Storage Account Contributor on the
  affected storage accounts. The connection test reports the subscription and
  the number of storage accounts read.
- **Cisco Meraki:** enter a Dashboard API key whose role can list organizations
  and networks and read appliance firewall rules. The supported fix changes
  broad allow rules to deny, so the identity also needs firewall-rule update
  rights. The connection test reports network discovery and how many networks'
  firewall settings were readable.
- **Cloudflare:** enter an API token scoped to the relevant accounts and zones.
  Scanning needs account/zone and ruleset read access; the supported managed WAF
  fix needs zone ruleset edit access. The connection test reports discovered
  accounts/zones and flags zones whose WAF/ruleset details could not be read.

All four providers use **Save & test** before scanning. A successful credential
save only means the app has a credential; the test checks actual API access.
Live fixes are limited to the reviewed actions shown in Remediation and still
require administrator approval. They do not automatically fix every finding.

Credential sources when no saved connection is configured:

- AWS: the standard boto3 credential chain (`AWS_PROFILE`, environment, or IAM
  role). The scanner needs list and read access to S3 bucket security settings.
- Azure: `AZURE_SUBSCRIPTION_ID` and an identity available to
  `DefaultAzureCredential`.
- Cisco Meraki: `MERAKI_DASHBOARD_API_KEY`.
- Cloudflare: `CLOUDFLARE_API_TOKEN`.

Provider collection can also run from PowerShell:

```powershell
python -m connectors.collect aws
python -m connectors.collect cisco azure cloudflare
python -m connectors.collect all
python -m backend.security_pipeline
```

Scanning uses read-only provider requests. Provider permissions and API quotas
still apply.

## Manual and AI-assisted remediation

For each supported finding, an admin chooses **Manual change** or
**AI-assisted auto-fix**. Both require impact review, explicit confirmation,
and Windows Hello approval. The app rescans the provider after a change. The
trained model prioritizes risk; reviewed provider-specific actions perform the
actual updates. The model does not generate arbitrary cloud changes or approve
them on its own.

Automatic fixes cover S3 public-access blocking, Azure storage network and
transport hardening, changing Meraki any-any allow rules to deny, and deploying
Cloudflare Managed WAF to uncovered active zones. Manual editors expose S3
public-access controls, Azure network/blob/HTTPS/TLS settings, ordered Meraki
firewall rules, and per-zone Cloudflare Managed WAF settings. Meraki changes
are rejected if live rules changed since the latest scan.

Passkey setup requires localhost or HTTPS. For a non-local deployment, set
`WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` to the deployed HTTPS host. Provider
write permissions are required for live changes. Requests and outcomes are
written to the local audit database. Biometric data and private passkey keys
stay on the device; the app stores only public keys and credential metadata.
Review the displayed impact before approving changes that can interrupt access.

## Machine learning

`ml/model.json` contains a Gaussian Naive Bayes posture triage model trained
from reproducible simulated resource configurations. `python -m ml.train_model`
regenerates it and writes a held-out synthetic evaluation to
`ml/evaluation.json`. Its features are the seven normalized posture dimensions;
it does not consume the rule engine's finding count, risk score, or benchmark
outcomes. It scores the same collected posture evidence through a separate
learned classifier; it is not an independent sensor and cannot discover
configuration the connectors did not collect. Detector rules and benchmark
mappings still run separately and are shown with ML triage in the dashboard.

The held-out score measures agreement with the synthetic scenario generator,
not accuracy on real cloud accounts. It cannot support a 95% real-world claim.
Unknown evidence remains unknown, and ML cannot authorize or verify a fix. To
incorporate analyst-reviewed labels, copy `ml/reviewed_labels_template.csv`,
add reviewed rows with values from 0 to 1, and run:

```powershell
python -m ml.train_model --reviewed-csv path\to\reviewed_labels.csv
```

Each retraining run uses a deterministic held-out synthetic set and reports its
metrics. Reviewed labels are included in training only; do not treat synthetic
holdout performance as a validation score for the reviewed data. Collect a
separate, account-disjoint labeled evaluation set before production claims or
automatic ML-driven actions. The app's periodic scan is polling, not event
streaming; live scanning requires provider credentials and read permissions.

## Pages

- **Dashboard** - posture cards, provider risk, resource state, recent findings.
- **Cloud Resources** - searchable inventory and per-resource details.
- **Security Findings** - severity, recommendations, and review links.
- **Risk Analysis** - weighted risk and evidence coverage by provider.
- **Remediation** - proposed actions, approval flow, and audit events.
- **Compliance** - benchmark status and CIS/NIST references.
- **Machine Learning** - model information and triage predictions.
- **Reports** - readable HTML reports, plain-text downloads, printable PDF output,
  and separately labeled JSON data exports.
- **Service Connections** - encrypted API credentials and direct links to each provider portal.
- **Settings** - account roles, scan jobs, and local audit history.

The CIS and NIST references are MultiCloudSecurity project mappings, not an
official CIS/NIST crosswalk or provider-specific CIS Benchmark.

## Main folders

- `connectors/` - provider collection and scan command.
- `normalizer/` - provider-to-common-model conversion and evidence tracking.
- `security/` - provider rules and weighted risk scoring.
- `compliance/benchmarks/` - benchmark definitions and evaluator.
- `ml/` - trained risk triage model.
- `remediation/` and `verification/` - recommendation, approved fix, and
  verification workflow.
- `backend/security_pipeline.py` - snapshot analysis and report generation.
- `dashboard/` - authenticated multi-page web app.
- `examples/demo_portfolio.py` - deterministic enterprise demo inventory generator.
