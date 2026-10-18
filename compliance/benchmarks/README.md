# MultiCloudSecurity Benchmark Package

## What this package is

This is a **project-specific multi-cloud security benchmark baseline** built
from the uploaded:

1. **CIS Controls v8.1.2**
2. **NIST Cybersecurity Framework (CSF) 2.0**
3. **NIST SP 800-53 Revision 5 / 5.1-derived control data**

The uploaded CIS document is the CIS Controls guide, not a provider-specific
CIS Benchmark. Therefore this package uses CIS **Safeguards** as the CIS
benchmark layer. It does not pretend that CIS Controls v8.1.2 is an AWS,
Azure, Cisco, or Cloudflare product benchmark.

NIST CSF 2.0 provides outcome-oriented Subcategories. NIST SP 800-53
provides more concrete security/privacy controls. The package combines them
into one machine-readable benchmark model.

## Important distinction

These mappings are **MultiCloudSecurity project mappings**, created from the
source documents. They are not an official CIS-to-NIST crosswalk.

The benchmark layer should be used as:

Provider facts
→ normalized common model
→ project benchmark evaluation
→ finding/risk
→ recommendation
→ approved remediation
→ re-scan
→ verification

ML should not directly execute cloud changes.

## Package files

- `cis_controls.py` - CIS Safeguards used by this baseline.
- `nist_csf.py` - selected NIST CSF 2.0 Subcategories.
- `nist_sp_800_53.py` - selected SP 800-53 controls.
- `mappings.py` - the combined benchmark catalogue.
- `benchmark_engine.py` - evaluates normalized resources.
- `README.md` - documentation.

## Initial benchmark dimensions

The baseline covers:

- exposure
- encryption
- privilege
- logging
- network security
- identity security
- configuration security
- remediation/verification
- recovery
- risk governance

## Integration

In `backend/security_pipeline.py`:

```python
from compliance.benchmarks.benchmark_engine import attach_benchmarks

normalized = ...
normalized["findings"] = findings
normalized["risk_score"] = calculate_resource_risk(normalized)
attach_benchmarks(normalized)
```

The benchmark results will appear under:

```json
"benchmarks": [
  {
    "benchmark_id": "MC-001",
    "status": "FAIL",
    "cis": ["CIS-4.1", "CIS-12.2"],
    "nist_csf": ["PR.IR-01", "PR.PS-01"],
    "nist_sp_800_53": ["SC-7", "CM-6"]
  }
]
```

## Why some checks say NOT_EVALUATED

Dimension checks produce `PASS` or `FAIL` only when the normalized resource
lists that dimension in `evaluated_dimensions`. Each normalizer should include
only dimensions supported by complete provider evidence. Missing, malformed,
or out-of-range values stay `NOT_EVALUATED`. Any measured weakness above zero
fails the dimension check.

Checks that need a distinct fact use `benchmark_evidence`, keyed by benchmark
ID. For example, `MC-003` needs explicit transport-security evidence and
`MC-007` needs explicit evidence that logs support investigation; neither can
be inferred from the general encryption or logging score.

A benchmark such as recovery integrity cannot honestly be inferred from a
single normalized risk dimension. Those checks need provider evidence and/or
a remediation verification record. They are left as `NOT_EVALUATED` rather
than inventing a pass/fail result.

## Provider-specific CIS Benchmarks

If later you obtain provider-specific CIS Benchmark PDFs (for example an AWS
Foundations benchmark), add them as a separate layer. Do not replace these
CIS Controls mappings. A future structure can be:

`CIS Controls -> NIST CSF -> NIST SP 800-53 -> provider CIS Benchmark`

This keeps the framework roles clear.
