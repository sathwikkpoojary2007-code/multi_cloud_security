"""NIST SP 800-53 Revision 5/5.1 control references.

These are the controls most directly useful for this project's posture checks,
configuration drift detection, logging, access, network protection, recovery,
and remediation workflow.
"""

NIST_SP_800_53 = {
    "AC-3": "Access Enforcement",
    "AC-6": "Least Privilege",
    "AU-2": "Event Logging",
    "AU-3": "Content of Audit Records",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "AU-12": "Audit Record Generation",
    "CM-2": "Baseline Configuration",
    "CM-3": "Configuration Change Control",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission and Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-4": "System Monitoring",
    "IR-4": "Incident Handling",
    "CP-10": "System Recovery and Reconstitution",
}

def get_sp(control_id):
    return NIST_SP_800_53[control_id]
