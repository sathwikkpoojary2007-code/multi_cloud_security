"""CIS Controls v8.1.2 references used by the MultiCloudSecurity benchmark."""

CIS_CONTROLS = {
    "CIS-3.10": {
        "title": "Encrypt Sensitive Data in Transit",
        "control": 3,
        "implementation_group": "IG1+",
    },
    "CIS-3.11": {
        "title": "Encrypt Sensitive Data at Rest",
        "control": 3,
        "implementation_group": "IG1+",
    },
    "CIS-4.1": {
        "title": "Establish and Maintain a Secure Configuration Process",
        "control": 4,
        "implementation_group": "IG1+",
    },
    "CIS-4.2": {
        "title": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
        "control": 4,
        "implementation_group": "IG1+",
    },
    "CIS-4.6": {
        "title": "Securely Manage Enterprise Assets and Software",
        "control": 4,
        "implementation_group": "IG1+",
    },
    "CIS-5.1": {
        "title": "Establish and Maintain an Inventory of Accounts",
        "control": 5,
        "implementation_group": "IG1+",
    },
    "CIS-6.1": {
        "title": "Establish an Access Granting Process",
        "control": 6,
        "implementation_group": "IG1+",
    },
    "CIS-6.3": {
        "title": "Require MFA for Externally-Exposed Applications",
        "control": 6,
        "implementation_group": "IG1+",
    },
    "CIS-7.2": {
        "title": "Establish and Maintain a Remediation Process",
        "control": 7,
        "implementation_group": "IG1+",
    },
    "CIS-7.6": {
        "title": "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
        "control": 7,
        "implementation_group": "IG2+",
    },
    "CIS-7.7": {
        "title": "Remediate Detected Vulnerabilities",
        "control": 7,
        "implementation_group": "IG2+",
    },
    "CIS-8.1": {
        "title": "Establish and Maintain an Audit Log Management Process",
        "control": 8,
        "implementation_group": "IG1+",
    },
    "CIS-8.2": {
        "title": "Collect Audit Logs",
        "control": 8,
        "implementation_group": "IG1+",
    },
    "CIS-8.5": {
        "title": "Collect Detailed Audit Logs",
        "control": 8,
        "implementation_group": "IG2+",
    },
    "CIS-8.9": {
        "title": "Centralize Audit Logs",
        "control": 8,
        "implementation_group": "IG2+",
    },
    "CIS-8.10": {
        "title": "Retain Audit Logs",
        "control": 8,
        "implementation_group": "IG2+",
    },
    "CIS-8.11": {
        "title": "Conduct Audit Log Reviews",
        "control": 8,
        "implementation_group": "IG2+",
    },
    "CIS-11.4": {
        "title": "Establish and Maintain an Isolated Instance of Recovery Data",
        "control": 11,
        "implementation_group": "IG1+",
    },
    "CIS-11.5": {
        "title": "Test Data Recovery",
        "control": 11,
        "implementation_group": "IG2+",
    },
    "CIS-12.2": {
        "title": "Establish and Maintain a Secure Network Architecture",
        "control": 12,
        "implementation_group": "IG2+",
    },
    "CIS-12.3": {
        "title": "Securely Manage Network Infrastructure",
        "control": 12,
        "implementation_group": "IG1+",
    },
    "CIS-12.5": {
        "title": "Centralize Network Authentication, Authorization, and Auditing (AAA)",
        "control": 12,
        "implementation_group": "IG2+",
    },
    "CIS-13.1": {
        "title": "Centralize Security Event Alerting",
        "control": 13,
        "implementation_group": "IG2+",
    },
    "CIS-13.6": {
        "title": "Collect Network Traffic Flow Logs",
        "control": 13,
        "implementation_group": "IG2+",
    },
}

def get_cis(control_id):
    return CIS_CONTROLS[control_id]
