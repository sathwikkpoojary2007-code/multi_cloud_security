"""NIST CSF 2.0 references used by the benchmark.

CSF 2.0 describes outcomes rather than prescribing one implementation.
The project therefore uses CSF Subcategories as outcome-level benchmark
references and uses CIS/SP 800-53 as the more concrete control references.
"""

NIST_CSF = {
    "GV.RM-06": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated.",
    "ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded.",
    "ID.RA-05": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization.",
    "ID.RA-06": "Risk responses are chosen, prioritized, planned, tracked, and communicated.",
    "ID.IM-02": "Improvements are identified from security tests and exercises.",
    "PR.AA-05": "Access permissions and authorizations are defined, managed, enforced, and reviewed, incorporating least privilege and separation of duties.",
    "PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest are protected.",
    "PR.DS-02": "The confidentiality, integrity, and availability of data-in-transit are protected.",
    "PR.PS-01": "Configuration management practices are established and applied.",
    "PR.PS-04": "Log records are generated and made available for continuous monitoring.",
    "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage.",
    "DE.CM-01": "Networks and network services are monitored to find potentially adverse events.",
    "DE.AE-03": "Information is correlated from multiple sources.",
    "RS.MI-01": "Incidents are contained.",
    "RS.MI-02": "Incidents are eradicated.",
    "RC.RP-02": "Recovery actions are selected, scoped, prioritized, and performed.",
    "RC.RP-05": "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed.",
}

def get_csf(control_id):
    return NIST_CSF[control_id]
