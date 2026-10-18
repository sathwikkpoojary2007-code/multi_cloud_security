from compliance.benchmarks.benchmark_engine import attach_benchmarks

resource = {
    "provider": "aws",
    "resource_type": "storage_bucket",
    "resource_id": "example",
    "security": {
        "exposure": 1.0,
        "privilege": 0.0,
        "encryption": 0.0,
        "logging": 1.0,
        "network_security": 0.0,
        "identity_security": 0.0,
        "configuration_security": 0.0,
    },
    "evaluated_dimensions": ["exposure", "encryption", "logging", "privilege", "network_security", "identity_security", "configuration_security"],
}

attach_benchmarks(resource)

for result in resource["benchmarks"]:
    print(result["benchmark_id"], result["status"])
