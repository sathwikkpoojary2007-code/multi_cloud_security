RISK_WEIGHTS = {
    "exposure": 0.25,
    "privilege": 0.15,
    "encryption": 0.15,
    "logging": 0.10,
    "network_security": 0.15,
    "identity_security": 0.10,
    "configuration_security": 0.10,
}


def calculate_risk(
    exposure,
    privilege,
    encryption,
    logging,
    network_security=0.0,
    identity_security=0.0,
    configuration_security=0.0
):
    """
    Calculate a security risk score from 0 to 100.

    Each factor:
        0.0 = no observed weakness
        1.0 = maximum observed weakness
    """

    score = (
        RISK_WEIGHTS["exposure"] * exposure +
        RISK_WEIGHTS["privilege"] * privilege +
        RISK_WEIGHTS["encryption"] * encryption +
        RISK_WEIGHTS["logging"] * logging +
        RISK_WEIGHTS["network_security"] * network_security +
        RISK_WEIGHTS["identity_security"] * identity_security +
        RISK_WEIGHTS["configuration_security"] * configuration_security
    )

    return round(score * 100, 2)


if __name__ == "__main__":

    risk = calculate_risk(
        exposure=1.0,
        privilege=0.0,
        encryption=0.0,
        logging=0.0,
        network_security=0.0,
        identity_security=0.0,
        configuration_security=0.0
    )

    print("Risk Score:", risk)
