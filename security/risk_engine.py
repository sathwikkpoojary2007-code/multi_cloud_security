def calculate_risk(exposure, privilege, encryption, logging):
    """
    Calculate a risk score from 0 to 100.

    Each factor must be between 0 and 1.
    0 = no observed weakness
    1 = maximum observed weakness
    """

    # Initial project weights.
    # These are design assumptions and can be validated/refined later.
    weights = {
        "exposure": 0.40,
        "privilege": 0.20,
        "encryption": 0.20,
        "logging": 0.20
    }

    score = (
        weights["exposure"] * exposure +
        weights["privilege"] * privilege +
        weights["encryption"] * encryption +
        weights["logging"] * logging
    )

    return round(score * 100, 2)


# Test calculation
risk = calculate_risk(
    exposure=1.0,
    privilege=0.0,
    encryption=0.0,
    logging=0.0
)

print("Risk Score:", risk)