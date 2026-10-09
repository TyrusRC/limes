SEVERITY_INT = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def to_int(s):
    """Map a severity label to the platform's int scale; unknown -> -1."""
    return SEVERITY_INT.get(str(s).strip().lower(), -1)
