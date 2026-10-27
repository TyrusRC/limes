from limes.celery import app
from remediation import service


@app.task(name='remediation_overdue', bind=False)
def remediation_overdue():
    """One in-app notification per remediation request that is past its due date and still active."""
    return {'notified': service.notify_overdue()}
