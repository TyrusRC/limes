from limes.celery import app
from reporting import sched


@app.task(name='generate_due_reports', bind=False)
def generate_due_reports():
    return {'generated': sched.run_due()}
