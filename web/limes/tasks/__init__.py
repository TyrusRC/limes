"""
Celery tasks package. Importing every submodule registers its tasks; the star
imports keep `from limes.tasks import X` working for every historical name.
"""
from limes.tasks.base import *
from limes.tasks.runner import *
from limes.tasks.runner import _append_history
from limes.tasks.notifications import *
from limes.tasks.persistence import *
from limes.tasks.enrichment import *
from limes.tasks.stages import *
from limes.tasks.control import *
