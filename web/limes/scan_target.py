"""Give every owned root domain a scan target (a Domain) so the continuous dispatcher rescans it."""
import logging

from django.db import IntegrityError, transaction
from django.utils import timezone

from targetApp.models import Domain

logger = logging.getLogger(__name__)

# Generic on purpose: Limes has no per-project membership, so naming the other project could leak once an ACL exists.
OTHER_PROJECT_MSG = ('{value} already exists as a scan target and is not linked to this project; add it where it '
                     'lives or remove it there first. It is monitored as a host here meanwhile.')
FAILED_MSG = ('could not create a scan target for {value}; it will be retried the next time it is added or '
              'confirmed')


def _wants_target(asset):
    return asset.kind == 'root_domain' and asset.scope_tier == 'owned_root' and asset.state != 'retired'


def has_scan_target(asset):
    return Domain.objects.filter(project_id=asset.project_id, name=asset.value).exists()


def ensure_scan_target(asset):
    """Return (Domain, None) for an owned, live root, creating its Domain in the asset's project if missing.
    (None, None) for anything else; (None, OTHER_PROJECT_MSG) when Domain.name (globally unique) is taken
    by another project or by none. Never raises: a failure is logged and returned as a generic warning,
    so the caller's own operation (add, confirm, decide) is never lost to it."""
    try:
        if not _wants_target(asset):
            return None, None
        domain = Domain.objects.filter(name=asset.value).first()
        if domain is None:
            try:
                with transaction.atomic():
                    return Domain.objects.create(name=asset.value, project_id=asset.project_id,
                                                 insert_date=timezone.now()), None
            except IntegrityError:  # lost a race to another creator: read what won
                domain = Domain.objects.filter(name=asset.value).first()
        if domain is not None and domain.project_id == asset.project_id:
            return domain, None
        return None, OTHER_PROJECT_MSG.format(value=asset.value)
    except Exception:
        logger.exception('ensure_scan_target failed for asset %s', getattr(asset, 'pk', None))
        return None, FAILED_MSG.format(value=asset.value)
