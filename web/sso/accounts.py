"""From verified claims to a local user. The rules, in order:
  1. the (issuer, sub) link, if there is one;
  2. an existing local account, only when LIMES_OIDC_LINK_BY_EMAIL is on, the provider says the email is verified,
     the account has no link to this provider yet, and the account is not privileged;
  3. a new account, only when LIMES_OIDC_AUTO_CREATE is on.
Anything else is refused. SSO never creates, links or promotes a superuser, staff or sys_admin account."""
import hashlib
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone
from rolepermissions.checkers import has_role
from rolepermissions.roles import assign_role

from dashboard.models import Project
from memberships import services
from memberships.models import ProjectMember, READ_ONLY
from sso import config
from sso.models import OidcIdentity

logger = logging.getLogger(__name__)

# Global (rolepermissions) role for a new SSO user. Never sys_admin.
GLOBAL_ROLE = {READ_ONLY: 'auditor', 'standard': 'penetration_tester'}


class Refused(Exception):
    """Sign-in refused. `reason` is a short code for the log; the user only ever sees one generic message."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _privileged(user):
    return user.is_superuser or user.is_staff or has_role(user, 'sys_admin')


def email_of(claims):
    email = claims.get('email')
    if not isinstance(email, str) or len(email) > 254:
        return '', False
    email = email.strip()
    if not email.isascii():
        return '', False  # no IDN / look-alike letters: a lookalike must never compare equal to a real address
    local, _, domain = email.partition('@')
    if not local or not domain or '@' in domain or any(c.isspace() for c in email):
        return '', False  # one @ and no spaces: anything stranger could make the domain check read the wrong part
    return email, claims.get('email_verified') is True  # only a real JSON true; "true" or 1 do not count


def check_domain(email, verified):
    allowed = config.allowed_domains()
    if not allowed:
        return
    if not email or not verified:
        raise Refused('domain_needs_verified_email')
    if email.rsplit('@', 1)[1].lower() not in allowed:
        raise Refused('domain_not_allowed')


def _username(issuer, sub):
    return 'sso-' + hashlib.sha256(f'{issuer}\n{sub}'.encode()).hexdigest()[:16]


@transaction.atomic
def resolve(claims):
    """The local user for these claims, created or linked if the rules allow. Raises Refused."""
    issuer, sub = settings.OIDC_ISSUER, claims['sub']
    email, verified = email_of(claims)
    check_domain(email, verified)
    User = get_user_model()
    link = OidcIdentity.objects.select_related('user').filter(issuer=issuer, subject=sub).first()
    if link:
        if not link.user.is_active:
            raise Refused('user_inactive')
        link.email, link.last_login_at = email, timezone.now()
        link.save(update_fields=['email', 'last_login_at'])
        return link.user
    user = None
    if settings.OIDC_LINK_BY_EMAIL and verified:
        # exact comparison in Python on ASCII only: the database folds some non-ASCII letters (dotless i) onto ASCII ones
        matches = [u for u in User.objects.filter(email__iexact=email)[:20] if u.email.isascii() and u.email.lower() == email.lower()]
        if len(matches) == 1:
            user = matches[0]
            if not user.is_active:
                raise Refused('user_inactive')
            if _privileged(user):
                raise Refused('privileged_account_not_linkable')
            if OidcIdentity.objects.filter(user=user, issuer=issuer).exists():
                raise Refused('account_already_linked')
            services.audit(None, None, 'sso_linked', user.username, 'linked by verified email')
    if user is None:
        if not settings.OIDC_AUTO_CREATE:
            raise Refused('no_account')
        user = _create(issuer, sub, email if verified else '')
    try:
        with transaction.atomic():
            OidcIdentity.objects.create(user=user, issuer=issuer, subject=sub, email=email, last_login_at=timezone.now())
    except IntegrityError:  # two logins of the same new identity at once: the other one won
        raise Refused('race')
    return user


def _create(issuer, sub, email):
    User = get_user_model()
    if User.objects.filter(username=_username(issuer, sub)).exists():
        raise Refused('username_taken')
    user = User(username=_username(issuer, sub), email=email, is_staff=False, is_superuser=False, is_active=True)
    user.set_unusable_password()
    user.save()
    role = config.default_role()
    assign_role(user, GLOBAL_ROLE[role])
    for project in Project.objects.filter(slug__in=[s.strip() for s in settings.OIDC_DEFAULT_PROJECTS if s.strip()]):
        member, made = ProjectMember.objects.get_or_create(user=user, project=project, defaults={'role': role})
        if made:
            services.audit(None, project, 'member_added', user.username, f'sso default project, role {role}')
    services.audit(None, None, 'sso_user_created', user.username, f'default role {role}')
    return user
