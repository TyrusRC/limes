from django.conf import settings
from django.db import models
from django.utils import timezone


class OidcIdentity(models.Model):
    """The link between a local user and one identity at one provider. Matching is on (issuer, sub), which the
    provider guarantees never to reuse; an email address is not an identity."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='oidc_identities')
    issuer = models.CharField(max_length=500)
    subject = models.CharField(max_length=255)
    email = models.CharField(max_length=254, blank=True, default='')
    created_at = models.DateTimeField(default=timezone.now)
    last_login_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name_plural = 'OIDC identities'
        constraints = [
            models.UniqueConstraint(fields=['issuer', 'subject'], name='one_user_per_provider_identity'),
            models.UniqueConstraint(fields=['user', 'issuer'], name='one_identity_per_user_and_provider'),
        ]
