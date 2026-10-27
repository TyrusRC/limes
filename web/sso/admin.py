from django.contrib import admin

from sso.models import OidcIdentity

admin.site.register(OidcIdentity)
