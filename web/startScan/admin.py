from django.contrib import admin
from startScan.models import *

admin.site.register(ScanHistory)
admin.site.register(ScanActivity)
admin.site.register(Vulnerability)
admin.site.register(CveId)
admin.site.register(Port)
admin.site.register(IpAddress)
admin.site.register(Technology)
admin.site.register(Command)
