from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied
from rolepermissions.checkers import has_permission
from memberships.drf import ProjectRolePermission

class HasPermission(ProjectRolePermission):
	"""
		This is a custom permission class for DRF that checks if the user 
		has the required permission.
		Usage in drf views:
		permission_classes = [HasPermission]
		permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS
	"""

	def has_permission(self, request, view):
		super().has_permission(request, view)  # the project layer first: the same decision as the middleware, from DRF's parse
		permission_code = getattr(view, 'permission_required', None)
		if not permission_code:
			raise PermissionDenied(detail="Permission is not specified for this view.")

		if not has_permission(request.user, permission_code):
			raise PermissionDenied(detail="This user does not have enough permissions")
		return True