from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """Allow access only to Admin users."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "admin"

class IsStaff(BasePermission):
    """Allow access only to Staff users."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "staff"

class IsStudent(BasePermission):
    """Allow access only to Student users."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "student"


class IsOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        return obj.student == request.user

class IsReviewer(BasePermission):
    def has_permission(self, request, view):
        return request.user.role in ['staff', 'admin']
    
    def has_object_permission(self, request, view, obj):
        return (
            request.user.role == 'admin' or
            (request.user.role == 'staff' and 
             obj.department == request.user.department)
        )
    
class IsPrototypeOwner(BasePermission):
    """
    Custom permission to only allow owners of a prototype to access or modify it.
    """

def has_object_permission(self, request, view, obj):
    return obj.prototype.student == request.user