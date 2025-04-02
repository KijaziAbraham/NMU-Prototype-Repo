from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PrototypeViewSet, user_profile
from .api_views import register_user, login_user
from .views import (
    UserViewSet, PrototypeViewSet,
    PrototypeAttachmentViewSet, DepartmentViewSet,
    AuditLogViewSet, change_password,
)


router = DefaultRouter()
router.register(r'prototypes', PrototypeViewSet, basename="prototype")  
router.register(r'users', UserViewSet) 
router.register(r'attachments', PrototypeAttachmentViewSet)
router.register(r'departments', DepartmentViewSet) 
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', register_user, name='register'),
    path('login/', login_user, name='login'),
    path("user/profile/", user_profile, name="user-profile"),
    path("user/change-password/", change_password, name="change-password"),


]

