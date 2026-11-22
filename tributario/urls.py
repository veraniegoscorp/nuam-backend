from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    LoginView,
    CurrentUserView,
    AdminUsersView,
    TaxRecordViewSet,
    ApprovalRequestViewSet,
    BulkUploadView,
    AuditLogViewSet
)

router = DefaultRouter()
router.register(r'tax-records', TaxRecordViewSet, basename='tax-record')
router.register(r'approvals', ApprovalRequestViewSet, basename='approval')
router.register(r'audit', AuditLogViewSet, basename='audit')

urlpatterns = [
    # Autenticación y JWT
    path('auth/login/', LoginView.as_view(), name='api-login'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/me/', CurrentUserView.as_view(), name='api-me'),
    path('admin/users/', AdminUsersView.as_view(), name='admin-users'),

    # Carga masiva
    path('bulk-upload/validate/', BulkUploadView.as_view(), {'action_type': 'validate'}, name='bulk-validate'),
    path('bulk-upload/confirm/', BulkUploadView.as_view(), {'action_type': 'confirm'}, name='bulk-confirm'),

    # Routers
    path('', include(router.urls)),
]
