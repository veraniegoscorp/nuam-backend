"""
URL configuration for core_nuam project.
"""
from django.urls import path, include
from django.http import JsonResponse
from .admin_views import admin_index, admin_login, admin_logout


def health(request):
    return JsonResponse({'status': 'ok', 'service': 'nuam-backend'})

urlpatterns = [
    path('admin/', admin_index, name='nuam-admin'),
    path('admin/login/', admin_login, name='nuam-admin-login'),
    path('admin/logout/', admin_logout, name='nuam-admin-logout'),
    path('api/v1/health/', health),
    path('api/v1/', include('tributario.urls')),
]
