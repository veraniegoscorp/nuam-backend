from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from tributario.models import (
    ApprovalRequest,
    AuditLog,
    TaxRecord,
    UserProfile,
)


def is_nuam_admin(user):
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.role == 'admin')


@login_required(login_url='/admin/login/')
def admin_index(request):
    if not is_nuam_admin(request.user):
        return render(request, 'core_nuam/admin_denied.html', status=403)

    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        role = request.POST.get('role')
        is_active = request.POST.get('is_active') == 'on'

        if user_id and role in dict(UserProfile.ROLE_CHOICES):
            target = User.objects.select_related('profile').filter(pk=user_id).first()
            if target:
                target.is_active = is_active
                target.save(update_fields=['is_active'])
                profile, _ = UserProfile.objects.get_or_create(
                    user=target,
                    defaults={'role': role},
                )
                profile.role = role
                profile.save(update_fields=['role'])

    users = User.objects.select_related('profile').order_by('email', 'username')
    context = {
        'users': users,
        'role_choices': UserProfile.ROLE_CHOICES,
        'stats': {
            'users': users.count(),
            'records': TaxRecord.objects.filter(is_deleted=False).count(),
            'approvals': ApprovalRequest.objects.filter(status='Pendiente').count(),
            'audit': AuditLog.objects.count(),
        },
    }
    return render(request, 'core_nuam/admin.html', context)


def admin_login(request):
    if request.user.is_authenticated and is_nuam_admin(request.user):
        return HttpResponseRedirect(reverse('nuam-admin'))

    error = ''
    if request.method == 'POST':
        identifier = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=identifier, password=password)
        if user is None and '@' in identifier:
            matched = User.objects.filter(email__iexact=identifier).only('username').first()
            if matched:
                user = authenticate(request, username=matched.username, password=password)

        if user is not None and is_nuam_admin(user):
            login(request, user)
            return HttpResponseRedirect(reverse('nuam-admin'))
        error = 'Credenciales inválidas o la cuenta no tiene permiso de administración.'

    return render(request, 'core_nuam/admin_login.html', {'error': error})


def admin_logout(request):
    logout(request)
    return HttpResponseRedirect('/admin/login/')
