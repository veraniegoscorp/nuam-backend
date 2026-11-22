from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
import secrets

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

    message = ''
    temporary_password = ''

    if request.method == 'POST':
        action = request.POST.get('action', 'update')

        if action == 'create':
            email = request.POST.get('email', '').strip().lower()
            full_name = request.POST.get('full_name', '').strip()
            role = request.POST.get('role', 'operador')
            country = request.POST.get('country', 'Chile')

            if not email or '@' not in email:
                message = 'Ingresa un correo válido.'
            elif User.objects.filter(email__iexact=email).exists():
                message = 'Ya existe una cuenta con ese correo.'
            elif role not in dict(UserProfile.ROLE_CHOICES):
                message = 'Selecciona un rol válido.'
            else:
                username = email.split('@', 1)[0]
                base_username = username
                suffix = 2
                while User.objects.filter(username__iexact=username).exists():
                    username = f'{base_username}{suffix}'
                    suffix += 1

                temporary_password = secrets.token_urlsafe(18)
                first_name, _, last_name = full_name.partition(' ')
                target = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=temporary_password,
                )
                UserProfile.objects.create(
                    user=target,
                    role=role,
                    country=country,
                    is_2fa_enabled=True,
                )
                AuditLog.objects.create(
                    action=f'Creación de usuario {email}',
                    user_name=request.user.get_full_name() or request.user.username,
                    result='Usuario creado',
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                )
                message = 'Usuario creado correctamente.'

        elif action == 'update':
            user_id = request.POST.get('user_id')
            role = request.POST.get('role')
            is_active = request.POST.get('is_active') == 'on'
            is_2fa_enabled = request.POST.get('is_2fa_enabled') == 'on'

            if user_id and role in dict(UserProfile.ROLE_CHOICES):
                target = User.objects.select_related('profile').filter(pk=user_id).first()
                if target:
                    target.is_active = is_active
                    target.save(update_fields=['is_active'])
                    profile, _ = UserProfile.objects.get_or_create(
                        user=target,
                        defaults={'role': role, 'country': 'Chile'},
                    )
                    profile.role = role
                    profile.is_2fa_enabled = is_2fa_enabled
                    profile.save(update_fields=['role', 'is_2fa_enabled'])
                    message = 'Usuario actualizado correctamente.'

    users = list(User.objects.select_related('profile').order_by('email', 'username'))
    for target in users:
        if not hasattr(target, 'profile'):
            profile = UserProfile.objects.create(
                user=target,
                role='admin' if target.is_superuser else 'operador',
                country='Chile',
            )
            target.profile = profile
    context = {
        'users': users,
        'role_choices': UserProfile.ROLE_CHOICES,
        'country_choices': UserProfile.COUNTRY_CHOICES,
        'message': message,
        'temporary_password': temporary_password,
        'stats': {
            'users': len(users),
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
