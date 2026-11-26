import hashlib
import hmac
import logging
import math
import os
import secrets
import csv
import io
from decimal import Decimal, InvalidOperation
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from django.db.models import Q
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from rest_framework import viewsets, status, permissions
from rest_framework.pagination import PageNumberPagination
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken

from .models import UserProfile, TaxRecord, ApprovalRequest, AuditLog, BulkUploadJob
from .validators import is_valid_chilean_rut, normalize_chilean_rut
from .serializers import (
    UserSerializer,
    UserNameUpdateSerializer,
    AdminUserCreateSerializer,
    TaxRecordListSerializer,
    TaxRecordDetailSerializer,
    ApprovalRequestSerializer,
    ApprovalResolveSerializer,
    AuditLogSerializer,
)
from openpyxl import load_workbook

logger = logging.getLogger(__name__)


def get_role(user):
    if user.is_superuser:
        return 'admin'
    return UserProfile.objects.filter(user=user).values_list('role', flat=True).first()


def get_client_ip(request):
    """IP real del cliente: tras el proxy de Vercel REMOTE_ADDR es la del proxy."""
    if os.getenv('VERCEL'):
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def log_action(request, action, result, tax_record=None):
    user = request.user
    display_name = user.get_full_name() or user.get_username()
    role = get_role(user) or 'usuario'
    AuditLog.objects.create(
        tax_record=tax_record,
        action=action,
        user_name=f'{display_name} · {role}',
        result=result,
        ip_address=get_client_ip(request),
    )


def read_verified_document(record):
    """Lee el PDF una sola vez y valida su SHA-256 sobre esos mismos bytes.

    Devuelve (verificado, hash_calculado, bytes). Los bytes devueltos son los que
    se hashearon, de modo que lo verificado es exactamente lo que se entrega.
    """
    if not record.document_file or not record.sha256_hash:
        return False, '', b''
    try:
        with record.document_file.open('rb') as document:
            content = document.read()
    except Exception:
        logger.exception('No fue posible leer el documento de %s.', record.folio)
        return False, '', b''
    hasher = hashlib.sha256()
    for start in range(0, len(content), 64 * 1024):
        hasher.update(content[start:start + 64 * 1024])
    actual_hash = hasher.hexdigest()
    verified = hmac.compare_digest(actual_hash, record.sha256_hash)
    if record.is_hash_verified != verified:
        record.is_hash_verified = verified
        record.save(update_fields=['is_hash_verified', 'updated_at'])
    return verified, actual_hash, content


def verify_document_hash(record):
    verified, actual_hash, _ = read_verified_document(record)
    return verified, actual_hash


class HasRole(permissions.BasePermission):
    allowed_roles = ()

    def has_permission(self, request, view):
        allowed_roles = getattr(view, 'allowed_roles', self.allowed_roles)
        return request.user.is_authenticated and (
            request.user.is_superuser or get_role(request.user) in allowed_roles
        )


class TaxRecordPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        page_size = self.get_page_size(self.request) or self.page_size
        total_pages = math.ceil(self.page.paginator.count / page_size) if self.page.paginator.count else 1
        return Response({
            'count': self.page.paginator.count,
            'page': self.page.number,
            'page_size': page_size,
            'total_pages': total_pages,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data,
        })


class TaxRecordPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        role = get_role(request.user)
        if request.method in permissions.SAFE_METHODS:
            return role in ('operador', 'supervisor', 'auditor', 'admin')
        if request.method == 'DELETE':
            return role in ('supervisor', 'admin')
        return role in ('operador', 'supervisor', 'admin')


class ApprovalPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        role = get_role(request.user)
        if getattr(view, 'action', '') == 'resolve':
            return role in ('supervisor', 'admin')
        return request.method in permissions.SAFE_METHODS and role in ('supervisor', 'auditor', 'admin')


class BulkUploadPermissions(HasRole):
    allowed_roles = ('operador', 'supervisor', 'admin')


class LoginView(APIView):
    """
    Endpoint de login con soporte para credenciales + 2FA y emisión de JWT.
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'auth_login'

    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        two_factor_code = request.data.get('two_factor_code', '')
        email = email.strip() if isinstance(email, str) else ''
        two_factor_code = two_factor_code.strip() if isinstance(two_factor_code, str) else ''
        if not isinstance(password, str):
            password = ''

        if not email or not password:
            return Response(
                {'detail': 'Debe ingresar correo y contraseña.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Buscar usuario por email o username
        user = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).first()
        if not user or not user.is_active or not user.check_password(password):
            AuditLog.objects.create(
                action='Intento de inicio de sesión',
                user_name='Intento de acceso',
                result='Credenciales incorrectas',
                ip_address=get_client_ip(request),
            )
            return Response(
                {'detail': 'Las credenciales ingresadas son incorrectas.'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        profile, _ = UserProfile.objects.get_or_create(user=user)

        now = timezone.now()
        if profile.locked_until and profile.locked_until > now:
            AuditLog.objects.create(
                action='Intento de acceso en cuenta bloqueada temporalmente',
                user_name=f'{user.get_full_name() or user.username} · {profile.get_role_display()}',
                result='Cuenta bloqueada por intentos 2FA fallidos',
                ip_address=get_client_ip(request),
            )
            return Response(
                {'detail': 'Cuenta bloqueada temporalmente tras múltiples intentos fallidos de segundo factor.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if profile.is_2fa_enabled and not two_factor_code:
            cooldown_active = (
                profile.two_factor_code_hash
                and profile.two_factor_code_sent_at
                and profile.two_factor_code_sent_at > now - timedelta(seconds=60)
            )
            if not cooldown_active:
                code = f'{secrets.randbelow(1_000_000):06d}'
                profile.two_factor_code_hash = make_password(code)
                profile.two_factor_code_expires_at = now + timedelta(minutes=5)
                profile.two_factor_code_sent_at = now
                profile.two_factor_attempts = 0
                profile.locked_until = None
                profile.save(update_fields=[
                    'two_factor_code_hash',
                    'two_factor_code_expires_at',
                    'two_factor_code_sent_at',
                    'two_factor_attempts',
                    'locked_until',
                ])
                try:
                    send_mail(
                        'Código de verificación NUAM',
                        f'Tu código de acceso es {code}. Vence en 5 minutos y solo puede usarse una vez.',
                        None,
                        [user.email],
                        fail_silently=False,
                    )
                except Exception:
                    profile.two_factor_code_hash = ''
                    profile.two_factor_code_expires_at = None
                    profile.save(update_fields=['two_factor_code_hash', 'two_factor_code_expires_at'])
                    logger.exception('No fue posible enviar el código de verificación 2FA.')
                    return Response(
                        {'detail': 'No fue posible enviar el código de verificación. Intenta nuevamente más tarde.'},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
            return Response({
                'requires_2fa': True,
                'email': user.email,
                'delivery_mode': (
                    'console'
                    if settings.EMAIL_BACKEND == 'django.core.mail.backends.console.EmailBackend'
                    else 'email'
                ),
                'message': (
                    'En el entorno local, revisa la consola del backend para el código.'
                    if settings.EMAIL_BACKEND == 'django.core.mail.backends.console.EmailBackend'
                    else 'Enviamos un código de un solo uso a tu correo institucional.'
                ),
            })

        if profile.is_2fa_enabled:
            code_is_current = (
                profile.two_factor_code_hash
                and profile.two_factor_code_expires_at
                and profile.two_factor_code_expires_at > timezone.now()
                and profile.two_factor_attempts < 5
            )
            if not code_is_current or not check_password(
                two_factor_code,
                profile.two_factor_code_hash,
            ):
                if code_is_current:
                    profile.two_factor_attempts += 1
                    update_fields = ['two_factor_attempts']
                    if profile.two_factor_attempts >= 5:
                        profile.locked_until = timezone.now() + timedelta(minutes=15)
                        update_fields.append('locked_until')
                    profile.save(update_fields=update_fields)
                AuditLog.objects.create(
                    action='Intento de verificación 2FA',
                    user_name=f'{user.get_full_name() or user.username} · {profile.get_role_display()}',
                    result=(
                        'Cuenta bloqueada tras 5 fallos consecutivos'
                        if profile.locked_until
                        else 'Código inválido o expirado'
                    ),
                    ip_address=get_client_ip(request),
                )
                return Response(
                    {'detail': 'Código de segundo factor inválido o expirado.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            profile.two_factor_code_hash = ''
            profile.two_factor_code_expires_at = None
            profile.two_factor_attempts = 0
            profile.locked_until = None
            profile.save(update_fields=[
                'two_factor_code_hash',
                'two_factor_code_expires_at',
                'two_factor_attempts',
                'locked_until',
            ])

        # Registrar evento de auditoría de inicio de sesión
        AuditLog.objects.create(
            action='Inicio de sesión exitoso (MFA verificado)',
            user_name=f"{user.get_full_name() or user.username} · {profile.get_role_display()}",
            result='Acceso concedido',
            ip_address=get_client_ip(request)
        )

        refresh = RefreshToken.for_user(user)
        return Response({
            'requires_2fa': False,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)


class CurrentUserView(APIView):
    """
    Retorna el perfil del usuario autenticado actual.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        UserProfile.objects.get_or_create(
            user=request.user,
            defaults={'role': 'admin' if request.user.is_superuser else 'operador'},
        )
        return Response(UserSerializer(request.user).data)

    def patch(self, request):
        serializer = UserNameUpdateSerializer(request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(UserSerializer(request.user).data)


class AdminUsersView(APIView):
    permission_classes = [HasRole]
    allowed_roles = ('admin',)

    def get(self, request):
        users = User.objects.order_by('first_name', 'last_name', 'username')
        for user in users:
            UserProfile.objects.get_or_create(
                user=user,
                defaults={'role': 'admin' if user.is_superuser else 'operador'},
            )
        return Response(UserSerializer(users, many=True).data)

    def post(self, request):
        serializer = AdminUserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        details = serializer.validated_data
        username = details['email'].split('@', 1)[0].lower()
        if User.objects.filter(username__iexact=username).exists():
            return Response(
                {'username': ['Ya existe una cuenta con el nombre derivado de este correo.']},
                status=status.HTTP_400_BAD_REQUEST,
            )
        temporary_password = secrets.token_urlsafe(18)
        first_name, _, last_name = details['full_name'].strip().partition(' ')
        user = User.objects.create_user(
            username=username,
            email=details['email'],
            first_name=first_name,
            last_name=last_name,
            password=temporary_password,
        )
        UserProfile.objects.create(
            user=user,
            role=details['role'],
            country=details['country'],
            is_2fa_enabled=True,
        )
        log_action(request, f'Creación de usuario {user.email}', 'Usuario creado')
        return Response({
            'user': UserSerializer(user).data,
            'temporary_password': temporary_password,
        }, status=status.HTTP_201_CREATED)


class AdminUserDetailView(APIView):
    permission_classes = [HasRole]
    allowed_roles = ('admin',)

    def patch(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        profile, _ = UserProfile.objects.get_or_create(
            user=user,
            defaults={'role': 'admin' if user.is_superuser else 'operador', 'country': 'Chile'},
        )

        role = request.data.get('role')
        is_active = request.data.get('is_active')
        two_factor_enabled = request.data.get('two_factor_enabled')
        changes = []

        if role is not None:
            if role not in ('admin', 'operador', 'supervisor', 'auditor'):
                return Response({'role': ['Rol inválido.']}, status=status.HTTP_400_BAD_REQUEST)
            if profile.role != role:
                profile.role = role
                changes.append(f'rol={role}')

        if is_active is not None:
            if not isinstance(is_active, bool):
                return Response({'is_active': ['Debe ser un valor booleano.']}, status=status.HTTP_400_BAD_REQUEST)
            if user.is_active != is_active:
                user.is_active = is_active
                user.save(update_fields=['is_active'])
                changes.append(f'is_active={is_active}')

        if two_factor_enabled is not None:
            if not isinstance(two_factor_enabled, bool):
                return Response({'two_factor_enabled': ['Debe ser un valor booleano.']}, status=status.HTTP_400_BAD_REQUEST)
            if profile.is_2fa_enabled != two_factor_enabled:
                profile.is_2fa_enabled = two_factor_enabled
                changes.append(f'two_factor_enabled={two_factor_enabled}')

        profile.save()
        if changes:
            log_action(request, f'Modificación de usuario {user.email}', ', '.join(changes))
        return Response(UserSerializer(user).data)


class TaxRecordViewSet(viewsets.ModelViewSet):
    """
    CRUD completo y búsqueda indexada de expedientes tributarios.
    """
    permission_classes = [TaxRecordPermissions]
    pagination_class = TaxRecordPagination

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        log_action(request, 'Consulta de expedientes tributarios', 'Listado consultado')
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        log_action(request, f'Consulta de expediente {response.data["folio"]}', 'Detalle consultado')
        return response

    def perform_create(self, serializer):
        record = serializer.save()
        log_action(self.request, f'Creación de expediente {record.folio}', 'Registro creado', record)

    def perform_update(self, serializer):
        record = serializer.save()
        log_action(self.request, f'Modificación de expediente {record.folio}', 'Registro actualizado', record)

    def get_queryset(self):
        queryset = TaxRecord.objects.filter(is_deleted=False)
        
        # Filtro de búsqueda general (inteligente)
        search = self.request.query_params.get('search', '').strip()
        if search:
            queryset = queryset.filter(
                Q(rut__icontains=search) |
                Q(company_name__icontains=search) |
                Q(folio__icontains=search) |
                Q(doc_type__icontains=search) |
                Q(notes__icontains=search) |
                Q(origin__icontains=search)
            )

        # Filtro por ejercicio (año)
        year = self.request.query_params.get('year')
        if year and year != 'Todos los ejercicios' and year != 'Todos':
            try:
                queryset = queryset.filter(year=int(year))
            except ValueError:
                pass

        # Filtro por emisor
        emisor = self.request.query_params.get('emisor')
        if emisor and emisor != 'Todos los emisores' and emisor != 'Todos':
            queryset = queryset.filter(company_name__icontains=emisor)

        # Filtro por tipo de documento
        doc_type = self.request.query_params.get('doc_type') or self.request.query_params.get('type')
        if doc_type and doc_type != 'Todos los documentos' and doc_type != 'Todos':
            queryset = queryset.filter(doc_type__iexact=doc_type)

        # Filtro por país
        country = self.request.query_params.get('country')
        if country and country != 'Todos los países' and country != 'Todos':
            queryset = queryset.filter(country__iexact=country)

        # Filtro por estado
        status_param = self.request.query_params.get('status')
        if status_param and status_param != 'Todos':
            queryset = queryset.filter(status__iexact=status_param)

        return queryset

    def get_serializer_class(self):
        if self.action in ['retrieve', 'create', 'update', 'partial_update']:
            return TaxRecordDetailSerializer
        return TaxRecordListSerializer

    def perform_destroy(self, instance):
        instance.is_deleted = True
        instance.save()
        log_action(self.request, f'Borrado lógico de expediente {instance.folio}', 'Registro desactivado', instance)

    @action(detail=True, methods=['get'])
    def verify_hash(self, request, pk=None):
        """
        Verificación de integridad de documento con hash SHA-256.
        """
        record = self.get_object()
        verified, _ = verify_document_hash(record)
        log_action(
            request,
            f'Verificación de hash de expediente {record.folio}',
            'Hash SHA-256 verificado' if verified else 'Documento no verificado',
            record,
        )
        return Response({
            'folio': record.folio,
            'sha256_hash': record.sha256_hash,
            'is_hash_verified': verified,
            'status': 'Documento verificado' if verified else 'Documento no disponible o no verificado',
        })

    @action(detail=True, methods=['get'])
    def download_pdf(self, request, pk=None):
        """
        Descarga segura de documento con validación de integridad SHA-256 en header.
        """
        record = self.get_object()
        if not record.document_file:
            log_action(request, f'Intento de descarga de expediente {record.folio}', 'Archivo original no disponible', record)
            return Response(
                {'detail': 'No existe un documento original almacenado para este expediente.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        verified, verified_hash, content = read_verified_document(record)
        if not verified:
            log_action(request, f'Fallo de integridad del expediente {record.folio}', 'Descarga bloqueada por hash distinto', record)
            return Response(
                {'detail': 'La integridad del documento no pudo verificarse. Descarga bloqueada.'},
                status=status.HTTP_409_CONFLICT,
            )
        log_action(request, f'Descarga de expediente {record.folio}', 'Hash SHA-256 verificado', record)
        response = FileResponse(
            io.BytesIO(content),
            as_attachment=True,
            filename=record.document_name or f'{record.folio}.pdf',
            content_type='application/pdf',
        )
        response['X-Integrity-SHA256'] = verified_hash
        return response

    @action(detail=False, methods=['get'])
    def dashboard_stats(self, request):
        """
        Métricas clave para la vista general / dashboard.
        """
        total = TaxRecord.objects.filter(is_deleted=False).count()
        pending = TaxRecord.objects.filter(is_deleted=False, status__icontains='Pendiente').count()
        recent = TaxRecord.objects.filter(is_deleted=False)[:5]
        verified = TaxRecord.objects.filter(
            is_deleted=False,
            document_file__gt='',
            is_hash_verified=True,
        ).count()
        first_of_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        downloads = AuditLog.objects.filter(
            action__startswith='Descarga de expediente',
            timestamp__gte=first_of_month,
        ).count()
        pending_approvals = ApprovalRequest.objects.filter(status='Pendiente').count()

        return Response({
            'total_records': total,
            'pending_review': pending,
            'pending_approvals': pending_approvals,
            'integrity_percentage': f'{(verified / total * 100):.1f}%' if total else '0.0%',
            'monthly_downloads': downloads,
            'recent_records': TaxRecordListSerializer(recent, many=True).data
        })


class ApprovalRequestViewSet(viewsets.ModelViewSet):
    """
    Bandeja de decisiones y flujo de solicitudes de entrega de respaldo al SII.
    """
    queryset = ApprovalRequest.objects.all()
    serializer_class = ApprovalRequestSerializer
    permission_classes = [ApprovalPermissions]

    def get_queryset(self):
        qs = ApprovalRequest.objects.all()
        status_param = self.request.query_params.get('status')
        if status_param and status_param != 'Todas':
            qs = qs.filter(status__iexact=status_param)
        priority = self.request.query_params.get('priority')
        if priority and priority != 'Todas':
            qs = qs.filter(priority__iexact=priority)
        return qs

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """
        Aprobación o Rechazo con comentario obligatorio por parte del Supervisor.
        """
        serializer = ApprovalResolveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        action_type = serializer.validated_data['action']
        comment = serializer.validated_data['comment']

        user_name = f"{request.user.get_full_name() or request.user.username} · {get_role(request.user)}"
        with transaction.atomic():
            approval = get_object_or_404(
                self.filter_queryset(self.get_queryset()).select_for_update(),
                pk=pk,
            )
            if approval.status != 'Pendiente':
                return Response(
                    {'detail': 'La solicitud ya fue resuelta.'},
                    status=status.HTTP_409_CONFLICT,
                )
            if action_type == 'approve':
                approval.status = 'Aprobada'
                approval.tax_record.status = 'Validado'
                message = 'Solicitud aprobada y enviada a respaldo.'
                result = 'Aprobado'
                action_label = 'Aprobación'
            else:
                approval.status = 'Rechazada'
                approval.tax_record.status = 'Observado'
                message = 'Solicitud rechazada.'
                result = 'Rechazado'
                action_label = 'Rechazo'
            approval.decision_comment = comment
            approval.decided_at = timezone.now()
            approval.decided_by = request.user
            approval.save()
            approval.tax_record.save()
            AuditLog.objects.create(
                tax_record=approval.tax_record,
                action=f'{action_label} de solicitud {approval.code}',
                user_name=user_name,
                result=result,
                ip_address=get_client_ip(request),
            )

        return Response({
            'detail': message,
            'approval': ApprovalRequestSerializer(approval).data
        })


class BulkUploadView(APIView):
    """
    Carga masiva de documentos con semáforo de calidad y reporte de validación previa.
    """
    permission_classes = [BulkUploadPermissions]

    def post(self, request, action_type='validate'):
        if action_type == 'confirm':
            job_id = request.data.get('job_id') or request.data.get('batch_id')
            if not job_id:
                return Response({'detail': 'Debe indicar el job_id del lote.'}, status=status.HTTP_400_BAD_REQUEST)
            created = 0
            with transaction.atomic():
                try:
                    job = BulkUploadJob.objects.select_for_update().get(pk=job_id)
                except (BulkUploadJob.DoesNotExist, ValueError, TypeError):
                    return Response({'detail': 'Lote no encontrado.'}, status=status.HTTP_404_NOT_FOUND)
                if job.status == 'Confirmado':
                    return Response({'detail': 'El lote ya fue confirmado.'}, status=status.HTTP_409_CONFLICT)
                for row in job.valid_payload:
                    # El folio es unico a nivel de BD, incluso para borrados logicos.
                    if TaxRecord.objects.filter(folio=row['folio']).exists():
                        continue
                    TaxRecord.objects.create(
                        folio=row['folio'],
                        rut=row['rut'],
                        company_name=row['company_name'],
                        year=row['year'],
                        doc_type=row['doc_type'],
                        amount=Decimal(str(row['amount'])),
                        origin=row['origin'],
                        country='Chile',
                        status='Pendiente de aprobación',
                    )
                    created += 1
                job.valid_rows = created
                job.status = 'Confirmado'
                job.save(update_fields=['valid_rows', 'status'])
            log_action(
                request,
                f'Confirmación de carga masiva {job.filename}',
                f'{created} registros creados',
            )
            return Response({
                'batch_id': job.pk,
                'filename': job.filename,
                'created': created,
                'valid_rows': job.valid_rows,
                'status': job.status,
            })

        uploaded = request.FILES.get('file')
        if not uploaded:
            return Response({'detail': 'Debe adjuntar un archivo .csv o .xlsx.'}, status=status.HTTP_400_BAD_REQUEST)
        filename = uploaded.name
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if extension not in ('csv', 'xlsx'):
            return Response({'detail': 'Formato no permitido. Use .csv o .xlsx.'}, status=status.HTTP_400_BAD_REQUEST)
        if uploaded.size > 25 * 1024 * 1024:
            return Response({'detail': 'El archivo no puede superar 25 MB.'}, status=status.HTTP_400_BAD_REQUEST)

        required = ['folio', 'rut', 'company_name', 'year', 'doc_type', 'amount', 'origin']
        try:
            if extension == 'csv':
                text = uploaded.read().decode('utf-8-sig')
                sample = text[:4096]
                dialect = csv.Sniffer().sniff(sample, delimiters=',;')
                reader = csv.DictReader(io.StringIO(text), dialect=dialect)
                rows = list(reader)
                headers = [str(h).strip().lower() for h in (reader.fieldnames or [])]
            else:
                workbook = load_workbook(uploaded, read_only=True, data_only=True)
                sheet = workbook.active
                values = list(sheet.iter_rows(values_only=True))
                if not values:
                    rows, headers = [], []
                else:
                    headers = [str(v).strip().lower() if v is not None else '' for v in values[0]]
                    rows = [dict(zip(headers, row)) for row in values[1:] if any(v is not None for v in row)]
        except Exception:
            return Response({'detail': 'No fue posible leer el archivo.'}, status=status.HTTP_400_BAD_REQUEST)

        missing_headers = [column for column in required if column not in headers]
        if missing_headers:
            return Response({
                'detail': 'Faltan columnas requeridas.',
                'missing_columns': missing_headers,
            }, status=status.HTTP_400_BAD_REQUEST)

        errors = []
        valid_payload = []
        seen_folios = set()
        for index, row in enumerate(rows, start=2):
            folio = str(row.get('folio') or '').strip()
            rut = str(row.get('rut') or '').strip()
            company_name = str(row.get('company_name') or '').strip()
            doc_type = str(row.get('doc_type') or '').strip()
            origin = str(row.get('origin') or '').strip()
            row_errors = []

            if not all([folio, rut, company_name, doc_type, origin]):
                for column, value in (
                    ('folio', folio), ('rut', rut), ('company_name', company_name),
                    ('doc_type', doc_type), ('origin', origin),
                ):
                    if not value:
                        row_errors.append((column, f'Campo obligatorio vacío: {column}'))
            elif not is_valid_chilean_rut(rut):
                row_errors.append(('rut', 'RUT inválido según algoritmo Módulo 11'))
            else:
                rut = normalize_chilean_rut(rut)
            try:
                year = int(str(row.get('year')).strip())
                if year < 1900 or year > 2100:
                    raise ValueError
            except (TypeError, ValueError):
                row_errors.append(('year', 'year debe ser un entero válido'))
                year = None
            try:
                amount_text = str(row.get('amount') or '').strip()
                if ',' in amount_text:
                    amount_text = amount_text.replace('.', '').replace(',', '.')
                amount = Decimal(amount_text)
                if amount < 0:
                    raise InvalidOperation
            except (InvalidOperation, TypeError, ValueError):
                row_errors.append(('amount', 'amount debe ser un monto válido'))
                amount = None

            if folio:
                if folio in seen_folios:
                    row_errors.append(('folio', 'folio repetido dentro del archivo'))
                seen_folios.add(folio)
                if TaxRecord.objects.filter(folio=folio).exists():
                    row_errors.append(('folio', 'folio duplicado en la base de datos'))

            if row_errors:
                errors.append({
                    'row': index,
                    'fields': sorted({column for column, _ in row_errors}),
                    'errors': [message for _, message in row_errors],
                    'details': [{'field': column, 'message': message} for column, message in row_errors],
                })
            else:
                valid_payload.append({
                    'folio': folio,
                    'rut': rut,
                    'company_name': company_name,
                    'year': year,
                    'doc_type': doc_type,
                    'amount': str(amount),
                    'origin': origin,
                })

        job = BulkUploadJob.objects.create(
            filename=filename,
            total_rows=len(rows),
            valid_rows=len(valid_payload),
            warning_rows=0,
            error_rows=len(errors),
            status='Validado' if not errors else 'Validado con errores',
            errors_json=errors,
            valid_payload=valid_payload,
            uploaded_by=request.user,
        )
        log_action(request, f'Validación de carga masiva {filename}', f'{len(valid_payload)} válidas, {len(errors)} con error')
        return Response({
            'batch_id': job.pk,
            'filename': filename,
            'total_rows': len(rows),
            'valid_rows': len(valid_payload),
            'warning_rows': 0,
            'error_rows': len(errors),
            'errors': errors,
            'status': job.status,
            'message': (
                'Validación completada sin inconsistencias. Lote listo para confirmar.'
                if not errors
                else f'Se detectaron {len(errors)} fila(s) con inconsistencias que no serán incorporadas.'
            ),
        }, status=status.HTTP_200_OK)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Consulta de auditoría y trazabilidad inmutable.
    """
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [HasRole]
    allowed_roles = ('supervisor', 'auditor', 'admin')

    def get_queryset(self):
        qs = AuditLog.objects.all()
        tax_record_id = self.request.query_params.get('tax_record_id')
        if tax_record_id:
            qs = qs.filter(tax_record_id=tax_record_id)
        return qs
