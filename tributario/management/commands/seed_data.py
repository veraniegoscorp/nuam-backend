from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.conf import settings
from django.db import connections
from django.contrib.auth.models import User
from tributario.models import UserProfile, TaxRecord, TaxFactor, ApprovalRequest, AuditLog


class Command(BaseCommand):
    help = 'Carga datos iniciales (usuarios, expedientes, aprobaciones y auditoría)'

    def handle(self, *args, **options):
        if not settings.DEBUG or connections['default'].vendor != 'sqlite':
            raise CommandError('seed_data solo puede ejecutarse en entorno local de desarrollo.')
        self.stdout.write('Iniciando carga de datos de prueba...')

        # 1. Crear usuarios
        users_data = [
            {
                'username': 'camila.vargas',
                'email': 'camila.vargas@nuam.com',
                'first_name': 'Camila',
                'last_name': 'Vargas',
                'role': 'operador',
                'country': 'Chile',
            },
            {
                'username': 'maria.rojas',
                'email': 'maria.rojas@nuam.com',
                'first_name': 'María',
                'last_name': 'Rojas',
                'role': 'supervisor',
                'country': 'Chile',
            },
            {
                'username': 'rodrigo.carrasco',
                'email': 'rodrigo.carrasco56@inacapmail.cl',
                'first_name': 'Rodrigo',
                'last_name': 'Carrasco',
                'role': 'operador',
                'country': 'Chile',
            }
        ]

        for udata in users_data:
            user, created = User.objects.get_or_create(
                username=udata['username'],
                defaults={
                    'email': udata['email'],
                    'first_name': udata['first_name'],
                    'last_name': udata['last_name']
                }
            )
            user.set_unusable_password()
            user.email = udata['email']
            user.first_name = udata['first_name']
            user.last_name = udata['last_name']
            user.save()

            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.role = udata['role']
            profile.country = udata['country']
            profile.is_2fa_enabled = True
            profile.save()

        self.stdout.write(self.style.SUCCESS('Usuarios de demostración creados; configura el envío de correo para iniciar sesión.'))

        # 2. Crear registros tributarios
        records_data = [
            {
                'folio': 'CERT-2025-0148',
                'rut': '76.543.210-8',
                'company_name': 'Inversiones Andinas S.A.',
                'year': 2025,
                'country': 'Chile',
                'doc_type': 'Certificado tributario',
                'status': 'Pendiente de aprobación',
                'amount': 12450000.00,
                'currency': 'CLP',
                'origin': 'Bolsa de Santiago',
                'document_name': 'CERT-2025-0148.pdf',
                'sha256_hash': '',
                'is_hash_verified': False,
                'version': '1 · Original',
                'factors': [
                    ('Factor de actualización', '1,045'),
                    ('Crédito por impuesto', '$2.180.000'),
                    ('Retención aplicada', '$845.500')
                ],
                'logs': [
                    ('Carga inicial del certificado · Versión 1', 'Camila Vargas · Operador', 'Documento registrado'),
                    ('Validación de integridad SHA-256', 'Sistema', 'Hash verificado'),
                    ('Solicitud de entrega de respaldo al SII', 'Camila Vargas · Operador', 'Pendiente de aprobación')
                ]
            },
            {
                'folio': 'CERT-2025-0149',
                'rut': '77.125.680-4',
                'company_name': 'Servicios del Pacífico SpA',
                'year': 2025,
                'country': 'Chile',
                'doc_type': 'Certificado tributario',
                'status': 'Pendiente de aprobación',
                'amount': 9820000.00,
                'currency': 'CLP',
                'origin': 'Bolsa de Santiago',
                'document_name': 'CERT-2025-0149.pdf',
                'sha256_hash': '',
                'is_hash_verified': False,
                'version': '1 · Original',
                'factors': [
                    ('Factor de actualización', '1,032'),
                    ('Crédito por impuesto', '$1.450.000'),
                ],
                'logs': [
                    ('Carga inicial del certificado', 'Camila Vargas · Operador', 'Documento registrado'),
                    ('Validación de integridad SHA-256', 'Sistema', 'Hash verificado')
                ]
            },
            {
                'folio': 'CERT-2025-0150',
                'rut': '76.284.931-6',
                'company_name': 'Comercial Los Alerces Ltda.',
                'year': 2025,
                'country': 'Chile',
                'doc_type': 'Certificado tributario',
                'status': 'Validado',
                'amount': 15300000.00,
                'currency': 'CLP',
                'origin': 'Bolsa de Santiago',
                'document_name': 'CERT-2025-0150.pdf',
                'sha256_hash': '',
                'is_hash_verified': False,
                'version': '1 · Original',
                'factors': [
                    ('Factor de actualización', '1,050'),
                    ('Crédito por impuesto', '$3.100.000'),
                ],
                'logs': [
                    ('Aprobación final del respaldo', 'María Rojas · Supervisor', 'Validado')
                ]
            },
            {
                'folio': 'CERT-2024-0089',
                'rut': '96.832.450-0',
                'company_name': 'Inversiones Cordillera S.A.',
                'year': 2024,
                'country': 'Chile',
                'doc_type': 'Certificado tributario',
                'status': 'Observado',
                'amount': 6340000.00,
                'currency': 'CLP',
                'origin': 'Bolsa de Santiago',
                'document_name': 'CERT-2024-0089.pdf',
                'sha256_hash': '',
                'is_hash_verified': False,
                'version': '1 · Original',
                'factors': [
                    ('Factor de actualización', '1,021'),
                ],
                'logs': [
                    ('Revisión por discrepancia en monto SII', 'María Rojas · Supervisor', 'Observado')
                ]
            }
        ]

        for rdata in records_data:
            rec, _ = TaxRecord.objects.update_or_create(
                folio=rdata['folio'],
                defaults={
                    'rut': rdata['rut'],
                    'company_name': rdata['company_name'],
                    'year': rdata['year'],
                    'country': rdata['country'],
                    'doc_type': rdata['doc_type'],
                    'status': rdata['status'],
                    'amount': rdata['amount'],
                    'currency': rdata['currency'],
                    'origin': rdata['origin'],
                    'document_name': rdata['document_name'],
                    'sha256_hash': rdata['sha256_hash'],
                    'is_hash_verified': rdata['is_hash_verified'],
                    'version': rdata['version']
                }
            )

            # Factores
            rec.factors.all().delete()
            for fname, fval in rdata['factors']:
                TaxFactor.objects.create(tax_record=rec, name=fname, value=fval)

            # Logs
            rec.audit_logs.all().delete()
            for action, uname, res in rdata['logs']:
                AuditLog.objects.create(
                    tax_record=rec,
                    action=action,
                    user_name=uname,
                    result=res,
                    ip_address='190.22.45.10'
                )

        self.stdout.write(self.style.SUCCESS('Expedientes tributarios cargados.'))

        # 3. Crear solicitudes de aprobación
        rec1 = TaxRecord.objects.get(folio='CERT-2025-0148')
        rec2 = TaxRecord.objects.get(folio='CERT-2025-0149')

        ApprovalRequest.objects.update_or_create(
            code='SOL-2026-0038',
            defaults={
                'tax_record': rec1,
                'applicant_name': 'Camila Vargas',
                'recipient': 'SII · Chile',
                'origin': 'Bolsa de Santiago',
                'reason': 'Entrega de respaldo del certificado tributario correspondiente al ejercicio 2025.',
                'status': 'Pendiente',
                'priority': 'Alta',
                'decision_comment': ''
            }
        )

        ApprovalRequest.objects.update_or_create(
            code='SOL-2026-0039',
            defaults={
                'tax_record': rec2,
                'applicant_name': 'Camila Vargas',
                'recipient': 'SII · Chile',
                'origin': 'Bolsa de Santiago',
                'reason': 'Entrega de respaldo del certificado tributario correspondiente al ejercicio 2025.',
                'status': 'Pendiente',
                'priority': 'Media',
                'decision_comment': ''
            }
        )

        self.stdout.write(self.style.SUCCESS('Solicitudes SOL-2026-0038 y SOL-2026-0039 creadas.'))
        self.stdout.write(self.style.SUCCESS('Inicialización completada con éxito.'))
