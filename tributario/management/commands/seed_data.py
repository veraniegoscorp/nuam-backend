from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from tributario.models import UserProfile, TaxRecord, TaxFactor, ApprovalRequest, AuditLog


class Command(BaseCommand):
    help = 'Carga datos iniciales (usuarios, expedientes, aprobaciones y auditoría)'

    def handle(self, *args, **options):
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
                'code': '123456'
            },
            {
                'username': 'maria.rojas',
                'email': 'maria.rojas@nuam.com',
                'first_name': 'María',
                'last_name': 'Rojas',
                'role': 'supervisor',
                'country': 'Chile',
                'code': '123456'
            },
            {
                'username': 'rodrigo.carrasco',
                'email': 'rodrigo.carrasco56@inacapmail.cl',
                'first_name': 'Rodrigo',
                'last_name': 'Carrasco',
                'role': 'operador',
                'country': 'Chile',
                'code': '123456'
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
            user.set_password('Admin1234*')
            user.email = udata['email']
            user.first_name = udata['first_name']
            user.last_name = udata['last_name']
            user.save()

            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.role = udata['role']
            profile.country = udata['country']
            profile.two_factor_code = udata['code']
            profile.is_2fa_enabled = True
            profile.save()

        self.stdout.write(self.style.SUCCESS('Usuarios creados: camila.vargas, maria.rojas, rodrigo.carrasco (pass: Admin1234*, 2FA: 123456)'))

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
                'sha256_hash': '6f2c9a048e3b17d5c0a8f69e12b4d730a5e1938c7d60f241b9e8a0524c6d3f17',
                'is_hash_verified': True,
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
                'sha256_hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'is_hash_verified': True,
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
                'sha256_hash': '7d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e',
                'is_hash_verified': True,
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
                'sha256_hash': '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b',
                'is_hash_verified': True,
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
