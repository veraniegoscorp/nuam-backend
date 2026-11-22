import hashlib
import re
import io
from unittest.mock import MagicMock, patch
from openpyxl import Workbook

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from .models import ApprovalRequest, AuditLog, BulkUploadJob, TaxRecord, UserProfile
from .storage import SupabaseStorage


class SecurityAndAccessTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.operator = self.create_user('operator@nuam.test', 'operador')
        self.supervisor = self.create_user('supervisor@nuam.test', 'supervisor')
        self.admin = self.create_user('admin@nuam.test', 'admin')
        self.record = TaxRecord.objects.create(
            folio='CERT-TEST-1',
            rut='76.543.210-8',
            company_name='Empresa de prueba',
            year=2025,
            country='Chile',
            doc_type='Certificado tributario',
        )
        self.approval = ApprovalRequest.objects.create(
            code='SOL-TEST-1',
            tax_record=self.record,
        )

    def create_user(self, email, role):
        username = email.split('@')[0]
        user = User.objects.create_user(username=username, email=email, password='Strong-Password-123!')
        UserProfile.objects.create(user=user, role=role)
        return user

    def test_health_endpoint_is_public(self):
        response = self.client.get('/api/v1/health/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'ok', 'service': 'nuam-backend'})

    def test_custom_admin_login_has_no_external_static_assets(self):
        response = self.client.get('/admin/login/')
        content = response.content.decode()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('/static/admin/', content)
        self.assertIn('NUAM', content)

    def test_custom_admin_requires_admin_profile(self):
        self.client.force_login(self.operator)
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 403)

        self.client.force_login(self.admin)
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 200)

    def test_anonymous_access_is_denied(self):
        response = self.client.get('/api/v1/tax-records/')
        self.assertEqual(response.status_code, 401)

    def test_cors_is_local_only_and_bulk_upload_requires_a_file(self):
        preflight = self.client.options(
            '/api/v1/auth/me/',
            HTTP_ORIGIN='http://localhost:5173',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
        )
        self.assertEqual(preflight['Access-Control-Allow-Origin'], 'http://localhost:5173')
        untrusted = self.client.options(
            '/api/v1/auth/me/',
            HTTP_ORIGIN='https://untrusted.example',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
        )
        self.assertNotIn('Access-Control-Allow-Origin', untrusted)

        self.client.force_authenticate(self.operator)
        response = self.client.post('/api/v1/bulk-upload/validate/', {}, format='multipart')
        self.assertEqual(response.status_code, 400)

    def test_only_admin_can_create_users(self):
        payload = {
            'email': 'new.user@nuam.test',
            'full_name': 'Nuevo Usuario',
            'role': 'supervisor',
            'country': 'Chile',
        }
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.post('/api/v1/admin/users/', payload, format='json').status_code, 403)

        self.client.force_authenticate(self.admin)
        response = self.client.post('/api/v1/admin/users/', payload, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['user']['profile']['role'], 'supervisor')
        created = User.objects.get(email='new.user@nuam.test')
        self.assertTrue(created.check_password(response.data['temporary_password']))

    def test_authenticated_user_can_set_their_name(self):
        self.client.force_authenticate(self.operator)
        invalid = self.client.patch(
            '/api/v1/auth/me/',
            {'first_name': ' ', 'last_name': ''},
            format='json',
        )
        self.assertEqual(invalid.status_code, 400)

        response = self.client.patch(
            '/api/v1/auth/me/',
            {'first_name': 'Vicente', 'last_name': 'Veraniego'},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.operator.refresh_from_db()
        self.assertEqual(self.operator.first_name, 'Vicente')
        self.assertEqual(self.operator.last_name, 'Veraniego')
        self.assertEqual(response.data['first_name'], 'Vicente')

    def test_role_restrictions_apply_to_api(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(
            self.client.post(
                f'/api/v1/approvals/{self.approval.pk}/resolve/',
                {'action': 'approve', 'comment': 'Aprobación de prueba'},
                format='json',
            ).status_code,
            403,
        )
        self.assertEqual(self.client.get('/api/v1/approvals/').status_code, 403)
        self.assertEqual(self.client.get('/api/v1/audit/').status_code, 403)

        self.client.force_authenticate(self.supervisor)
        self.assertEqual(self.client.get('/api/v1/audit/').status_code, 200)

    @override_settings(STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
        'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'},
    })
    def test_record_create_requires_original_and_rejects_duplicate(self):
        self.client.force_authenticate(self.operator)
        document = b'%PDF-1.4\noriginal document'
        payload = {
            'folio': 'CERT-NEW-1',
            'rut': '77.111.222-3',
            'company_name': 'Nueva empresa',
            'year': '2025',
            'country': 'Chile',
            'doc_type': 'Certificado tributario',
            'document_file': SimpleUploadedFile('record.pdf', document, content_type='application/pdf'),
            'status': 'Validado',
        }
        created = self.client.post('/api/v1/tax-records/', payload, format='multipart')
        self.assertEqual(created.status_code, 201, created.data)
        self.assertTrue(created.data['is_hash_verified'])
        self.assertEqual(created.data['status'], 'Pendiente de aprobación')

        payload['folio'] = 'CERT-NEW-2'
        payload['document_file'] = SimpleUploadedFile('duplicate.pdf', document, content_type='application/pdf')
        duplicate = self.client.post('/api/v1/tax-records/', payload, format='multipart')
        self.assertEqual(duplicate.status_code, 400)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_email_2fa_code_is_hashed_expiring_and_one_time(self):
        user = User.objects.create_user(
            username='mfa-user',
            email='mfa@nuam.test',
            password='Strong-Password-123!',
        )
        profile = UserProfile.objects.create(user=user, role='operador')

        response = self.client.post('/api/v1/auth/login/', {
            'email': user.email,
            'password': 'Strong-Password-123!',
        }, format='json')
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(len(mail.outbox), 1)
        code = re.search(r'\b\d{6}\b', mail.outbox[0].body).group()
        profile.refresh_from_db()
        self.assertNotEqual(profile.two_factor_code_hash, code)
        self.assertTrue(profile.two_factor_code_expires_at)

        verified = self.client.post('/api/v1/auth/login/', {
            'email': user.email,
            'password': 'Strong-Password-123!',
            'two_factor_code': code,
        }, format='json')
        self.assertEqual(verified.status_code, 200)
        self.assertIn('access', verified.data)
        profile.refresh_from_db()
        self.assertEqual(profile.two_factor_code_hash, '')

        replay = self.client.post('/api/v1/auth/login/', {
            'email': user.email,
            'password': 'Strong-Password-123!',
            'two_factor_code': code,
        }, format='json')
        self.assertEqual(replay.status_code, 401)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_sixth_invalid_code_is_blocked(self):
        user = User.objects.create_user(
            username='locked-user',
            email='locked@nuam.test',
            password='Strong-Password-123!',
        )
        UserProfile.objects.create(user=user, role='operador')
        credentials = {'email': user.email, 'password': 'Strong-Password-123!'}
        self.client.post('/api/v1/auth/login/', credentials, format='json')
        for _ in range(5):
            response = self.client.post(
                '/api/v1/auth/login/',
                {**credentials, 'two_factor_code': '000000'},
                format='json',
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            self.client.post(
                '/api/v1/auth/login/',
                {**credentials, 'two_factor_code': re.search(r'\b\d{6}\b', mail.outbox[0].body).group()},
                format='json',
            ).status_code,
            401,
        )

    @override_settings(STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
        'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'},
    })
    def test_document_download_checks_sha256_and_blocks_tampering(self):
        record = TaxRecord.objects.create(
            folio='CERT-FILE-1',
            rut='76.543.210-8',
            company_name='Empresa de prueba',
            year=2025,
            country='Chile',
            doc_type='Certificado tributario',
        )
        record.document_file.save(
            'original.pdf',
            SimpleUploadedFile('original.pdf', b'original pdf bytes', content_type='application/pdf'),
        )
        expected_hash = hashlib.sha256(b'original pdf bytes').hexdigest()
        self.assertEqual(record.sha256_hash, expected_hash)
        self.client.force_authenticate(self.operator)

        response = self.client.get(f'/api/v1/tax-records/{record.pk}/download_pdf/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Integrity-SHA256'], expected_hash)
        self.assertEqual(b''.join(response.streaming_content), b'original pdf bytes')
        response.close()

        storage = record.document_file.storage
        stored_name = record.document_file.name
        storage.delete(stored_name)
        storage.save(stored_name, ContentFile(b'tampered bytes'))
        blocked = self.client.get(f'/api/v1/tax-records/{record.pk}/download_pdf/')
        self.assertEqual(blocked.status_code, 409)


@override_settings(STORAGES={
    'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
})
class AdminUserCreationTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            username='django-admin',
            email='django-admin@nuam.test',
            password='Strong-Admin-Password-123!',
        )
        UserProfile.objects.create(user=self.admin_user, role='admin', country='Chile')
        self.client.force_login(self.admin_user)

    def test_admin_home_has_direct_create_user_action(self):
        response = self.client.get('/admin/')

        self.assertContains(response, 'Panel administrativo')
        self.assertContains(response, 'Usuarios')
        self.assertNotContains(response, '/static/admin/')

    def test_admin_creates_application_user_with_role_and_email(self):
        response = self.client.post('/admin/', {
            'action': 'create',
            'full_name': 'Nuevo Operador',
            'email': 'new.operator@nuam.test',
            'role': 'operador',
            'country': 'Chile',
        })

        self.assertEqual(response.status_code, 200)
        target = User.objects.get(email='new.operator@nuam.test')
        target.refresh_from_db()
        target.profile.refresh_from_db()
        self.assertTrue(target.is_active)
        self.assertEqual(target.profile.role, 'operador')
        self.assertContains(response, 'Contraseña temporal')


class BulkUploadAndUserManagementTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.operator = User.objects.create_user(
            username='bulk-operator',
            email='bulk.operator@nuam.test',
            password='Strong-Password-123!',
        )
        UserProfile.objects.create(user=self.operator, role='operador', country='Chile')
        self.supervisor = User.objects.create_user(
            username='bulk-supervisor',
            email='bulk.supervisor@nuam.test',
            password='Strong-Password-123!',
        )
        UserProfile.objects.create(user=self.supervisor, role='supervisor', country='Chile')
        self.admin = User.objects.create_superuser(
            username='bulk-admin',
            email='bulk.admin@nuam.test',
            password='Strong-Password-123!',
        )
        UserProfile.objects.create(user=self.admin, role='admin', country='Chile')

    def test_valid_csv_is_validated_and_confirmed(self):
        self.client.force_authenticate(self.operator)
        csv_file = SimpleUploadedFile(
            'expedientes.csv',
            b'folio,rut,company_name,year,doc_type,amount,origin\nCSV-001,76.111.111-1,Empresa Chile 2025,2025,Certificado tributario,12450000,Bolsa de Santiago\n',
            content_type='text/csv',
        )
        validated = self.client.post('/api/v1/bulk-upload/validate/', {'file': csv_file}, format='multipart')
        self.assertEqual(validated.status_code, 200, validated.data)
        self.assertEqual(validated.data['total_rows'], 1)
        self.assertEqual(validated.data['valid_rows'], 1)
        job_id = validated.data['batch_id']

        confirmed = self.client.post('/api/v1/bulk-upload/confirm/', {'job_id': job_id}, format='json')
        self.assertEqual(confirmed.status_code, 200, confirmed.data)
        record = TaxRecord.objects.get(folio='CSV-001')
        self.assertEqual(record.country, 'Chile')
        self.assertEqual(record.status, 'Pendiente de aprobación')
        self.assertEqual(BulkUploadJob.objects.get(pk=job_id).status, 'Confirmado')
        self.assertTrue(AuditLog.objects.filter(action__startswith='Confirmación de carga masiva').exists())

    def test_valid_xlsx_is_validated(self):
        self.client.force_authenticate(self.supervisor)
        workbook = Workbook()
        sheet = workbook.active
        sheet.append(['folio', 'rut', 'company_name', 'year', 'doc_type', 'amount', 'origin'])
        sheet.append(['XLSX-001', '77.222.222-2', 'Empresa XLSX', 2025, 'Certificado tributario', 995000, 'SII'])
        stream = io.BytesIO()
        workbook.save(stream)
        xlsx_file = SimpleUploadedFile(
            'expedientes.xlsx',
            stream.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        )
        response = self.client.post('/api/v1/bulk-upload/validate/', {'file': xlsx_file}, format='multipart')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['valid_rows'], 1)

    def test_bulk_validation_reports_duplicates_corrupt_rows_and_missing_columns(self):
        self.client.force_authenticate(self.operator)
        TaxRecord.objects.create(folio='DUP-DB', rut='1', company_name='Existente', year=2025)
        csv_file = SimpleUploadedFile(
            'duplicate.csv',
            b'folio,rut,company_name,year,doc_type,amount,origin\n'
            b'DUP-DB,76.1,Empresa,2025,Certificado tributario,1000,SII\n'
            b'DUP-FILE,76.2,Empresa,2025,Certificado tributario,2000,SII\n'
            b'DUP-FILE,76.3,Empresa,2025,Certificado tributario,no-valido,SII\n'
            b'CORRUPTA,76.4,Empresa,no-es-anio,Certificado tributario,-10,SII\n',
            content_type='text/csv',
        )
        response = self.client.post('/api/v1/bulk-upload/validate/', {'file': csv_file}, format='multipart')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['total_rows'], 4)
        self.assertGreaterEqual(response.data['error_rows'], 3)
        job = BulkUploadJob.objects.get(pk=response.data['batch_id'])
        self.assertTrue(job.errors_json)

        missing = SimpleUploadedFile(
            'missing.csv',
            b'folio,rut\nUNO,76.1\n',
            content_type='text/csv',
        )
        missing_response = self.client.post('/api/v1/bulk-upload/validate/', {'file': missing}, format='multipart')
        self.assertEqual(missing_response.status_code, 400)
        self.assertIn('missing_columns', missing_response.data)

    def test_bulk_rejects_invalid_extension_and_large_file(self):
        self.client.force_authenticate(self.operator)
        invalid = SimpleUploadedFile('datos.txt', b'folio,rut', content_type='text/plain')
        invalid_response = self.client.post('/api/v1/bulk-upload/validate/', {'file': invalid}, format='multipart')
        self.assertEqual(invalid_response.status_code, 400)

        large = SimpleUploadedFile('datos.csv', b'a' * (25 * 1024 * 1024 + 1), content_type='text/csv')
        large_response = self.client.post('/api/v1/bulk-upload/validate/', {'file': large}, format='multipart')
        self.assertEqual(large_response.status_code, 400)

    def test_admin_patch_user_and_dashboard_pending_approvals(self):
        self.client.force_authenticate(self.admin)
        patch_response = self.client.patch(
            f'/api/v1/admin/users/{self.operator.pk}/',
            {'role': 'supervisor', 'is_active': False, 'two_factor_enabled': False},
            format='json',
        )
        self.assertEqual(patch_response.status_code, 200, patch_response.data)
        self.operator.refresh_from_db()
        self.operator.profile.refresh_from_db()
        self.assertEqual(self.operator.profile.role, 'supervisor')
        self.assertFalse(self.operator.is_active)
        self.assertFalse(self.operator.profile.is_2fa_enabled)
        self.assertTrue(AuditLog.objects.filter(action__startswith='Modificación de usuario').exists())

        record = TaxRecord.objects.create(folio='APP-001', rut='76.1', company_name='Empresa', year=2025)
        ApprovalRequest.objects.create(code='SOL-APP-001', tax_record=record, status='Pendiente')
        self.client.force_authenticate(self.operator)
        stats = self.client.get('/api/v1/tax-records/dashboard_stats/')
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.data['pending_approvals'], 1)

    def test_only_supervisor_or_admin_can_read_audit(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.get('/api/v1/audit/').status_code, 403)
        self.client.force_authenticate(self.supervisor)
        self.assertEqual(self.client.get('/api/v1/audit/').status_code, 200)
        self.client.force_authenticate(self.admin)
        self.assertEqual(self.client.get('/api/v1/audit/').status_code, 200)


class SupabaseStorageAuthHeaderTests(SimpleTestCase):
    def build_request(self, api_key, use_bearer_auth):
        response = MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.read.return_value = b''
        response.headers = {}
        with self.settings(
            SUPABASE_URL='https://project.supabase.co',
            SUPABASE_STORAGE_KEY=api_key,
            SUPABASE_STORAGE_USE_BEARER=use_bearer_auth,
            SUPABASE_STORAGE_BUCKET='tax-documents',
        ):
            with patch('tributario.storage.urlopen', return_value=response) as mocked_urlopen:
                SupabaseStorage()._request('GET', 'documents/test.pdf')
        return mocked_urlopen.call_args.args[0]

    def test_secret_key_uses_apikey_without_bearer_header(self):
        request = self.build_request('sb_secret_test', False)
        self.assertEqual(request.get_header('Apikey'), 'sb_secret_test')
        self.assertIsNone(request.get_header('Authorization'))

    def test_legacy_service_role_key_keeps_bearer_header(self):
        request = self.build_request('legacy-service-role-test', True)
        self.assertEqual(request.get_header('Apikey'), 'legacy-service-role-test')
        self.assertEqual(
            request.get_header('Authorization'),
            'Bearer legacy-service-role-test',
        )
