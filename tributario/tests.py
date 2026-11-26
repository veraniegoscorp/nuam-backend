import hashlib
import io
import re
import statistics
import time
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from openpyxl import Workbook

from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from .models import ApprovalRequest, AuditLog, BulkUploadJob, TaxRecord, UserProfile
from .storage import SupabaseStorage
from .validators import compute_rut_dv, is_valid_chilean_rut, normalize_chilean_rut


class SecurityAndAccessTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.operator = self.create_user('operator@nuam.test', 'operador')
        self.supervisor = self.create_user('supervisor@nuam.test', 'supervisor')
        self.admin = self.create_user('admin@nuam.test', 'admin')
        self.record = TaxRecord.objects.create(
            folio='CERT-TEST-1',
            rut='76.543.210-3',
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
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    })
    def test_record_create_requires_original_and_rejects_duplicate(self):
        self.client.force_authenticate(self.operator)
        document = b'%PDF-1.4\noriginal document'
        payload = {
            'folio': 'CERT-NEW-1',
            'rut': '77.111.222-6',
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
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    })
    def test_document_download_checks_sha256_and_blocks_tampering(self):
        record = TaxRecord.objects.create(
            folio='CERT-FILE-1',
            rut='76.543.210-3',
            company_name='Empresa de prueba',
            year=2025,
            country='Chile',
            doc_type='Certificado tributario',
        )
        record.document_file.save(
            'original.pdf',
            SimpleUploadedFile('original.pdf', b'%PDF-1.4\noriginal pdf bytes', content_type='application/pdf'),
        )
        expected_hash = hashlib.sha256(b'%PDF-1.4\noriginal pdf bytes').hexdigest()
        self.assertEqual(record.sha256_hash, expected_hash)
        self.client.force_authenticate(self.operator)

        response = self.client.get(f'/api/v1/tax-records/{record.pk}/download_pdf/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Integrity-SHA256'], expected_hash)
        self.assertEqual(b''.join(response.streaming_content), b'%PDF-1.4\noriginal pdf bytes')
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
        cache.clear()
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
            b'folio,rut,company_name,year,doc_type,amount,origin\nCSV-001,76.111.111-6,Empresa Chile 2025,2025,Certificado tributario,12450000,Bolsa de Santiago\n',
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
        sheet.append(['XLSX-001', '77.222.222-K', 'Empresa XLSX', 2025, 'Certificado tributario', 995000, 'SII'])
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
        TaxRecord.objects.create(folio='DUP-DB', rut='76.543.210-3', company_name='Existente', year=2025)
        csv_file = SimpleUploadedFile(
            'duplicate.csv',
            b'folio,rut,company_name,year,doc_type,amount,origin\n'
            b'DUP-DB,76.543.210-3,Empresa,2025,Certificado tributario,1000,SII\n'
            b'DUP-FILE,76.111.111-6,Empresa,2025,Certificado tributario,2000,SII\n'
            b'DUP-FILE,76.111.111-6,Empresa,2025,Certificado tributario,no-valido,SII\n'
            b'CORRUPTA,76.543.210-8,Empresa,no-es-anio,Certificado tributario,-10,SII\n',
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
            b'folio,rut\nUNO,76.543.210-3\n',
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

        record = TaxRecord.objects.create(folio='APP-001', rut='76.543.210-3', company_name='Empresa', year=2025)
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


@override_settings(STORAGES={
    'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
})
class UnitDomainValidationTests(TestCase):
    """Sección 3.1 del Informe: SHA-256 FIPS 180-4, Módulo 11 RUT, DecimalField(18,2) y Parsers."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.operator = User.objects.create_user(
            username='unit-op',
            email='unit.op@nuam.test',
            password='Strong-Password-123!',
        )
        UserProfile.objects.create(user=self.operator, role='operador', country='Chile')
        self.client.force_authenticate(self.operator)

    def test_sha256_fips_180_4_known_vectors(self):
        self.assertEqual(
            hashlib.sha256(b'').hexdigest(),
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        )
        self.assertEqual(
            hashlib.sha256(b'abc').hexdigest(),
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        )

    def test_sha256_chunked_64kb_multichunk_pdf_determinism(self):
        large_pdf = b'%PDF-1.4\n' + (b'NUAM-CHUNK-64KB-' * 12000)
        expected = hashlib.sha256(large_pdf).hexdigest()
        res = self.client.post('/api/v1/tax-records/', {
            'folio': 'UNIT-SHA-64K',
            'rut': '76.543.210-3',
            'company_name': 'Custodia Criptográfica S.A.',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '1500000.00',
            'document_file': SimpleUploadedFile('multi.pdf', large_pdf, content_type='application/pdf'),
        }, format='multipart')
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.data['sha256_hash'], expected)

    def test_modulo11_accepts_valid_numeric_and_k_ruts(self):
        self.assertEqual(compute_rut_dv('76543210'), '3')
        self.assertEqual(compute_rut_dv('77222222'), 'K')
        self.assertEqual(compute_rut_dv('96832450'), '0')
        self.assertTrue(is_valid_chilean_rut('76543210-3'))
        self.assertTrue(is_valid_chilean_rut('77.222.222-k'))
        self.assertEqual(normalize_chilean_rut('76543210-3'), '76.543.210-3')

    def test_modulo11_rejects_altered_check_digit_without_db_write(self):
        initial_count = TaxRecord.objects.count()
        res = self.client.post('/api/v1/tax-records/', {
            'folio': 'UNIT-RUT-BAD',
            'rut': '76.543.210-8',
            'company_name': 'Empresa DV Alterado',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '10000.00',
            'document_file': SimpleUploadedFile('rut.pdf', b'%PDF-1.4\ntest', content_type='application/pdf'),
        }, format='multipart')
        self.assertEqual(res.status_code, 400)
        self.assertIn('rut', res.data)
        self.assertEqual(TaxRecord.objects.count(), initial_count)

    def test_modulo11_rejects_malformed_or_out_of_range_rut(self):
        self.assertFalse(is_valid_chilean_rut('123-4'))
        self.assertFalse(is_valid_chilean_rut('ABC.DEF.GHI-J'))
        self.assertFalse(is_valid_chilean_rut(''))

    def test_decimal_amount_rejects_negative_values_on_api(self):
        res = self.client.post('/api/v1/tax-records/', {
            'folio': 'UNIT-AMT-NEG',
            'rut': '76.543.210-3',
            'company_name': 'Empresa Monto Negativo',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '-5000.50',
            'document_file': SimpleUploadedFile('neg.pdf', b'%PDF-1.4\nneg', content_type='application/pdf'),
        }, format='multipart')
        self.assertEqual(res.status_code, 400)
        self.assertIn('amount', res.data)

    def test_decimal_amount_rejects_alphanumeric_values_on_api(self):
        res = self.client.post('/api/v1/tax-records/', {
            'folio': 'UNIT-AMT-ALPHA',
            'rut': '76.543.210-3',
            'company_name': 'Empresa Monto Alfa',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': 'doce-mil',
            'document_file': SimpleUploadedFile('alp.pdf', b'%PDF-1.4\nalp', content_type='application/pdf'),
        }, format='multipart')
        self.assertEqual(res.status_code, 400)
        self.assertIn('amount', res.data)

    def test_bulk_parser_requires_all_seven_mandatory_columns_xlsx(self):
        wb = Workbook()
        ws = wb.active
        ws.append(['folio', 'rut', 'company_name', 'year', 'doc_type', 'amount'])
        ws.append(['XLSX-MISS', '76.543.210-3', 'Empresa', 2025, 'Certificado tributario', 1000])
        buf = io.BytesIO()
        wb.save(buf)
        xlsx = SimpleUploadedFile(
            'incomplete.xlsx',
            buf.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        )
        res = self.client.post('/api/v1/bulk-upload/validate/', {'file': xlsx}, format='multipart')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.data['missing_columns'], ['origin'])


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    },
)
class FunctionalUseCasesTests(TestCase):
    """Sección 3.2 del Informe: Casos de Uso CU1 a CU6 y pruebas de borde."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.operator = User.objects.create_user(username='cu-op', email='cu.op@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=self.operator, role='operador', country='Chile')
        self.supervisor = User.objects.create_user(username='cu-sup', email='cu.sup@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=self.supervisor, role='supervisor', country='Chile')
        self.admin = User.objects.create_user(username='cu-adm', email='cu.adm@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=self.admin, role='admin', country='Chile')

    def test_cu1_multicriteria_search_combines_rut_year_type_and_status(self):
        TaxRecord.objects.create(
            folio='CU1-MATCH',
            rut='76.543.210-3',
            company_name='Inversiones Andinas S.A.',
            year=2025,
            doc_type='Certificado tributario',
            status='Validado',
            notes='Respaldo auditado SII',
        )
        TaxRecord.objects.create(
            folio='CU1-OTHER',
            rut='96.832.450-0',
            company_name='Otra Sociedad SpA',
            year=2024,
            doc_type='Declaración jurada',
            status='Observado',
        )
        self.client.force_authenticate(self.operator)
        res = self.client.get('/api/v1/tax-records/', {
            'search': 'auditado SII',
            'year': '2025',
            'doc_type': 'Certificado tributario',
            'status': 'Validado',
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data['count'], 1)
        self.assertEqual(res.data['results'][0]['folio'], 'CU1-MATCH')

    def test_cu1_paginated_response_structure_and_page_navigation(self):
        for i in range(25):
            TaxRecord.objects.create(
                folio=f'PAG-{i:03d}',
                rut='76.543.210-3',
                company_name=f'Empresa Paginada {i}',
                year=2025,
            )
        self.client.force_authenticate(self.operator)
        p1 = self.client.get('/api/v1/tax-records/?page=1')
        p2 = self.client.get('/api/v1/tax-records/?page=2')
        self.assertEqual(p1.status_code, 200)
        self.assertEqual(p1.data['count'], 25)
        self.assertEqual(p1.data['total_pages'], 2)
        self.assertEqual(len(p1.data['results']), 20)
        self.assertEqual(len(p2.data['results']), 5)

    def test_cu2_logical_delete_preserves_record_in_database_and_hides_from_list(self):
        rec = TaxRecord.objects.create(
            folio='CU2-SOFTDEL',
            rut='76.543.210-3',
            company_name='Empresa Soft Delete',
            year=2025,
        )
        self.client.force_authenticate(self.supervisor)
        del_res = self.client.delete(f'/api/v1/tax-records/{rec.pk}/')
        self.assertEqual(del_res.status_code, 204)
        rec.refresh_from_db()
        self.assertTrue(rec.is_deleted)
        list_res = self.client.get('/api/v1/tax-records/')
        self.assertEqual(list_res.data['count'], 0)

    def test_cu2_metadata_update_preserves_original_pdf_and_sha256(self):
        self.client.force_authenticate(self.operator)
        pdf_bytes = b'%PDF-1.4\ninmutable-sii-content'
        created = self.client.post('/api/v1/tax-records/', {
            'folio': 'CU2-IMMUT',
            'rut': '76.543.210-3',
            'company_name': 'Empresa Inmutable',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '100000.00',
            'document_file': SimpleUploadedFile('immut.pdf', pdf_bytes, content_type='application/pdf'),
        }, format='multipart')
        rec_id = created.data['id']
        orig_hash = created.data['sha256_hash']

        updated = self.client.patch(f'/api/v1/tax-records/{rec_id}/', {
            'amount': '250000.00',
            'notes': 'Rectificación de monto relacional',
        }, format='multipart')
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data['sha256_hash'], orig_hash)
        dl = self.client.get(f'/api/v1/tax-records/{rec_id}/download_pdf/')
        self.assertEqual(b''.join(dl.streaming_content), pdf_bytes)
        dl.close()

    def test_cu3_bulk_upload_rejects_invalid_modulo11_rut_per_row(self):
        self.client.force_authenticate(self.operator)
        csv_data = (
            b'folio,rut,company_name,year,doc_type,amount,origin\n'
            b'BULK-OK-1,76.543.210-3,Empresa Valida,2025,Certificado tributario,50000,SII\n'
            b'BULK-BAD-RUT,76.543.210-9,Empresa RUT Invalido,2025,Certificado tributario,50000,SII\n'
        )
        val_res = self.client.post(
            '/api/v1/bulk-upload/validate/',
            {'file': SimpleUploadedFile('lote_rut.csv', csv_data, content_type='text/csv')},
            format='multipart',
        )
        self.assertEqual(val_res.status_code, 200)
        self.assertEqual(val_res.data['valid_rows'], 1)
        self.assertEqual(val_res.data['error_rows'], 1)
        self.assertEqual(val_res.data['errors'][0]['row'], 3)

        conf_res = self.client.post('/api/v1/bulk-upload/confirm/', {'job_id': val_res.data['batch_id']}, format='json')
        self.assertEqual(conf_res.status_code, 200)
        self.assertTrue(TaxRecord.objects.filter(folio='BULK-OK-1').exists())
        self.assertFalse(TaxRecord.objects.filter(folio='BULK-BAD-RUT').exists())

    def test_cu4_approval_requires_explicit_comment_and_updates_status(self):
        rec = TaxRecord.objects.create(folio='CU4-REC', rut='76.543.210-3', company_name='Empresa CU4', year=2025)
        app = ApprovalRequest.objects.create(code='SOL-CU4-1', tax_record=rec)
        self.client.force_authenticate(self.supervisor)

        empty_comment = self.client.post(f'/api/v1/approvals/{app.pk}/resolve/', {'action': 'approve', 'comment': ''}, format='json')
        self.assertEqual(empty_comment.status_code, 400)

        ok_res = self.client.post(
            f'/api/v1/approvals/{app.pk}/resolve/',
            {'action': 'approve', 'comment': 'Respaldo cuadrado con DJ 1948'},
            format='json',
        )
        self.assertEqual(ok_res.status_code, 200)
        rec.refresh_from_db()
        self.assertEqual(rec.status, 'Validado')

        conflict_res = self.client.post(
            f'/api/v1/approvals/{app.pk}/resolve/',
            {'action': 'reject', 'comment': 'Intento duplicado'},
            format='json',
        )
        self.assertEqual(conflict_res.status_code, 409)

    def test_cu6_new_account_mandates_2fa_and_one_time_temp_password(self):
        self.client.force_authenticate(self.admin)
        created = self.client.post('/api/v1/admin/users/', {
            'email': 'provisioned@nuam.test',
            'full_name': 'Cuenta Aprovisionada',
            'role': 'operador',
            'country': 'Chile',
        }, format='json')
        self.assertEqual(created.status_code, 201)
        temp_pwd = created.data['temporary_password']
        self.assertTrue(created.data['user']['profile']['is_2fa_enabled'])

        anon = APIClient()
        step1 = anon.post('/api/v1/auth/login/', {'email': 'provisioned@nuam.test', 'password': temp_pwd}, format='json')
        self.assertEqual(step1.status_code, 200)
        self.assertTrue(step1.data['requires_2fa'])


@override_settings(STORAGES={
    'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
})
class IntegrationAndAuditTests(TestCase):
    """Sección 3.3 del Informe: Trazabilidad CU5 en AuditLog y Custodia Criptográfica."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.supervisor = User.objects.create_user(username='int-sup', email='int.sup@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=self.supervisor, role='supervisor', country='Chile')
        self.client.force_authenticate(self.supervisor)

    def test_cu5_audit_log_tracks_create_update_delete_upload_download_approve(self):
        created = self.client.post('/api/v1/tax-records/', {
            'folio': 'AUDIT-ALL-1',
            'rut': '76.543.210-3',
            'company_name': 'Trazabilidad Total S.A.',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '800000.00',
            'document_file': SimpleUploadedFile('trace.pdf', b'%PDF-1.4\ntrace', content_type='application/pdf'),
        }, format='multipart')
        rec_id = created.data['id']
        self.client.patch(f'/api/v1/tax-records/{rec_id}/', {'notes': 'Modificado'}, format='multipart')
        dl = self.client.get(f'/api/v1/tax-records/{rec_id}/download_pdf/')
        dl.close()
        app = ApprovalRequest.objects.create(code='SOL-TRACE-1', tax_record_id=rec_id)
        self.client.post(f'/api/v1/approvals/{app.pk}/resolve/', {'action': 'approve', 'comment': 'OK'}, format='json')
        csv_file = SimpleUploadedFile(
            'trace.csv',
            b'folio,rut,company_name,year,doc_type,amount,origin\nAUDIT-ALL-2,96.832.450-0,Lote,2025,Certificado tributario,100,SII\n',
            content_type='text/csv',
        )
        val = self.client.post('/api/v1/bulk-upload/validate/', {'file': csv_file}, format='multipart')
        self.client.post('/api/v1/bulk-upload/confirm/', {'job_id': val.data['batch_id']}, format='json')
        self.client.delete(f'/api/v1/tax-records/{rec_id}/')

        actions = list(AuditLog.objects.values_list('action', flat=True))
        self.assertTrue(any('Creación de expediente' in a for a in actions))
        self.assertTrue(any('Modificación de expediente' in a for a in actions))
        self.assertTrue(any('Descarga de expediente' in a for a in actions))
        self.assertTrue(any('Aprobación de solicitud' in a for a in actions))
        self.assertTrue(any('Confirmación de carga masiva' in a for a in actions))
        self.assertTrue(any('Borrado lógico de expediente' in a for a in actions))

    def test_tampering_alert_is_recorded_in_audit_log_on_http_409(self):
        rec = TaxRecord.objects.create(folio='TAMPER-LOG-1', rut='76.543.210-3', company_name='Custodia', year=2025)
        rec.document_file.save('orig.pdf', SimpleUploadedFile('orig.pdf', b'%PDF-1.4\nlegit', content_type='application/pdf'))
        st = rec.document_file.storage
        name = rec.document_file.name
        st.delete(name)
        st.save(name, ContentFile(b'%PDF-1.4\ncorrupted-bytes'))

        res = self.client.get(f'/api/v1/tax-records/{rec.pk}/download_pdf/')
        self.assertEqual(res.status_code, 409)
        self.assertTrue(AuditLog.objects.filter(tax_record=rec, action__startswith='Fallo de integridad').exists())

    def test_verify_hash_endpoint_reports_integrity_state(self):
        rec = TaxRecord.objects.create(folio='VER-HASH-1', rut='76.543.210-3', company_name='Verificacion', year=2025)
        rec.document_file.save('ver.pdf', SimpleUploadedFile('ver.pdf', b'%PDF-1.4\nverificado', content_type='application/pdf'))

        ok_verify = self.client.get(f'/api/v1/tax-records/{rec.pk}/verify_hash/')
        self.assertEqual(ok_verify.status_code, 200)
        self.assertTrue(ok_verify.data['is_hash_verified'])

        st = rec.document_file.storage
        name = rec.document_file.name
        st.delete(name)
        st.save(name, ContentFile(b'%PDF-1.4\naltered'))
        bad_verify = self.client.get(f'/api/v1/tax-records/{rec.pk}/verify_hash/')
        self.assertFalse(bad_verify.data['is_hash_verified'])

    def test_download_without_file_returns_404_not_fake_pdf(self):
        rec = TaxRecord.objects.create(folio='NO-FILE-1', rut='76.543.210-3', company_name='Sin PDF', year=2025)
        res = self.client.get(f'/api/v1/tax-records/{rec.pk}/download_pdf/')
        self.assertEqual(res.status_code, 404)

    def test_pdf_upload_rejects_non_pdf_magic_bytes_and_over_25mb(self):
        fake_pdf = SimpleUploadedFile('fake.pdf', b'NOT-A-PDF-HEADER', content_type='application/pdf')
        r1 = self.client.post('/api/v1/tax-records/', {
            'folio': 'FAKE-PDF-1',
            'rut': '76.543.210-3',
            'company_name': 'Fake PDF',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'document_file': fake_pdf,
        }, format='multipart')
        self.assertEqual(r1.status_code, 400)

        huge_pdf = SimpleUploadedFile('huge.pdf', b'%PDF-' + (b'0' * (25 * 1024 * 1024 + 10)), content_type='application/pdf')
        r2 = self.client.post('/api/v1/tax-records/', {
            'folio': 'HUGE-PDF-1',
            'rut': '76.543.210-3',
            'company_name': 'Huge PDF',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'document_file': huge_pdf,
        }, format='multipart')
        self.assertEqual(r2.status_code, 400)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    },
)
class OwaspAndComplianceTests(TestCase):
    """Sección 3.4 del Informe: RBAC (incl. Auditor lectura), 2FA, SQLi, XSS, CORS y Ley 21.719."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.auditor = User.objects.create_user(username='sec-aud', email='auditor@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=self.auditor, role='auditor', country='Chile')
        self.record = TaxRecord.objects.create(
            folio='SEC-REC-1',
            rut='76.543.210-3',
            company_name='Seguridad Tributaria S.A.',
            year=2025,
        )
        self.approval = ApprovalRequest.objects.create(code='SOL-SEC-1', tax_record=self.record)

    def test_rbac_auditor_role_is_strictly_read_only(self):
        self.client.force_authenticate(self.auditor)
        self.assertEqual(self.client.get('/api/v1/tax-records/').status_code, 200)
        self.assertEqual(self.client.get('/api/v1/audit/').status_code, 200)
        self.assertEqual(self.client.get('/api/v1/approvals/').status_code, 200)

        self.assertEqual(self.client.post('/api/v1/tax-records/', {'folio': 'X'}, format='multipart').status_code, 403)
        self.assertEqual(self.client.patch(f'/api/v1/tax-records/{self.record.pk}/', {'notes': 'X'}).status_code, 403)
        self.assertEqual(self.client.delete(f'/api/v1/tax-records/{self.record.pk}/').status_code, 403)
        self.assertEqual(
            self.client.post(f'/api/v1/approvals/{self.approval.pk}/resolve/', {'action': 'approve', 'comment': 'X'}).status_code,
            403,
        )
        self.assertEqual(self.client.post('/api/v1/bulk-upload/validate/', {}).status_code, 403)
        self.assertEqual(self.client.get('/api/v1/admin/users/').status_code, 403)

    def test_owasp_sqli_payloads_neutralized_in_search_and_login(self):
        self.client.force_authenticate(self.auditor)
        r1 = self.client.get('/api/v1/tax-records/', {'search': "1' OR '1'='1"})
        r2 = self.client.get('/api/v1/tax-records/', {'search': "1' UNION SELECT username, password FROM auth_user --"})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.data['count'], 0)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.data['count'], 0)

        anon = APIClient()
        login_sqli = anon.post('/api/v1/auth/login/', {'email': "admin' OR '1'='1", 'password': "x' OR '1'='1"}, format='json')
        self.assertEqual(login_sqli.status_code, 401)

    def test_owasp_xss_script_tags_stored_inert_with_json_and_nosniff(self):
        op = User.objects.create_user(username='xss-op', email='xss.op@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=op, role='operador', country='Chile')
        self.client.force_authenticate(op)
        payload_xss = '<script>alert("xss")</script> Empresa'
        res = self.client.post('/api/v1/tax-records/', {
            'folio': 'XSS-SAFE-1',
            'rut': '76.543.210-3',
            'company_name': payload_xss,
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '1000.00',
            'document_file': SimpleUploadedFile('xss.pdf', b'%PDF-1.4\nxss', content_type='application/pdf'),
        }, format='multipart')
        self.assertEqual(res.status_code, 201)
        self.assertIn('application/json', res['Content-Type'])
        self.assertEqual(res['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(res.data['company_name'], payload_xss)

    @override_settings(CORS_ALLOWED_ORIGINS=['https://nuam-basics.vercel.app'])
    def test_cors_blocks_unauthorized_third_party_vercel_and_wildcard(self):
        trusted = self.client.options(
            '/api/v1/auth/me/',
            HTTP_ORIGIN='https://nuam-basics.vercel.app',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
        )
        self.assertEqual(trusted.get('Access-Control-Allow-Origin'), 'https://nuam-basics.vercel.app')
        lookalike = self.client.options(
            '/api/v1/auth/me/',
            HTTP_ORIGIN='https://nuam-frontend-evil.vercel.app',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
        )
        self.assertIsNone(lookalike.get('Access-Control-Allow-Origin'))

        untrusted_vercel = self.client.options(
            '/api/v1/auth/me/',
            HTTP_ORIGIN='https://external-attacker.vercel.app',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
        )
        self.assertIsNone(untrusted_vercel.get('Access-Control-Allow-Origin'))

    def test_2fa_code_expires_after_five_minutes(self):
        user = User.objects.create_user(username='exp-2fa', email='exp@nuam.test', password='Strong-Password-123!')
        profile = UserProfile.objects.create(user=user, role='operador', country='Chile')
        anon = APIClient()
        anon.post('/api/v1/auth/login/', {'email': user.email, 'password': 'Strong-Password-123!'}, format='json')
        code = re.search(r'\b\d{6}\b', mail.outbox[-1].body).group()

        profile.refresh_from_db()
        profile.two_factor_code_expires_at = timezone.now() - timedelta(seconds=1)
        profile.save(update_fields=['two_factor_code_expires_at'])

        expired = anon.post('/api/v1/auth/login/', {
            'email': user.email,
            'password': 'Strong-Password-123!',
            'two_factor_code': code,
        }, format='json')
        self.assertEqual(expired.status_code, 401)

    def test_account_locks_after_five_failed_2fa_attempts_even_on_new_login(self):
        user = User.objects.create_user(username='lockout-2fa', email='lockout@nuam.test', password='Strong-Password-123!')
        profile = UserProfile.objects.create(user=user, role='operador', country='Chile')
        anon = APIClient()
        creds = {'email': user.email, 'password': 'Strong-Password-123!'}
        anon.post('/api/v1/auth/login/', creds, format='json')
        for _ in range(5):
            anon.post('/api/v1/auth/login/', {**creds, 'two_factor_code': '000000'}, format='json')

        profile.refresh_from_db()
        self.assertIsNotNone(profile.locked_until)
        blocked_step1 = anon.post('/api/v1/auth/login/', creds, format='json')
        self.assertEqual(blocked_step1.status_code, 401)

    def test_login_rate_limiting_blocks_brute_force_with_http_429(self):
        cache.clear()
        anon = APIClient()
        statuses = [
            anon.post('/api/v1/auth/login/', {'email': 'nobody@nuam.test', 'password': 'bad'}, format='json').status_code
            for _ in range(11)
        ]
        self.assertEqual(statuses[:10], [401] * 10)
        self.assertEqual(statuses[10], 429)


@override_settings(STORAGES={
    'default': {'BACKEND': 'django.core.files.storage.InMemoryStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
})
class PerformanceAndIndexingTests(TestCase):
    """Sección 3.5 del Informe: Índices compuestos B-Tree, latencia < 1s / < 2s y estrés de 200 consultas."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.supervisor = User.objects.create_user(username='perf-sup', email='perf@nuam.test', password='Strong-Password-123!')
        UserProfile.objects.create(user=self.supervisor, role='supervisor', country='Chile')
        self.client.force_authenticate(self.supervisor)

    def test_composite_btree_indexes_are_configured_on_taxrecord(self):
        index_names = {idx.name for idx in TaxRecord._meta.indexes}
        self.assertIn('idx_taxrec_folio_rut_year', index_names)
        self.assertIn('idx_taxrec_rut_comp_year', index_names)
        self.assertIn('idx_taxrec_year_type_stat', index_names)

    def test_indexed_search_latency_under_1000ms_and_200_requests_zero_error(self):
        TaxRecord.objects.bulk_create([
            TaxRecord(
                folio=f'BENCH-{i:04d}',
                rut='76.543.210-3' if i % 2 == 0 else '96.832.450-0',
                company_name=f'Sociedad Benchmark {i % 20} S.A.',
                year=2023 + (i % 3),
                country='Chile',
                doc_type='Certificado tributario',
                amount=Decimal('1250000.00'),
                status='Validado' if i % 3 == 0 else 'Pendiente de aprobación',
            )
            for i in range(300)
        ])

        latencies_ms = []
        errors = 0
        for i in range(200):
            t0 = time.perf_counter()
            res = self.client.get('/api/v1/tax-records/', {
                'search': f'Benchmark {i % 20}',
                'year': str(2023 + (i % 3)),
            })
            latencies_ms.append((time.perf_counter() - t0) * 1000)
            if res.status_code != 200:
                errors += 1

        p95 = sorted(latencies_ms)[int(len(latencies_ms) * 0.95) - 1]
        self.assertEqual(errors, 0)
        self.assertLess(p95, 1000.0)

    def test_crud_create_and_update_latency_under_2000ms(self):
        t0 = time.perf_counter()
        created = self.client.post('/api/v1/tax-records/', {
            'folio': 'PERF-WRITE-01',
            'rut': '76.543.210-3',
            'company_name': 'Escritura Rápida SpA',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '450000.00',
            'document_file': SimpleUploadedFile('fast.pdf', b'%PDF-1.4\nfast-write', content_type='application/pdf'),
        }, format='multipart')
        create_ms = (time.perf_counter() - t0) * 1000
        self.assertEqual(created.status_code, 201)
        self.assertLess(create_ms, 2000.0)

        t1 = time.perf_counter()
        updated = self.client.patch(
            f'/api/v1/tax-records/{created.data["id"]}/',
            {'amount': '550000.00', 'notes': 'Actualización medida'},
            format='multipart',
        )
        update_ms = (time.perf_counter() - t1) * 1000
        self.assertEqual(updated.status_code, 200)
        self.assertLess(update_ms, 2000.0)



class ComplianceHardeningTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.operator = User.objects.create_user('op-h', 'op-h@nuam.test', 'Strong-Password-123!')
        UserProfile.objects.create(user=self.operator, role='operador')
        self.supervisor = User.objects.create_user('sup-h', 'sup-h@nuam.test', 'Strong-Password-123!')
        UserProfile.objects.create(user=self.supervisor, role='supervisor')

    def _create(self, folio='H-1', pdf=b'%PDF-1.4\noriginal'):
        return self.client.post('/api/v1/tax-records/', {
            'folio': folio,
            'rut': '76.543.210-3',
            'company_name': f'Empresa {folio}',
            'year': 2025,
            'doc_type': 'Certificado tributario',
            'amount': '1000.00',
            'document_file': SimpleUploadedFile(f'{folio}.pdf', pdf, content_type='application/pdf'),
        }, format='multipart')

    def test_original_pdf_cannot_be_replaced(self):
        self.client.force_authenticate(self.operator)
        created = self._create()
        self.assertEqual(created.status_code, 201)
        response = self.client.patch(f"/api/v1/tax-records/{created.data['id']}/", {
            'document_file': SimpleUploadedFile('otro.pdf', b'%PDF-1.4\notro', content_type='application/pdf'),
        }, format='multipart')
        self.assertEqual(response.status_code, 400)
        record = TaxRecord.objects.get(pk=created.data['id'])
        self.assertEqual(record.sha256_hash, created.data['sha256_hash'])
        download = self.client.get(f'/api/v1/tax-records/{record.pk}/download_pdf/')
        self.assertEqual(b''.join(download.streaming_content), b'%PDF-1.4\noriginal')
        download.close()

    def test_bulk_confirm_works_and_skips_logically_deleted_folio(self):
        self.client.force_authenticate(self.supervisor)
        TaxRecord.objects.create(folio='BORRADO', rut='76.543.210-3', company_name='X', year=2024, is_deleted=True)
        csv_file = SimpleUploadedFile(
            'lote.csv',
            b'folio,rut,company_name,year,doc_type,amount,origin\n'
            b'BORRADO,76.543.210-3,Empresa,2025,Certificado tributario,1000,SII\n'
            b'NUEVO-1,76.111.111-6,Empresa,2025,Certificado tributario,2000,SII\n',
            content_type='text/csv',
        )
        validated = self.client.post('/api/v1/bulk-upload/validate/', {'file': csv_file}, format='multipart')
        self.assertEqual(validated.data['valid_rows'], 1)
        self.assertEqual(validated.data['errors'][0]['fields'], ['folio'])
        self.assertEqual(validated.data['errors'][0]['details'][0]['field'], 'folio')
        confirmed = self.client.post('/api/v1/bulk-upload/confirm/', {'job_id': validated.data['batch_id']}, format='json')
        self.assertEqual(confirmed.status_code, 200)
        self.assertEqual(confirmed.data['created'], 1)
        missing = self.client.post('/api/v1/bulk-upload/confirm/', {'job_id': 99999}, format='json')
        self.assertEqual(missing.status_code, 404)

    def test_bulk_reports_exact_column_for_each_error(self):
        self.client.force_authenticate(self.operator)
        csv_file = SimpleUploadedFile(
            'campos.csv',
            b'folio,rut,company_name,year,doc_type,amount,origin\n'
            b'F1,76.543.210-3,Empresa,abc,Certificado tributario,-5,SII\n'
            b'F2,,Empresa,2025,Certificado tributario,10,SII\n',
            content_type='text/csv',
        )
        response = self.client.post('/api/v1/bulk-upload/validate/', {'file': csv_file}, format='multipart')
        by_row = {error['row']: error for error in response.data['errors']}
        self.assertEqual(by_row[2]['fields'], ['amount', 'year'])
        self.assertEqual(by_row[3]['fields'], ['rut'])

    def test_download_serves_the_exact_bytes_that_were_verified(self):
        self.client.force_authenticate(self.operator)
        created = self._create('H-BYTES', b'%PDF-1.4\nverificado')
        response = self.client.get(f"/api/v1/tax-records/{created.data['id']}/download_pdf/")
        body = b''.join(response.streaming_content)
        response.close()
        self.assertEqual(hashlib.sha256(body).hexdigest(), response['X-Integrity-SHA256'])

    @patch.dict('os.environ', {'VERCEL': '1'})
    def test_audit_ip_uses_forwarded_client_address_behind_proxy(self):
        self.client.force_authenticate(self.supervisor)
        self.client.get('/api/v1/tax-records/', HTTP_X_FORWARDED_FOR='200.1.2.3, 76.76.0.1')
        self.assertTrue(AuditLog.objects.filter(ip_address='200.1.2.3').exists())

    def test_security_headers_and_hardened_settings(self):
        from django.conf import settings as dj_settings
        self.assertTrue(dj_settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(dj_settings.X_FRAME_OPTIONS, 'DENY')
        self.assertIn('x-integrity-sha256', dj_settings.CORS_EXPOSE_HEADERS)
        self.assertEqual(dj_settings.CORS_ALLOWED_ORIGIN_REGEXES, [])
