import hashlib
import re
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from .models import ApprovalRequest, TaxRecord, UserProfile
from .storage import SupabaseStorage


class SecurityAndAccessTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.operator = self.create_user('operator@nuam.test', 'operador')
        self.supervisor = self.create_user('supervisor@nuam.test', 'supervisor')
        self.auditor = self.create_user('auditor@nuam.test', 'auditor')
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

    def test_anonymous_access_is_denied(self):
        response = self.client.get('/api/v1/tax-records/')
        self.assertEqual(response.status_code, 401)

    def test_cors_is_local_only_and_bulk_upload_is_disabled(self):
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
        self.assertEqual(response.status_code, 501)

    def test_only_admin_can_create_users(self):
        payload = {
            'email': 'new.user@nuam.test',
            'full_name': 'Nuevo Usuario',
            'role': 'auditor',
            'country': 'Chile',
        }
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.post('/api/v1/admin/users/', payload, format='json').status_code, 403)

        self.client.force_authenticate(self.admin)
        response = self.client.post('/api/v1/admin/users/', payload, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['user']['profile']['role'], 'auditor')
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
        admin_user = User.objects.create_superuser(
            username='django-admin',
            email='django-admin@nuam.test',
            password='Strong-Admin-Password-123!',
        )
        self.client.force_login(admin_user)

    def test_admin_home_has_direct_create_user_action(self):
        response = self.client.get(reverse('admin:index'))

        self.assertContains(response, 'Hola, django-admin')
        self.assertContains(response, 'Crear usuario')
        self.assertContains(response, reverse('admin:auth_user_add'))

    def test_admin_creates_application_user_with_role_and_email(self):
        add_url = reverse('admin:auth_user_add')
        add_page = self.client.get(add_url)
        add_form = add_page.context['adminform'].form
        self.assertIn('email', add_form.fields)
        self.assertIn('role', add_form.fields)
        data = {
            'username': 'new-operator',
            'email': 'new.operator@nuam.test',
            'first_name': 'Nuevo',
            'last_name': 'Operador',
            'role': 'operador',
            'country': 'Chile',
            'password1': 'F8!Kq3z#vR2mD7xL',
            'password2': 'F8!Kq3z#vR2mD7xL',
            '_save': 'Guardar',
        }

        response = self.client.post(add_url, data)

        self.assertEqual(response.status_code, 302)
        user = User.objects.get(email='new.operator@nuam.test')
        self.assertTrue(user.check_password('F8!Kq3z#vR2mD7xL'))
        self.assertEqual(user.profile.role, 'operador')
        self.assertEqual(user.profile.country, 'Chile')
        self.assertTrue(user.profile.is_2fa_enabled)


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
