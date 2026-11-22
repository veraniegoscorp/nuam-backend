from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured


class SupabaseStorage(Storage):
    def __init__(self):
        self.base_url = settings.SUPABASE_URL.rstrip('/')
        self.api_key = settings.SUPABASE_STORAGE_KEY
        self.use_bearer_auth = settings.SUPABASE_STORAGE_USE_BEARER
        self.bucket = quote(settings.SUPABASE_STORAGE_BUCKET, safe='')
        if not self.base_url or not self.api_key:
            raise ImproperlyConfigured('Configura las credenciales privadas de Supabase Storage.')

    def _object_url(self, name):
        return f'{self.base_url}/storage/v1/object/{self.bucket}/{quote(name, safe="/")}'

    def _request(self, method, name, data=None, content_type=None):
        headers = {'apikey': self.api_key}
        if self.use_bearer_auth:
            headers['Authorization'] = f'Bearer {self.api_key}'
        if content_type:
            headers['Content-Type'] = content_type
        if method == 'POST':
            headers['x-upsert'] = 'false'
        request = Request(self._object_url(name), data=data, headers=headers, method=method)
        with urlopen(request, timeout=30) as response:
            return response.read(), response.headers

    def _open(self, name, mode='rb'):
        content, _ = self._request('GET', name)
        return ContentFile(content, name=name)

    def _save(self, name, content):
        content_type = getattr(content, 'content_type', None) or 'application/octet-stream'
        data = b''.join(content.chunks())
        self._request('POST', name, data=data, content_type=content_type)
        return name

    def delete(self, name):
        try:
            self._request('DELETE', name)
        except HTTPError as error:
            if error.code != 404:
                raise

    def exists(self, name):
        try:
            self._request('HEAD', name)
            return True
        except HTTPError as error:
            if error.code == 404:
                return False
            raise

    def size(self, name):
        _, headers = self._request('HEAD', name)
        return int(headers['Content-Length'])

    def url(self, name):
        raise ValueError('Los documentos son privados y se sirven mediante la API autenticada.')
