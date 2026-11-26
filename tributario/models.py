import hashlib
from decimal import Decimal
from django.core.validators import MinValueValidator
from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('operador', 'Operador'),
        ('supervisor', 'Supervisor'),
        ('auditor', 'Auditor'),
        ('admin', 'Administrador'),
    )
    COUNTRY_CHOICES = (
        ('Chile', 'Chile'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='operador')
    country = models.CharField(max_length=20, choices=COUNTRY_CHOICES, default='Chile')
    two_factor_code_hash = models.CharField(max_length=128, blank=True, default='')
    two_factor_code_expires_at = models.DateTimeField(null=True, blank=True)
    two_factor_code_sent_at = models.DateTimeField(null=True, blank=True)
    two_factor_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    is_2fa_enabled = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()} - {self.country})"


class TaxRecord(models.Model):
    STATUS_CHOICES = (
        ('Pendiente de aprobación', 'Pendiente de aprobación'),
        ('Validado', 'Validado'),
        ('Observado', 'Observado'),
        ('Pendiente', 'Pendiente'),
    )
    COUNTRY_CHOICES = (
        ('Chile', 'Chile'),
    )

    folio = models.CharField(max_length=50, unique=True, db_index=True)
    rut = models.CharField(max_length=25, db_index=True)
    company_name = models.CharField(max_length=200, db_index=True)
    year = models.IntegerField(default=2025, db_index=True)
    country = models.CharField(max_length=50, choices=COUNTRY_CHOICES, default='Chile', db_index=True)
    doc_type = models.CharField(max_length=100, default='Certificado tributario', db_index=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pendiente de aprobación')
    amount = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))],
    )
    currency = models.CharField(max_length=10, default='CLP')
    origin = models.CharField(max_length=100, default='Bolsa de Santiago')
    document_name = models.CharField(max_length=255, default='documento.pdf')
    document_file = models.FileField(upload_to='documents/', null=True, blank=True)
    sha256_hash = models.CharField(max_length=64, blank=True, default='')
    is_hash_verified = models.BooleanField(default=False)
    version = models.CharField(max_length=50, default='1 · Original')
    notes = models.TextField(blank=True, default='')
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['folio', 'rut', 'year'], name='idx_taxrec_folio_rut_year'),
            models.Index(fields=['rut', 'company_name', 'year'], name='idx_taxrec_rut_comp_year'),
            models.Index(fields=['year', 'doc_type', 'status'], name='idx_taxrec_year_type_stat'),
        ]

    def __str__(self):
        return f"{self.folio} - {self.company_name} ({self.year})"

    def save(self, *args, **kwargs):
        if self.document_file and not self.sha256_hash:
            hasher = hashlib.sha256()
            for chunk in self.document_file.chunks():
                hasher.update(chunk)
            self.sha256_hash = hasher.hexdigest()
            self.is_hash_verified = True
        super().save(*args, **kwargs)


class TaxFactor(models.Model):
    tax_record = models.ForeignKey(TaxRecord, related_name='factors', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    value = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.name}: {self.value}"


class ApprovalRequest(models.Model):
    STATUS_CHOICES = (
        ('Pendiente', 'Pendiente'),
        ('Aprobada', 'Aprobada'),
        ('Rechazada', 'Rechazada'),
    )
    PRIORITY_CHOICES = (
        ('Alta', 'Alta'),
        ('Media', 'Media'),
        ('Baja', 'Baja'),
    )

    code = models.CharField(max_length=50, unique=True, db_index=True)
    tax_record = models.ForeignKey(TaxRecord, related_name='approvals', on_delete=models.CASCADE)
    applicant_name = models.CharField(max_length=100, default='Camila Vargas')
    recipient = models.CharField(max_length=100, default='SII · Chile')
    origin = models.CharField(max_length=100, default='Bolsa de Santiago')
    reason = models.TextField(default='Entrega de respaldo del certificado tributario correspondiente al ejercicio 2025.')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pendiente')
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='Alta')
    decision_comment = models.TextField(blank=True, default='')
    decided_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    decided_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.code} - {self.tax_record.company_name} ({self.status})"


class AuditLog(models.Model):
    tax_record = models.ForeignKey(TaxRecord, null=True, blank=True, related_name='audit_logs', on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    user_name = models.CharField(max_length=100, default='Sistema')
    result = models.CharField(max_length=100, default='Completado')
    ip_address = models.CharField(max_length=50, default='127.0.0.1')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} - {self.action} ({self.user_name})"


class BulkUploadJob(models.Model):
    filename = models.CharField(max_length=255)
    total_rows = models.IntegerField(default=0)
    valid_rows = models.IntegerField(default=0)
    warning_rows = models.IntegerField(default=0)
    error_rows = models.IntegerField(default=0)
    status = models.CharField(max_length=50, default='Validado')
    errors_json = models.JSONField(default=list)
    valid_payload = models.JSONField(default=list)
    uploaded_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.filename} ({self.status} - {self.total_rows} filas)"
