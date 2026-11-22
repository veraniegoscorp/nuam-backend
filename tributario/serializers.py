import hashlib

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, TaxRecord, TaxFactor, ApprovalRequest, AuditLog, BulkUploadJob


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['role', 'country', 'is_2fa_enabled']


class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'profile']


class UserNameUpdateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=150, allow_blank=False)
    last_name = serializers.CharField(max_length=150, allow_blank=True, required=False)

    class Meta:
        model = User
        fields = ['first_name', 'last_name']


class AdminUserCreateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    full_name = serializers.CharField(max_length=150)
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES)
    country = serializers.ChoiceField(choices=UserProfile.COUNTRY_CHOICES, required=False, default='Chile')

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError('Ya existe una cuenta con ese correo.')
        return value


class TaxFactorSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaxFactor
        fields = ['id', 'name', 'value']


class AuditLogSerializer(serializers.ModelSerializer):
    formatted_date = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ['id', 'tax_record', 'action', 'user_name', 'result', 'ip_address', 'timestamp', 'formatted_date']

    def get_formatted_date(self, obj):
        return obj.timestamp.strftime('%d/%m/%Y · %H:%M')


class TaxRecordListSerializer(serializers.ModelSerializer):
    formatted_amount = serializers.SerializerMethodField()
    sha256_hash = serializers.SerializerMethodField()
    is_hash_verified = serializers.SerializerMethodField()

    class Meta:
        model = TaxRecord
        fields = [
            'id', 'folio', 'rut', 'company_name', 'year', 'country',
            'doc_type', 'status', 'amount', 'currency', 'formatted_amount',
            'origin', 'document_name', 'sha256_hash', 'is_hash_verified',
            'version', 'created_at', 'updated_at'
        ]

    def get_formatted_amount(self, obj):
        try:
            return f"{obj.currency} {int(obj.amount):,}".replace(',', '.')
        except Exception:
            return f"{obj.currency} {obj.amount}"

    def get_sha256_hash(self, obj):
        return obj.sha256_hash if obj.document_file else ''

    def get_is_hash_verified(self, obj):
        return bool(obj.document_file and obj.is_hash_verified and obj.sha256_hash)


class TaxRecordDetailSerializer(serializers.ModelSerializer):
    factors = TaxFactorSerializer(many=True, read_only=True)
    audit_logs = AuditLogSerializer(many=True, read_only=True)
    formatted_amount = serializers.SerializerMethodField()
    sha256_hash = serializers.SerializerMethodField()
    is_hash_verified = serializers.SerializerMethodField()
    document_file = serializers.FileField(write_only=True, required=False, allow_null=True)

    class Meta:
        model = TaxRecord
        fields = [
            'id', 'folio', 'rut', 'company_name', 'year', 'country',
            'doc_type', 'status', 'amount', 'currency', 'formatted_amount',
            'origin', 'document_name', 'document_file', 'sha256_hash',
            'is_hash_verified', 'version', 'notes', 'factors', 'audit_logs',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'sha256_hash', 'is_hash_verified', 'created_at', 'updated_at',
            'factors', 'audit_logs', 'status',
        ]

    def get_formatted_amount(self, obj):
        try:
            return f"{obj.currency} {int(obj.amount):,}".replace(',', '.')
        except Exception:
            return f"{obj.currency} {obj.amount}"

    def get_sha256_hash(self, obj):
        return obj.sha256_hash if obj.document_file else ''

    def get_is_hash_verified(self, obj):
        return bool(obj.document_file and obj.is_hash_verified and obj.sha256_hash)

    def validate_document_file(self, value):
        if value.size > 25 * 1024 * 1024:
            raise serializers.ValidationError('El documento no puede superar 25 MB.')
        if not value.name.lower().endswith('.pdf') or value.read(5) != b'%PDF-':
            raise serializers.ValidationError('Solo se aceptan documentos PDF válidos.')
        value.seek(0)
        digest = hashlib.sha256()
        for chunk in value.chunks():
            digest.update(chunk)
        value.seek(0)
        duplicates = TaxRecord.objects.filter(
            sha256_hash=digest.hexdigest(),
            is_deleted=False,
        )
        if self.instance:
            duplicates = duplicates.exclude(pk=self.instance.pk)
        if duplicates.exists():
            raise serializers.ValidationError('Este documento ya está registrado.')
        return value

    def validate(self, attrs):
        if not self.instance and not attrs.get('document_file'):
            raise serializers.ValidationError({'document_file': 'Adjunta el documento original en PDF.'})
        rut = attrs.get('rut', self.instance.rut if self.instance else None)
        year = attrs.get('year', self.instance.year if self.instance else None)
        company_name = attrs.get('company_name', self.instance.company_name if self.instance else None)
        doc_type = attrs.get('doc_type', self.instance.doc_type if self.instance else None)
        duplicate = TaxRecord.objects.filter(
            rut=rut,
            year=year,
            company_name=company_name,
            doc_type=doc_type,
            is_deleted=False,
        )
        if self.instance:
            duplicate = duplicate.exclude(pk=self.instance.pk)
        if duplicate.exists():
            raise serializers.ValidationError('Ya existe un expediente con los mismos datos tributarios.')
        return attrs

    def update(self, instance, validated_data):
        if 'document_file' in validated_data:
            instance.sha256_hash = ''
            instance.is_hash_verified = False
        return super().update(instance, validated_data)


class ApprovalRequestSerializer(serializers.ModelSerializer):
    tax_record_detail = TaxRecordListSerializer(source='tax_record', read_only=True)
    formatted_date = serializers.SerializerMethodField()

    class Meta:
        model = ApprovalRequest
        fields = [
            'id', 'code', 'tax_record', 'tax_record_detail', 'applicant_name',
            'recipient', 'origin', 'reason', 'status', 'priority',
            'decision_comment', 'decided_by', 'decided_at', 'created_at',
            'formatted_date'
        ]

    def get_formatted_date(self, obj):
        return obj.created_at.strftime('%d/%m/%Y · %H:%M')


class ApprovalResolveSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    comment = serializers.CharField(max_length=500, required=True, allow_blank=False)


class BulkUploadJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulkUploadJob
        fields = '__all__'
