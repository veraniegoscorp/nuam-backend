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
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile']


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


class TaxRecordDetailSerializer(serializers.ModelSerializer):
    factors = TaxFactorSerializer(many=True, read_only=True)
    audit_logs = AuditLogSerializer(many=True, read_only=True)
    formatted_amount = serializers.SerializerMethodField()

    class Meta:
        model = TaxRecord
        fields = [
            'id', 'folio', 'rut', 'company_name', 'year', 'country',
            'doc_type', 'status', 'amount', 'currency', 'formatted_amount',
            'origin', 'document_name', 'document_file', 'sha256_hash',
            'is_hash_verified', 'version', 'notes', 'factors', 'audit_logs',
            'created_at', 'updated_at'
        ]

    def get_formatted_amount(self, obj):
        try:
            return f"{obj.currency} {int(obj.amount):,}".replace(',', '.')
        except Exception:
            return f"{obj.currency} {obj.amount}"


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
