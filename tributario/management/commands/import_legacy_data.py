from django.core.management.base import BaseCommand, CommandError
from django.db import connections, transaction

from tributario.models import ApprovalRequest, AuditLog, BulkUploadJob, TaxFactor, TaxRecord


class Command(BaseCommand):
    help = 'Importa registros de negocio desde db.sqlite3 a PostgreSQL sin sobrescribir datos.'

    def handle(self, *args, **options):
        if 'legacy' not in connections.databases:
            raise CommandError('Configura PostgreSQL en DB_* antes de importar datos.')
        if connections['default'].vendor != 'postgresql':
            raise CommandError('La base de destino debe ser PostgreSQL.')

        source = connections['legacy']
        if not source.introspection.table_names():
            raise CommandError('La base SQLite de origen no contiene tablas.')
        if 'tributario_taxrecord' not in source.introspection.table_names():
            raise CommandError('La base SQLite de origen no contiene expedientes tributarios.')
        if TaxRecord.objects.using('legacy').filter(document_file__gt='').exists():
            raise CommandError(
                'Hay archivos locales; configura Supabase Storage y migra los objetos antes de importar.'
            )

        counts = {'records': 0, 'factors': 0, 'approvals': 0, 'audit_logs': 0, 'upload_jobs': 0}
        record_map = {}
        with transaction.atomic(using='default'):
            for old in TaxRecord.objects.using('legacy').all().iterator():
                record, created = TaxRecord.objects.using('default').get_or_create(
                    folio=old.folio,
                    defaults={
                        'rut': old.rut,
                        'company_name': old.company_name,
                        'year': old.year,
                        'country': old.country,
                        'doc_type': old.doc_type,
                        'status': old.status,
                        'amount': old.amount,
                        'currency': old.currency,
                        'origin': old.origin,
                        'document_name': old.document_name,
                        'sha256_hash': '',
                        'is_hash_verified': False,
                        'version': old.version,
                        'notes': old.notes,
                        'is_deleted': old.is_deleted,
                    },
                )
                if created:
                    TaxRecord.objects.using('default').filter(pk=record.pk).update(
                        created_at=old.created_at,
                        updated_at=old.updated_at,
                    )
                    counts['records'] += 1
                record_map[old.pk] = record

            for old_factor in TaxFactor.objects.using('legacy').select_related('tax_record').iterator():
                record = record_map[old_factor.tax_record_id]
                _, created = TaxFactor.objects.using('default').get_or_create(
                    tax_record=record,
                    name=old_factor.name,
                    value=old_factor.value,
                )
                counts['factors'] += int(created)

            for old in ApprovalRequest.objects.using('legacy').select_related('tax_record').iterator():
                record = record_map[old.tax_record_id]
                approval, created = ApprovalRequest.objects.using('default').get_or_create(
                    code=old.code,
                    defaults={
                        'tax_record': record,
                        'applicant_name': old.applicant_name,
                        'recipient': old.recipient,
                        'origin': old.origin,
                        'reason': old.reason,
                        'status': old.status,
                        'priority': old.priority,
                        'decision_comment': old.decision_comment,
                        'decided_at': old.decided_at,
                    },
                )
                if created:
                    ApprovalRequest.objects.using('default').filter(pk=approval.pk).update(
                        created_at=old.created_at,
                    )
                    counts['approvals'] += 1

            for old in AuditLog.objects.using('legacy').select_related('tax_record').iterator():
                record = record_map.get(old.tax_record_id) if old.tax_record_id else None
                exists = AuditLog.objects.using('default').filter(
                    tax_record=record,
                    action=old.action,
                    user_name=old.user_name,
                    result=old.result,
                    ip_address=old.ip_address,
                    timestamp=old.timestamp,
                ).exists()
                if not exists:
                    entry = AuditLog.objects.using('default').create(
                        tax_record=record,
                        action=old.action,
                        user_name=old.user_name,
                        result=old.result,
                        ip_address=old.ip_address,
                    )
                    AuditLog.objects.using('default').filter(pk=entry.pk).update(timestamp=old.timestamp)
                    counts['audit_logs'] += 1

            for old in BulkUploadJob.objects.using('legacy').iterator():
                exists = BulkUploadJob.objects.using('default').filter(
                    filename=old.filename,
                    status=old.status,
                    created_at=old.created_at,
                ).exists()
                if not exists:
                    job = BulkUploadJob.objects.using('default').create(
                        filename=old.filename,
                        total_rows=old.total_rows,
                        valid_rows=old.valid_rows,
                        warning_rows=old.warning_rows,
                        error_rows=old.error_rows,
                        status=old.status,
                        errors_json=old.errors_json,
                    )
                    BulkUploadJob.objects.using('default').filter(pk=job.pk).update(
                        created_at=old.created_at,
                    )
                    counts['upload_jobs'] += 1

        self.stdout.write(self.style.SUCCESS(
            'Importación aditiva completada: '
            + ', '.join(f'{name}={count}' for name, count in counts.items())
            + '. Las cuentas demo no se importaron.'
        ))
