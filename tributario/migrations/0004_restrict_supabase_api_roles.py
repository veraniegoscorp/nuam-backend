from django.db import migrations


TABLES = (
    'auth_group',
    'auth_group_permissions',
    'auth_permission',
    'auth_user',
    'auth_user_groups',
    'auth_user_user_permissions',
    'django_admin_log',
    'django_content_type',
    'django_migrations',
    'django_session',
    'token_blacklist_blacklistedtoken',
    'token_blacklist_outstandingtoken',
    'tributario_approvalrequest',
    'tributario_auditlog',
    'tributario_bulkuploadjob',
    'tributario_taxfactor',
    'tributario_taxrecord',
    'tributario_userprofile',
)

SEQUENCES = (
    'auth_group_id_seq',
    'auth_permission_id_seq',
    'auth_user_id_seq',
    'django_admin_log_id_seq',
    'django_content_type_id_seq',
    'token_blacklist_blacklistedtoken_id_seq',
    'token_blacklist_outstandingtoken_id_seq',
    'tributario_approvalrequest_id_seq',
    'tributario_auditlog_id_seq',
    'tributario_bulkuploadjob_id_seq',
    'tributario_taxfactor_id_seq',
    'tributario_taxrecord_id_seq',
    'tributario_userprofile_id_seq',
)


def restrict_postgrest_roles(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f'REVOKE ALL PRIVILEGES ON TABLE public.{table} FROM anon, authenticated')
            cursor.execute(f'ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY')
        for sequence in SEQUENCES:
            cursor.execute(
                'SELECT to_regclass(%s)',
                [f'public.{sequence}'],
            )
            if cursor.fetchone()[0]:
                cursor.execute(
                    f'REVOKE ALL PRIVILEGES ON SEQUENCE public.{sequence} FROM anon, authenticated'
                )


class Migration(migrations.Migration):
    dependencies = [
        ('tributario', '0003_alter_taxrecord_is_hash_verified'),
    ]

    operations = [
        migrations.RunPython(restrict_postgrest_roles, migrations.RunPython.noop),
    ]
