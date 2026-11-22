# Generated for NUAM Evaluation 3

from django.db import migrations, models


def migrate_auditors(apps, schema_editor):
    UserProfile = apps.get_model('tributario', 'UserProfile')
    UserProfile.objects.filter(role='auditor').update(role='operador')


class Migration(migrations.Migration):

    dependencies = [
        ('tributario', '0004_restrict_supabase_api_roles'),
    ]

    operations = [
        migrations.RunPython(migrate_auditors, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('operador', 'Operador'),
                    ('supervisor', 'Supervisor'),
                    ('admin', 'Administrador'),
                ],
                default='operador',
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='country',
            field=models.CharField(
                choices=[('Chile', 'Chile')],
                default='Chile',
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name='taxrecord',
            name='country',
            field=models.CharField(
                choices=[('Chile', 'Chile')],
                db_index=True,
                default='Chile',
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name='bulkuploadjob',
            name='valid_payload',
            field=models.JSONField(default=list),
        ),
    ]
