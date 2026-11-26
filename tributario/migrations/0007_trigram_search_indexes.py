from django.db import migrations

COLUMNS = ('folio', 'rut', 'company_name', 'doc_type', 'origin')


def create_trigram_indexes(apps, schema_editor):
    """Indices GIN trigram para que icontains (LIKE '%x%') no recorra toda la tabla."""
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')
        for column in COLUMNS:
            cursor.execute(
                f'CREATE INDEX IF NOT EXISTS idx_taxrec_{column}_trgm '
                f'ON tributario_taxrecord USING gin (UPPER("{column}"::text) gin_trgm_ops)'
            )


def drop_trigram_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        for column in COLUMNS:
            cursor.execute(f'DROP INDEX IF EXISTS idx_taxrec_{column}_trgm')


class Migration(migrations.Migration):
    dependencies = [('tributario', '0006_align_indexes_roles_and_validators')]
    operations = [migrations.RunPython(create_trigram_indexes, drop_trigram_indexes)]
