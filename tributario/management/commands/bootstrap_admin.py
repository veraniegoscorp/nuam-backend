from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from tributario.models import UserProfile


class Command(BaseCommand):
    help = 'Asigna el rol de administrador inicial a una cuenta existente.'

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True)

    def handle(self, *args, **options):
        if UserProfile.objects.filter(role='admin').exists():
            raise CommandError('Ya existe un administrador; usa el panel para gestionar cuentas.')
        user = User.objects.filter(email__iexact=options['email']).first()
        if user is None:
            raise CommandError('No existe una cuenta con ese correo. Créala primero con createsuperuser.')
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = 'admin'
        profile.save(update_fields=['role'])
        self.stdout.write(self.style.SUCCESS(f'Rol administrador asignado a {user.email}.'))
