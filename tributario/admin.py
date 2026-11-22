from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import UserProfile


class NuamUserCreationForm(UserCreationForm):
    role = forms.ChoiceField(
        choices=UserProfile.ROLE_CHOICES,
        label='Rol en NUAM',
        initial='operador',
    )
    country = forms.ChoiceField(
        choices=UserProfile.COUNTRY_CHOICES,
        label='País',
        initial='Chile',
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'role', 'country')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].label = 'Usuario'
        self.fields['username'].help_text = (
            'Identificador interno. Para iniciar sesión, se usará el correo electrónico.'
        )
        self.fields['email'].label = 'Correo electrónico'
        self.fields['email'].required = True
        self.fields['first_name'].label = 'Nombre'
        self.fields['first_name'].required = True
        self.fields['last_name'].label = 'Apellido'
        self.fields['password1'].label = 'Contraseña inicial'
        self.fields['password2'].label = 'Confirmar contraseña'

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError('Ya existe una cuenta con ese correo.')
        return email


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    extra = 1
    max_num = 1
    can_delete = False
    fields = ('role', 'country')
    verbose_name = 'Acceso a la plataforma NUAM'
    verbose_name_plural = 'Acceso a la plataforma NUAM'


class NuamUserAdmin(UserAdmin):
    add_form = NuamUserCreationForm
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username',
                'email',
                'first_name',
                'last_name',
                'role',
                'country',
                'password1',
                'password2',
            ),
        }),
    )
    inlines = (UserProfileInline,)
    list_display = (
        'username',
        'email',
        'first_name',
        'last_name',
        'nuam_role',
        'is_active',
    )
    list_filter = ('is_active', 'profile__role', 'profile__country')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('email',)

    def get_inline_instances(self, request, obj=None):
        if obj is None:
            return []
        return super().get_inline_instances(request, obj)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:
            UserProfile.objects.create(
                user=obj,
                role=form.cleaned_data['role'],
                country=form.cleaned_data['country'],
            )

    @admin.display(description='Rol NUAM', ordering='profile__role')
    def nuam_role(self, obj):
        try:
            return obj.profile.get_role_display()
        except UserProfile.DoesNotExist:
            return 'Sin configurar'


admin.site.unregister(User)
admin.site.register(User, NuamUserAdmin)
admin.site.site_header = 'NUAM · Administración'
admin.site.site_title = 'NUAM Admin'
admin.site.index_title = 'Centro de administración'
admin.site.index_template = 'tributario/admin/index.html'
