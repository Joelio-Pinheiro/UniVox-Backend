from rest_framework import serializers
from django.core.validators import validate_email
from .models import User, EmailConfirmation
from univox.email import generate_confirmation_code, send_confirmation_email
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .models import User

#SERIALIZER PARA TESTES
class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'user_name', 'email', 'email_verified', 'description', 'created_at']

class CreateUserSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()
    contact_number = serializers.CharField(max_length=20)

class UpdateUserSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=50, required=False)
    user_name = serializers.CharField(max_length=50, required=False)
    description = serializers.CharField(max_length=200, required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=False)

    def validate(self, data):
        instance = self.instance

        if 'name' in data and User.objects.filter(name__iexact=data['name']).exclude(pk=instance.pk).exists():
            raise serializers.ValidationError({'error': 'This name is already in use.'})
        
        if 'user_name' in data and User.objects.filter(user_name__iexact=data['user_name']).exclude(pk=instance.pk).exists():
            raise serializers.ValidationError({'error': 'This username is already in use.'})

        if 'email' in data and User.objects.filter(email__iexact=data['email']).exclude(pk=instance.pk).exists():
            raise serializers.ValidationError({'error': 'This email is already in use.'})
            
        return data

    def validate_user_name(self, value):
        if not value.startswith('@'):
            value = f'@{value}'
        return value

    def update(self, instance, validated_data):

        instance._email_changed = False 


        new_email = validated_data.get('email')
        if new_email and new_email != instance.email:
            instance.email = new_email
            instance.email_verified = False
            code = generate_confirmation_code()
            EmailConfirmation.objects.update_or_create(
                user=instance,
                defaults={'code': code, 'created_at': timezone.now(), 'is_confirmed': False}
            )
            send_confirmation_email(instance, code)

            instance._email_changed = True


        if 'password' in validated_data:
            instance.password = make_password(validated_data['password'])
        
        instance.name = validated_data.get('name', instance.name)
        instance.user_name = validated_data.get('user_name', instance.user_name)
        instance.description = validated_data.get('description', instance.description)
        instance.email = validated_data.get('email', instance.email)
        
        instance.save()
        return instance

class DeleteUserSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)

class DeleteUserAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordValidateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)


class ResetPasswordChooseNewSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)

class ResetPasswordResend(serializers.Serializer):
    email = serializers.EmailField()