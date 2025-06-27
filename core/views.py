from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from django.utils import timezone
from django.contrib.auth.hashers import check_password, make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import User, EmailConfirmation, PasswordReset
from univox.email import generate_confirmation_code, send_confirmation_email, is_code_expired, send_password_confirmation_code

from .serializers import (
    CreateUserSerializer,
    DeleteUserSerializer,
    LoginUserSerializer,
    VerifyEmailSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordValidateSerializer,
    ResetPasswordChooseNewSerializer,
)

@swagger_auto_schema(method='post', request_body=CreateUserSerializer)
@api_view(['POST'])
def create_user(request):
    data = request.data
    required_fields = ['name', 'password', 'email', 'contact_number']
    missing_fields = [field for field in required_fields if not data.get(field)]

    if missing_fields:
        return Response({'error': f'Missing required fields: {", ".join(missing_fields)}.'}, status=status.HTTP_400_BAD_REQUEST)

    name = data['name']
    password = data['password']
    email = data['email']
    contact_number = data['contact_number']

    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email format.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(name__iexact=name).exists():
        return Response({'error': 'Name already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        existing_user = User.objects.get(name=name)
        existing_confirmation = EmailConfirmation.objects.get(user=existing_user)

        if not is_code_expired(existing_confirmation.created_at):
            return Response({'error': 'Cannot use this name right now!'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            existing_user.delete()

    except (User.DoesNotExist, EmailConfirmation.DoesNotExist):
        pass

    hashed_password = make_password(password)
    user = User.objects.create(name=name, password=hashed_password, email=email, contact_number=contact_number)

    code = generate_confirmation_code()
    EmailConfirmation.objects.create(user=user, code=code)
    send_confirmation_email(user, code)

    return Response({'message': 'Verification code sent to email.', 'user_id': user.id})


@swagger_auto_schema(method='post', request_body=DeleteUserSerializer)
@api_view(['POST'])
def delete_user(request):
    name = request.data.get('name')

    if not User.objects.filter(name__iexact=name).exists():
        return Response({'error': 'Name does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.get(name=name)
    user.delete()

    return Response({'message': 'User deleted successfully.', 'user_name': name})


@swagger_auto_schema(method='post', request_body=LoginUserSerializer)
@api_view(['POST'])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Email and Password required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

    if check_password(password, user.password) and user.email_verified:
        request.session['logged'] = True
        return Response({'message': 'Authentication successful.', 'user_id': user.id})
    else:
        return Response({'error': 'Authentication Failed.'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def logout_user(request):
    if (not request.session['logged']):
        return JsonResponse({'error': 'There is not user logged in.'}, status=401)
    
    request.session.flush()
    return Response({'message': 'Logged out successfully.'})

@swagger_auto_schema(method='post', request_body=VerifyEmailSerializer)
@api_view(['POST'])
def verify_email(request):
    email_input = request.data.get('email')
    code_input = request.data.get('code')

    try:
        user = User.objects.get(email=email_input)
    except User.DoesNotExist:
        return Response({'error': 'Unknown user.'}, status=status.HTTP_401_UNAUTHORIZED)

    if user.email_verified:
        return Response({'error': 'User already verified!'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        confirmation = EmailConfirmation.objects.get(user=user, code=code_input)

        if is_code_expired(confirmation.created_at):
            user.delete()
            return Response({'error': 'Code expired!'}, status=status.HTTP_401_UNAUTHORIZED)

        if code_input != confirmation.code:
            return Response({'error': 'Invalid code!'}, status=status.HTTP_401_UNAUTHORIZED)

        confirmation.is_confirmed = True
        confirmation.save()

        user.email_verified = True
        user.save()

        return Response({'message': 'User verified!'})
    except EmailConfirmation.DoesNotExist:
        return Response({'error': 'Unknown confirmation request!'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(method='post', request_body=ResetPasswordRequestSerializer)
@api_view(['POST'])
def reset_password_request(request):
    email = request.data.get('email')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Unknown user.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if is_code_expired(password_confirmation.created_at):
            password_confirmation.delete()
        else:
            return Response({'error': 'A password recovery request already exists.'}, status=status.HTTP_401_UNAUTHORIZED)
    except PasswordReset.DoesNotExist:
        pass

    code = generate_confirmation_code()
    PasswordReset.objects.create(user=user, code=code)
    send_password_confirmation_code(user, code)

    return Response({'message': 'Verification code sent to email.'})

@swagger_auto_schema(method='post', request_body=ResetPasswordValidateSerializer)
@api_view(['POST'])
def reset_password_validate(request):
    email = request.data.get('email')
    code = request.data.get('code')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Unknown user.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if is_code_expired(password_confirmation.created_at):
            password_confirmation.delete()
            return Response({'error': 'Password recovery code expired.'}, status=status.HTTP_401_UNAUTHORIZED)

        if code != password_confirmation.code:
            return Response({'error': 'Invalid code!'}, status=status.HTTP_401_UNAUTHORIZED)

        password_confirmation.is_confirmed = True
        password_confirmation.save()
        return Response({'Message': 'Password recovery code confirmed!'})
    except PasswordReset.DoesNotExist:
        return Response({'error': 'No password recovery request exists.'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(method='post', request_body=ResetPasswordChooseNewSerializer)
@api_view(['POST'])
def reset_password_chooseNew(request):
    email = request.data.get('email')
    newPassword = request.data.get('new_password')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Unknown user.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if password_confirmation.is_confirmed:
            user.password = make_password(newPassword)
            user.save()
            return Response({'message': 'Password successfully changed!'})
        else:
            return Response({'error': 'Password request not validated yet!'}, status=status.HTTP_401_UNAUTHORIZED)
    except PasswordReset.DoesNotExist:
        return Response({'error': 'No password recovery request exists.'}, status=status.HTTP_401_UNAUTHORIZED)
