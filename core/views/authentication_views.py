from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from django.utils import timezone
from django.contrib.auth.hashers import check_password, make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from ..models import User, EmailConfirmation, PasswordReset
from univox.email import generate_confirmation_code, send_confirmation_email, is_code_expired, send_password_confirmation_code

from ..serializers import (
    CreateUserSerializer,
    DeleteUserSerializer,
    LoginUserSerializer,
    VerifyEmailSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordValidateSerializer,
    ResetPasswordChooseNewSerializer,
    ResetPasswordResend,
    UserListSerializer,
    UpdateUserSerializer,
    DeleteUserAccountSerializer
)

#GET PARA TESTES
@api_view(['GET'])
def list_users(request):

    users = User.objects.all().order_by('id')
    serializer = UserListSerializer(users, many=True)
    return Response(serializer.data)

@swagger_auto_schema(method='post', request_body=CreateUserSerializer)
@api_view(['POST'])
def create_user(request):
    data = request.data
    required_fields = ['name', 'password', 'email']
    missing_fields = [field for field in required_fields if not data.get(field)]

    if missing_fields:
        return Response({'error': f'Campos em branco: {", ".join(missing_fields)}.'}, status=status.HTTP_400_BAD_REQUEST)

    name = data['name']
    password = data['password']
    email = data['email']

    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Formato de email inválido.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(name__iexact=name).exists():
        return Response({'error': 'Nome já em uso.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'Esse email já está em uso.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        email_prefix = email.split('@')[0]
        user_name = f'@{email_prefix}'
    except IndexError:
        return Response({'error': 'Formato de email inválido.'}, status=status.HTTP_400_BAD_REQUEST)
    
    if User.objects.filter(user_name__iexact=user_name).exists():
        return Response({'error': 'Já existe um usuário com esse nome de usuário derivado de e-mail.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        existing_user = User.objects.get(name=name)
        existing_confirmation = EmailConfirmation.objects.get(user=existing_user)

        if not is_code_expired(existing_confirmation.created_at):
            return Response({'error': 'Não é possível usar este nome agora!'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            existing_user.delete()

    except (User.DoesNotExist, EmailConfirmation.DoesNotExist):
        pass

    hashed_password = make_password(password)
    user = User.objects.create(name=name, password=hashed_password, email=email, user_name=user_name)

    code = generate_confirmation_code()
    EmailConfirmation.objects.create(user=user, code=code)
    send_confirmation_email(user, code)

    return Response({'message': 'Código de verificação enviado ao email.', 'user_id': user.id})

@swagger_auto_schema(method='patch', request_body=UpdateUserSerializer)
@api_view(['PATCH'])
def update_user_profile(request):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_id = request.session.get('user_id')
        user_instance = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'Usuário não encotrado.'}, status=status.HTTP_404_NOT_FOUND)

    serializer = UpdateUserSerializer(instance=user_instance, data=request.data, partial=True)
    
    if serializer.is_valid():
        updated_user = serializer.save()

        if getattr(updated_user, '_email_changed', False):
            return Response({
                'message': 'Perfil atualizado. Código de confirmação de email enviado. Por favor verificar.'
            }, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Perfil atualizado com sucesso.'}, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='delete', request_body=DeleteUserSerializer)
@api_view(['DELETE'])
def delete_user_by_name(request):
    name = request.data.get('name')

    if not User.objects.filter(name__iexact=name).exists():
        return Response({'error': 'Não existe um usuário com este nome.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.get(name=name)
    user.delete()

    return Response({'message': 'Conta do usuário removida.', 'user_name': name})

@swagger_auto_schema(method='delete', request_body=DeleteUserAccountSerializer)
@api_view(['DELETE'])
def delete_user_logged(request):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária para deletar a conta.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'Usuário não encontrado.'}, status=status.HTTP_404_NOT_FOUND)

    password = request.data.get('password')
    if not password:
        return Response({'error': 'Confirmação da senha é necessária para deletar a conta.'}, status=status.HTTP_400_BAD_REQUEST)

    if not check_password(password, user.password):
        return Response({'error': 'Senha inválida.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    user_name_deleted = user.name
    user.delete()
    request.session.flush()

    return Response({'message': 'Conta deletada com sucesso.', 'user_name': user_name_deleted})


@swagger_auto_schema(method='post', request_body=LoginUserSerializer)
@api_view(['POST'])
def login_user(request):
    if (request.session.get('logged')):
        return Response({'error': 'Usuário já possui sessão ativa'}, status=status.HTTP_401_UNAUTHORIZED)

    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Campos não devem ser vazios'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Não existe uma conta com este email'}, status=status.HTTP_401_UNAUTHORIZED)

    if check_password(password, user.password) and user.email_verified:
        request.session['logged'] = True
        request.session['user_id'] = user.id
        return Response({'message': 'Usuário autenticado', 'user_id': user.id})
    else:
        return Response({'error': 'Falha na autenticação'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def logout_user(request):
    if (not request.session.get('logged')):
        return Response({'error': 'Usuário não possui sessão ativa'}, status=status.HTTP_401_UNAUTHORIZED)
    
    request.session.flush()
    return Response({'message': 'Sessão encerrada com sucesso'})

@swagger_auto_schema(method='post', request_body=VerifyEmailSerializer)
@api_view(['POST'])
def verify_email(request):
    email_input = request.data.get('email')
    code_input = request.data.get('code')

    try:
        user = User.objects.get(email=email_input)
    except User.DoesNotExist:
        return Response({'error': 'Não existe uma conta com este email'}, status=status.HTTP_401_UNAUTHORIZED)

    if user.email_verified:
        return Response({'error': 'Email já verificado'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        confirmation = EmailConfirmation.objects.get(user=user, code=code_input)

        if is_code_expired(confirmation.created_at):
            user.delete()
            return Response({'error': 'Código expirado. Por favor, solicite um novo'}, status=status.HTTP_401_UNAUTHORIZED)

        if code_input != confirmation.code:
            return Response({'error': 'Código inválido'}, status=status.HTTP_401_UNAUTHORIZED)

        confirmation.is_confirmed = True
        confirmation.save()

        user.email_verified = True
        user.save()

        return Response({'message': 'Usuário verificado'})
    except EmailConfirmation.DoesNotExist:
        return Response({'error': 'Requisição de confirmação desconhecida'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(method='post', request_body=ResetPasswordRequestSerializer)
@api_view(['POST'])
def reset_password_request(request):
    email = request.data.get('email')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Não existe conta com este email'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if is_code_expired(password_confirmation.created_at):
            password_confirmation.delete()
        else:
            return Response({'error': 'Já há um pedido de alteração de senha aberto'}, status=status.HTTP_401_UNAUTHORIZED)
    except PasswordReset.DoesNotExist:
        pass

    code = generate_confirmation_code()
    PasswordReset.objects.create(user=user, code=code)
    send_password_confirmation_code(user, code)

    return Response({'message': 'Código enviado. Por favor, verifique seu email'})

@swagger_auto_schema(method='post', request_body=ResetPasswordValidateSerializer)
@api_view(['POST'])
def reset_password_validate(request):
    email = request.data.get('email')
    code = request.data.get('code')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Não existe uma conta com este email'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if is_code_expired(password_confirmation.created_at):
            password_confirmation.delete()
            return Response({'error': 'Código expirado. Por favor, solicite um novo'}, status=status.HTTP_401_UNAUTHORIZED)

        if code != password_confirmation.code:
            return Response({'error': 'Código inválido'}, status=status.HTTP_401_UNAUTHORIZED)

        password_confirmation.is_confirmed = True
        password_confirmation.save()
        return Response({'Message': 'Código confirmado'})
    except PasswordReset.DoesNotExist:
        return Response({'error': 'Não existe uma solicitação para troca de senha aberta'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(method='post', request_body=ResetPasswordChooseNewSerializer)
@api_view(['POST'])
def reset_password_chooseNew(request):
    email = request.data.get('email')
    newPassword = request.data.get('new_password')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Não existe uma conta com este email'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if password_confirmation.is_confirmed:
            user.password = make_password(newPassword)
            user.save()
            return Response({'message': 'Senha alterada com sucesso'})
        else:
            return Response({'error': 'Requisição ainda não validada'}, status=status.HTTP_401_UNAUTHORIZED)
    except PasswordReset.DoesNotExist:
        return Response({'error': 'Não existe uma solicitação para troca de senha aberta.'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(method='post', request_body=ResetPasswordResend)
@api_view(['POST'])
def reset_password_resend(request):
    email = request.data.get('email')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Não existe uma conta com este email'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        password_confirmation = PasswordReset.objects.get(user=user)

        if password_confirmation.is_confirmed:
            return Response({'error': 'Senha já foi confirmada'}, status=status.HTTP_400_BAD_REQUEST)

        if is_code_expired(password_confirmation.created_at):
            newCode = generate_confirmation_code()
            send_password_confirmation_code(user, newCode)

            password_confirmation.code = newCode
            password_confirmation.created_at = timezone.now()
            
            password_confirmation.save()

            return Response({'message': 'Um novo código de confirmação foi enviado para seu email'})
        else:
            timeLeft = password_confirmation.created_at - timezone.now()
            return Response({'error': 'Aguarde mais um tempo para o reenvio', 'timeleft': timeLeft.total_seconds()}, status=status.HTTP_400_BAD_REQUEST)
    except PasswordReset.DoesNotExist:
        return Response({'error': 'Não existe uma solicitação para troca de senha aberta'}, status=status.HTTP_401_UNAUTHORIZED)