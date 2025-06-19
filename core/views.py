from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.hashers import check_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from .models import User
from .models import EmailConfirmation
from univox.email import generate_confirmation_code, send_confirmation_email

@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        # Validating POST Request
        required_fields = ['name', 'password', 'email', 'contact_number']
        missing_fields = [field for field in required_fields if not request.POST.get(field)]

        if missing_fields:
            return JsonResponse(
                {'error': f'Missing required fields: {", ".join(missing_fields)}.'},
                status=400
            )

        name = request.POST.get('name')
        password = request.POST.get('password')
        email = request.POST.get('email')
        contact_number = request.POST.get('contact_number')

        # Validating email
        try: validate_email(email)
        except ValidationError:
            return JsonResponse({'error': 'Invalid email format.'}, status=400)

        if User.objects.filter(name__iexact=name).exists():
            return JsonResponse({'error': 'Name already exists.'}, status=400)
        
        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse({'error': 'Email already exists.'}, status=400)

        # Hashing password
        hashed_password = make_password(password)

        user = User.objects.create(
            name=name,
            password=hashed_password,
            email=email,
            contact_number=contact_number
        )

        code = generate_confirmation_code()
        EmailConfirmation.objects.create(user=user, code=code)
        send_confirmation_email(user, code)

        return JsonResponse({'message': 'User created successfully.', 'user_id': user.id})

    return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def delete_user(request):
    if request.method == 'POST':
        name = request.POST.get('name')
    
        if not User.objects.filter(name__iexact=name).exists():
            return JsonResponse({'error': 'Name does not exists.'}, status=400)

        user = User.objects.get(name=name)
        user.delete()

        return JsonResponse({'message': 'User deleted successfully.', 'user_name': name})

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and Password required.'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid credentials.'}, status=401)

        if (check_password(password, user.password) and user.email_verified):
            # Authentication success
            request.session['logged'] = True
            return JsonResponse({'message': 'Authentication successful.', 'user_id': user.id})
        else:
            # Wrong password
            return JsonResponse({'error': 'Authentication Failed.'}, status=401)

    return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def logout_user(request):
    request.session.flush()
    return JsonResponse({'message': 'Logged out successfully.'})

@csrf_exempt
def verify_email(request):
    if request.method == 'POST':
        name_input = request.POST.get('name')
        code_input = request.POST.get('code')
        user = None

        try:
            user = User.objects.get(name=name_input)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Unknown user.'}, status=401)

        try:
            confirmation = EmailConfirmation.objects.get(user=user, code=code_input)
            confirmation.is_confirmed = True
            confirmation.save()
            
            user.email_verified = True
            user.save()

            return JsonResponse({'message': 'User verified!.'})
        except EmailConfirmation.DoesNotExist:
            return JsonResponse({'error': 'Unknown email.'}, status=401)

    return JsonResponse({'error': 'Invalid request method.'}, status=405)