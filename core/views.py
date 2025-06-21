from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from .models import User
from .models import EmailConfirmation
from .models import PasswordReset
from univox.email import generate_confirmation_code, send_confirmation_email, is_code_expired, send_password_confirmation_code

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

        #Checking if user exists but is not verified yet
        try:
            existing_user = User.objects.get(name=name)
            existing_confirmation = User.objects.get(user=existing_user)

            #Can't create because there is some user validating his/her account
            if (not is_code_expired(existing_confirmation.created_at)):
                return JsonResponse({'error': 'Cannot use this name right now!'}, status=401)
            else:
                existing_user.delete()

        except (User.DoesNotExist, EmailConfirmation.DoesNotExist):
            pass

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

        return JsonResponse({'message': 'Verification code sent to email.', 'user_id': user.id})

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
    if (request.session['logged']):
        return JsonResponse({'error': 'User already logged in!'}, status=401)
    
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
            request.session['user'] = user.name
            return JsonResponse({'message': 'Authentication successful.', 'user_id': user.id})
        else:
            # Wrong password
            return JsonResponse({'error': 'Authentication Failed.'}, status=401)

    return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def logout_user(request):
    if (not request.session['logged']):
        return JsonResponse({'error': 'There is not user logged in.'}, status=401)
    
    request.session.flush()
    return JsonResponse({'message': 'Logged out successfully.'}, 'user_name': request['user'])

@csrf_exempt
def verify_email(request):
    if request.method == 'POST':
        email_input = request.POST.get('email')
        code_input = request.POST.get('code')
        user = None

        #Getting user existence
        try:
            user = User.objects.get(email=email_input)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Unknown user.'}, status=401)

        #User already verified
        if (user.email_verified):
            return JsonResponse({'error': 'User already verified!.'}, status=401)

        #Validating confirmation code
        try:
            confirmation = EmailConfirmation.objects.get(user=user, code=code_input)

            #Code expired
            if (is_code_expired(confirmation.created_at)):
                user.delete()
                return JsonResponse({'error': 'Code expired!'}, status=401)

            #Verifying code
            if (code_input != confirmation.code):
                return JsonResponse({'error': 'Invalid code!'}, status=401)

            #else
            confirmation.is_confirmed = True
            confirmation.save()
            
            user.email_verified = True
            user.save()

            return JsonResponse({'message': 'User verified!.'})
        except EmailConfirmation.DoesNotExist:
            return JsonResponse({'error': 'Unknown confirmation request!.'}, status=401)

    return JsonResponse({'error': 'Invalid request method.'}, status=405)

#Password resetting process
@csrf_exempt 
def reset_password_request(request):    #1. Making the request
    if request.method == 'POST':
        email = request.POST.get('email')
        
        #Getting user existence
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Unknown user.'}, status=401)
        
        #Checking if there is any active password recovery requests
        try:
            password_confirmation = PasswordReset.objects.get(user=user)

            if (is_code_expired(password_confirmation.created_at)):
                password_confirmation.delete()
            else:
                return JsonResponse({'error': 'A password recovery request already exists.'}, status=401)                
        except PasswordReset.DoesNotExist:
            pass

        #Sending code
        code = generate_confirmation_code()
        PasswordReset.objects.create(user=user, code=code)
        send_password_confirmation_code(user, code)

        return JsonResponse({'message': 'Verification code sent to email.'})
    
    return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def reset_password_validate(request):    #2. Validate the code
    if request.method == 'POST':
        email = request.POST.get('email')
        code = request.POST.get('code')

        #Getting user existence
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Unknown user.'}, status=401)
        
        #Checking if there is any active password recovery requests
        try:
            password_confirmation = PasswordReset.objects.get(user=user)

            if (is_code_expired(password_confirmation.created_at)):
                password_confirmation.delete()
                return JsonResponse({'error': 'Password recovery code expired.'}, status=401)
            else:
                if (code != password_confirmation.code):
                    return JsonResponse({'error': 'Invalid code!'}, status=401)
                
                password_confirmation.is_confirmed = True
                password_confirmation.save()

                return JsonResponse({'Message': 'Password recovery code confirmed!'})

        except PasswordReset.DoesNotExist:
            return JsonResponse({'error': 'A password recovery request does not exist for this user.'}, status=401) 
        
    return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def reset_password_chooseNew(request):    #3. Choose new password
    if request.method == 'POST':
        email = request.POST.get('email')
        newPassword = request.POST.get('new_password')

        #Getting user existence
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Unknown user.'}, status=401)
        
        #Checking if there is any active password recovery requests
        try:
            password_confirmation = PasswordReset.objects.get(user=user)

            if (password_confirmation.is_confirmed):
                user.password = make_password(newPassword)
                user.save()
                return JsonResponse({'message': 'Password succesfully changed!.'})
            else:   
                return JsonResponse({'error': 'Password request is not validated yet!.'}, status=401)

        except PasswordReset.DoesNotExist:
            return JsonResponse({'error': 'A password recovery request does not exist for this user.'}, status=401) 
        
    return JsonResponse({'error': 'Invalid request method.'}, status=405)
