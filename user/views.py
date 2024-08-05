from pyexpat.errors import messages
import uuid
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import logout
from nextedge import settings
from django.contrib.auth.hashers import make_password
from user import models
from user.models import CustomUser, PasswordResetToken, UserProfile
from django.urls import reverse
from datetime import datetime, timedelta, timezone
from django.utils import timezone
from django.http import HttpResponse
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse

def login_page(request):
    return render(request, 'user/login_page.html', {'is_register': False})

# def user_profile(request):
#     if request.method == 'POST':
#         user_id=request.user
#         first_name = request.POST.get('first_name')
#         last_name = request.POST.get('last_name')
#         phone_number = request.POST.get('phone_number')
#         bio = request.POST.get('bio')
#         country=request.POST.get('country')
#         profile_picture = request.FILES.get('profile_picture')
        
#         student_instance = user_profile.objects.create(first_name=first_name, last_name=last_name,
#                                                       bio=bio, profile_picture=profile_picture,
#                                                       phone_number=phone_number)
#         return redirect('studentindex')
        
#     return redirect(request,'user_profile.html')

def registerfn(request):
    if request.method == 'POST':
    # Handle registration
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        # Add validation logic here
        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('login_page') 

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email is already taken.")
            return redirect('login_page') 

        user = CustomUser.objects.create_user(username=username, email=email, password=password1, role='student',is_staff=True)
        if user:
            return redirect('login_page')  # Redirect to student index page after successful registration
        else:
            messages.error(request, "Something went wrong. Try again.")
        
def loginfn(request):
    user=request.user
    if user.is_authenticated:
        if UserProfile.objects.filter(user=user).exists():
            return redirect('studentindex')
        else:
            return redirect('user_profile')
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            if user.is_superuser==True:
                return redirect('adminindex')
            elif user.role == 'student':
                if UserProfile.objects.filter(user=user).exists():
                    return redirect('studentindex')
                else:
                    return redirect('user_profile')
        else:
            return redirect('login_page')
        
def send_password_reset_email(request, user, token):
    reset_url = request.build_absolute_uri(f'/new_password/{token}/')
    subject = 'Password Reset Request'
    context = {
        'user': user,
        'reset_url': reset_url,
    }
    html_content = render_to_string('user/mail_read.html', context)
    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [user.email])
    email.attach_alternative(html_content, 'text/html')
    email.send()

def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get('email')
        associated_users = CustomUser.objects.filter(email=email)
        if associated_users.exists():
            for user in associated_users:
                token = PasswordResetToken.objects.create(user=user)
                send_password_reset_email(request, user, token.token)
            return HttpResponse('A password reset link has been sent to your email.')
        else:
            return HttpResponse('No user is associated with this email address.')
    return render(request, 'user/password_reset.html')

def reset_password(request, token):
    reset_token = PasswordResetToken.objects.filter(token=token, expiry__gt=timezone.now()).first()
    if not reset_token:
        return HttpResponse("Invalid or expired token.")
    
    if request.method == "POST":
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if password1 == password2:
            reset_token.user.set_password(password1)
            reset_token.user.save()
            reset_token.delete()
            return redirect('login_page')
        else:
            return HttpResponse("Passwords do not match.")
    
    return render(request, 'user/new_password.html', {'token': token})

def change_password(request):
    user_profile = UserProfile.objects.get(user=request.user)
    if request.method == "POST":
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if password1 == password2:
            user = request.user
            user.set_password(password1)
            user.save()
            return redirect('login_page')
        else:
            return HttpResponse("Passwords do not match.")
    
    return render(request, 'user/change_password.html', {'user_profile': user_profile})



    
def index(request):
    return render(request,'user/index.html')

def password_reset(request):
    return render(request,'user/password_reset.html')

def studentindex(request):
    user_profile = UserProfile.objects.get(user=request.user)
    return render(request, 'user/studentindex.html', {'user_profile': user_profile})
    
def adminindex(request):
    users = UserProfile.objects.all()
    return render(request, 'admin/adminindex.html', {'users': users})
    
def new_password(request):
    return render(request,'user/new_password.html')

def user_profile(request):
    return render(request,'user/user_profile.html')


def password_done(request):
    return render(request,'user/password_done.html')

def edit_profile_success(request):
    return render(request,'user/user_profile.html')

def userlogout(request):
    logout(request) 
    return redirect('index')

def user_profile(request):
    user = request.user
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone_number = request.POST.get('phone_number')
        bio = request.POST.get('bio')
        country = request.POST.get('country')
        profile_picture = request.FILES.get('profile_picture')
        
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.first_name = first_name
        profile.last_name = last_name
        profile.phone_number = phone_number
        profile.bio = bio
        profile.country = country
        
        if profile_picture:
            profile.profile_picture = profile_picture
        
        profile.save()
        return redirect('studentindex')

    return render(request,'user/user_profile.html')


def profile_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    return render(request, 'user/profile_view.html', {'user_profile': user_profile})

def delete_profile_picture(request):
    user_profile =UserProfile.objects.get(user=request.user)
    user_profile.profile_picture.delete()
    user_profile.save()
    return JsonResponse({'status': 'success'})

def replace_profile_picture(request):
    if 'profile_picture' in request.FILES:
        user_profile =UserProfile.objects.get(user=request.user)
        user_profile.profile_picture = request.FILES['profile_picture']
        user_profile.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)

def edit_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    
    if request.method == 'POST':
        first_name = request.POST.get('firstName')
        last_name = request.POST.get('lastName')
        phone_number=request.POST.get('phone_number')
        bio = request.POST.get('bio')
        
        user_profile.first_name = first_name
        user_profile.phone_number=phone_number
        user_profile.last_name = last_name
        user_profile.bio = bio
        user_profile.save()
        
        return redirect('profile_view') 
    
    return render(request, 'user/edit_profile.html', {'user_profile': user_profile})


