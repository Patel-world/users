from django.shortcuts import render, redirect
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import logout
from django.contrib.auth.forms import UserCreationForm
from verify_email.email_handler import send_verification_email
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate

from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.template import Context
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from django.contrib.auth import login

from django.shortcuts import render

from users.models import Profile
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from .models import *
import uuid
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.template import Context

# Create your views here.

@login_required
def home(request):
    return render(request, 'users/00/home.html')


def login_attempt(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user_obj = User.objects.filter(username=username).first()
        if user_obj is None:
            messages.success(request, 'User not found.')
            return redirect('/users/login')

        profile_obj = Profile.objects.filter(user=user_obj).first()

        if not profile_obj.is_verified:
            messages.success(request, 'Profile is not verified check your mail.')
            return redirect('/users/login')

        user = authenticate(username=username, password=password)
        if user is None:
            messages.success(request, 'Wrong password.')
            return redirect('/users/login')

        login(request, user)
        return redirect('/')

    return render(request, 'users/00/login.html')


def register_attempt(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            if User.objects.filter(username=username).first():
                messages.success(request, 'Username is taken.')
                return redirect('/users/register')

            if User.objects.filter(email=email).first():
                messages.success(request, 'Email is taken.')
                return redirect('/users/register')

            user_obj = User(username=username, email=email)
            user_obj.set_password(password)
            user_obj.save()
            auth_token = str(uuid.uuid4())
            profile_obj = Profile.objects.create(user=user_obj, auth_token=auth_token)
            profile_obj.save()
            send_mail_after_registration(email, auth_token, username)
            return redirect('/users/token')

        except Exception as e:
            print(e)

    return render(request, 'users/00/register.html')


def success(request):
    return render(request, 'users/00/success.html')


def token_send(request):
    return render(request, 'users/00/token_send.html')


def verify(request, auth_token):
    try:
        profile_obj = Profile.objects.filter(auth_token=auth_token).first()

        if profile_obj:
            if profile_obj.is_verified:
                messages.success(request, 'Your account is already verified.')
                return redirect('/users/login')
            profile_obj.is_verified = True
            profile_obj.save()
            messages.success(request, 'Your account has been verified.')
            return redirect('/users/success')
        else:
            return redirect('/users/error')
    except Exception as e:
        print(e)
        return redirect('/')


def error_page(request):
    return render(request, 'users/00/error.html')


def send_mail_after_registration(email, token, username):
    subject = 'Your accounts need to be verified'
    message = f'https://adhy.herokuapp.com/users/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    #send_mail(subject, message, email_from, recipient_list)

    html_content = render_to_string('users/00/email.html',{'username':username,'verurl':message})
    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives(subject,text_content,email_from,recipient_list)

    email.attach_alternative(html_content,"text/html")
    email.send()




def send_mail_for_reset(email, token, username):
    subject = 'Your accounts need to be verified'
    message = f'https://adhy.herokuapp.com/users/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    #send_mail(subject, message, email_from, recipient_list)

    html_content = render_to_string('users/00/email.html',{'username':username,'verurl':message})
    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives(subject,text_content,email_from,recipient_list)

    email.attach_alternative(html_content,"text/html")
    email.send()


def logout_view(request):
    """log the user out"""
    logout(request)
    return HttpResponseRedirect(reverse('index'))


def register(request):
    """Register a new user"""
    if request.method != 'POST':
        """Display blank registration form."""
        form = UserCreationForm()
    else:
        """Process completed form."""
        form = UserCreationForm(data=request.POST)

        if form.is_valid():
            new_user = form.save()
            inactive_user = send_verification_email(request, form)
            """log the user in and then redirect to the home page."""
            authenticated_user = authenticate(username=new_user.username, password=request.POST['password1'])
            login(request, authenticated_user)
            return HttpResponseRedirect(reverse('index'))
    context = {'form': form}
    return render(request, 'users/register.html', context)

def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "users/password_reset_email.txt"
                    c = {
					"email":user.email,
					'domain':'adhy.herokuapp.com',
					'site_name': 'Website',
					"uid": urlsafe_base64_encode(force_bytes(user.pk)),
					"user": user,
					'token': default_token_generator.make_token(user),
					'protocol': 'https',
					}
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'admin@example.com' , [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect ("/password_reset/done/")
            else:
                return redirect('/users/email_does_not_exists')

    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="users/password_reset.html", context={"password_reset_form":password_reset_form})

def user_not_exist(request):
    return render(request, 'users/00/user_not_exist.html')


def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('change_password')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'users/change_password.html', {
        'form': form
    })
