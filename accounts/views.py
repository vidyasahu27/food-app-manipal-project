from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.utils.http import urlsafe_base64_decode

from vendor.forms import VendorForm
from .forms import UserForm
from .models import User, UserProfile
from django.contrib import messages, auth

from .utils import detect_user, send_email
from django.core.exceptions import PermissionDenied

# Restrict the restaurant from accessing the customer page
def check_role_restaurant(user):
    if user.role == 1:
        return True
    raise PermissionDenied

# Restrict the customer from accessing the vendor page
def check_role_customer(user):
    if user.role == 2:
        return True
    raise PermissionDenied

def register_user(request):
    if request.user.is_authenticated:
        return redirect('customerDashboard')
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():

            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password
            )
            user.role = User.CUSTOMER
            user.save()

            # Send verification email
            send_email(request, user, 'VERIFICATION_EMAIL')
            messages.success(request, 'You have registered successfully.')
            return redirect('registerUser')
        else:
            print(form.errors)
    else:
        form = UserForm()

    context = {
        'form': form,
    }
    return render(request, 'accounts/registeruser.html', context)

def register_restaurant(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        #store the data and create the user
        form = UserForm(request.POST)
        vendor_form = VendorForm(request.POST, request.FILES)

        if form.is_valid() and vendor_form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password
            )
            user.role = User.RESTAURANT
            user.save()

            vendor = vendor_form.save(commit=False)
            vendor.user = user

            # getting the user profile from the user which got created via Signals
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()

            # Send verification email
            send_email(request, user, 'VERIFICATION_EMAIL')

            messages.success(request, 'You have registered successfully. Please wait for the Admin approval.')
            return redirect('registerRestaurant')
        else:
            print(form.errors)
    else:
        form = UserForm()
        vendor_form = VendorForm()

    context = {
        'form': form,
        'vendor_form': vendor_form,
    }
    return render(request, 'accounts/registerrestaurant.html', context=context)

def login(request):
    if request.user.is_authenticated:
        return redirect('myAccount')
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You have logged-in successfully')
            return redirect('myAccount')
        else:
            messages.error(request, 'Username/password incorrect!')
            return redirect('login')
    return render(request, 'accounts/login.html')

def logout(request):
    auth.logout(request)
    messages.info(request, 'You are logged out')
    return redirect('login')

@login_required(login_url='login')
@user_passes_test(check_role_customer)
def customer_dashboard(request):
    return render(request, 'accounts/customer_dashboard.html')

@login_required(login_url='login')
@user_passes_test(check_role_restaurant)
def restaurant_dashboard(request):
    return render(request, 'accounts/restaurant_dashboard.html')

@login_required(login_url='login')
def my_account(request):
    if not request.user.is_authenticated:
        return redirect('login')
    user = request.user
    redirect_url = detect_user(user)
    return redirect(redirect_url)

def activate(request, uidb64, token):
    # Activate the user
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congrats, your account has been activated.')
        return redirect('myAccount')
    else:
        messages.error(request, 'Invalid activation link.')
        return redirect('myAccount')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)

            # send reset password email
            send_email(request, user, 'RESET_PASSWORD_EMAIL')
            messages.success(request, 'Password reset link has been sent to your email address.')
            return redirect('login')
        else:
            messages.error(request, 'Some error occurred.')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgot_password.html')

def validate_reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.info(request, 'Please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(request, 'This link has been expired.')
        return redirect('myAccount')

def reset_password(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            pk = request.session.get('uid')
            user = User.objects.get(pk=pk)
            user.set_password(password)
            user.is_active = True
            user.save()
            messages.success(request, 'Password has been reset successfully.')
            return redirect('login')
        else:
            messages.error(request, 'Passwords not match!')
    return render(request, 'accounts/reset_password.html')