from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.conf import settings
from urllib.parse import urlencode
import requests
import secrets
import logging

from .models import lostitem, founditem

logger = logging.getLogger(__name__)
User = get_user_model()

# ===== ROOT REDIRECT =====

def index(request):
    """Root path — redirect based on auth status"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')

# ===== AUTHENTICATION VIEWS =====

def login_view(request):
    """Handle user login with email/password"""
    next_url = request.GET.get('next') or request.POST.get('next') or ''
    
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password')
        
        user = authenticate(request, username=email, password=password)
        if user is not None:
            auth_login(request, user)
            # Validate next_url for security
            if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
                return redirect(next_url)
            return redirect('dashboard')
        
        return render(request, 'login.html', {'error': 'Invalid credentials', 'next': next_url})
    
    return render(request, 'login.html', {'next': next_url})


def signup_view(request):
    """Handle user signup with email/password"""
    if request.method == 'POST':
        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip().lower()
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        # Validation
        if not email or not password1 or password1 != password2:
            return render(request, 'signup.html', {'error': 'Please check your input.'})

        # Create user
        username = email.split('@')[0][:150]
        user, created = User.objects.get_or_create(
            email=email, 
            defaults={'username': username}
        )
        
        if not created:
            return render(request, 'signup.html', {'error': 'Account with this email already exists.'})

        # Set password and name
        user.set_password(password1)
        if full_name:
            user.first_name = full_name.split()[0]
        user.save()

        # Auto-login after signup
        auth_login(request, user)
        return redirect(reverse('dashboard'))
    
    return render(request, 'signup.html')


def logout_view(request):
    """Handle user logout"""
    auth_logout(request)
    return redirect(reverse('login'))


def google_login(request):
    """Initiate Google OAuth login"""
    client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)
    if not client_id:
        logger.error("GOOGLE_CLIENT_ID missing in settings")
        return HttpResponse("Google OAuth not configured.", status=500)

    state = secrets.token_urlsafe(16)
    request.session['google_oauth_state'] = state
    redirect_uri = request.build_absolute_uri(reverse('google_callback'))
    
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': redirect_uri,
        'state': state,
        'access_type': 'offline',
        'prompt': 'select_account'
    }
    
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)
    return redirect(auth_url)


def google_callback(request):
    """Handle Google OAuth callback"""
    error = request.GET.get('error')
    if error:
        logger.warning("Google OAuth error: %s", error)
        return redirect('login')

    state = request.GET.get('state')
    if not state or state != request.session.get('google_oauth_state'):
        logger.error("Invalid or missing OAuth state")
        return HttpResponse("Invalid OAuth state.", status=400)

    code = request.GET.get('code')
    if not code:
        logger.error("Google callback missing code")
        return HttpResponse("Missing code in callback.", status=400)

    # Exchange code for token
    token_endpoint = 'https://oauth2.googleapis.com/token'
    try:
        token_resp = requests.post(token_endpoint, data={
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': request.build_absolute_uri(reverse('google_callback')),
            'grant_type': 'authorization_code',
        }, timeout=10)
        token_resp.raise_for_status()
        token_data = token_resp.json()
    except Exception as e:
        logger.exception("Failed to fetch token: %s", e)
        return HttpResponse("Failed to fetch token from Google.", status=502)

    access_token = token_data.get('access_token')
    if not access_token:
        logger.error("No access_token in response")
        return HttpResponse("Invalid token response.", status=502)

    # Fetch user info
    try:
        userinfo_resp = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}, 
            timeout=10
        )
        userinfo_resp.raise_for_status()
        info = userinfo_resp.json()
    except Exception as e:
        logger.exception("Failed to fetch userinfo: %s", e)
        return HttpResponse("Failed to fetch user info from Google.", status=502)

    email = info.get('email')
    name = info.get('name', '')
    if not email:
        logger.error("Google userinfo missing email")
        return HttpResponse("Google account has no email.", status=400)

    # Create or get user
    username = email.split('@')[0][:150]
    user, created = User.objects.get_or_create(
        email=email, 
        defaults={
            'username': username, 
            'first_name': name.split()[0] if name else ''
        }
    )

    user.backend = 'django.contrib.auth.backends.ModelBackend'
    auth_login(request, user)
    return redirect('dashboard')


# ===== DASHBOARD VIEWS =====

@login_required(login_url='login')
def dashboard(request):
    """User dashboard — authenticated users only"""
    context = {
        'user': request.user,
    }
    return render(request, 'dashboard.html', context)


# ===== REPORT VIEWS =====

@login_required(login_url='login')
def report_lost(request):
    """Report a lost item"""
    if request.method == 'POST':
        item_name = request.POST.get('item_name')
        description = request.POST.get('description')
        lost_place = request.POST.get('lost_place')
        lost_date = request.POST.get('lost_date')
        owner_name = request.POST.get('owner_name')
        phone_number = request.POST.get('phone_number')
        
        new_lostitem = lostitem(
            item_name=item_name,
            description=description,
            lost_place=lost_place,
            lost_date=lost_date,
            owner_name=owner_name,
            phone_number=phone_number,
        )
        new_lostitem.save()
        return redirect('dashboard')
    
    return render(request, 'report_lost.html')


@login_required(login_url='login')
def report_found(request):
    """Report a found item"""
    if request.method == 'POST':
        item_name = request.POST.get('item_name')
        description = request.POST.get('description')
        found_place = request.POST.get('found_place')
        found_date = request.POST.get('found_date')
        finder_name = request.POST.get('finder_name')
        phone_number = request.POST.get('phone_number')
        
        new_founditem = founditem(
            item_name=item_name,
            description=description,
            found_place=found_place,
            found_date=found_date,
            finder_name=finder_name,
            phone_number=phone_number,
        )
        new_founditem.save()
        return redirect('dashboard')
    
    return render(request, 'report_found.html')


# ===== LEGACY VIEWS (keep for backward compatibility) =====

def login(request):
    """Legacy — redirect to login_view"""
    return login_view(request)


def signup(request):
    """Legacy — redirect to signup_view"""
    return signup_view(request)


def litem(request):
    """Display lost item form — legacy"""
    return render(request, 'lostitem.html')


def fitem(request):
    """Display found item form — legacy"""
    return render(request, 'founditem.html')


def lost_item(request):
    """Handle lost item submission — legacy"""
    if request.method == 'POST':
        item_name = request.POST.get('item_name')
        description = request.POST.get('description')
        lost_place = request.POST.get('lost_place')
        lost_date = request.POST.get('lost_date')
        owner_name = request.POST.get('owner_name')
        phone_number = request.POST.get('phone_number')
        
        new_lostitem = lostitem(
            item_name=item_name,
            description=description,
            lost_place=lost_place,
            lost_date=lost_date,
            owner_name=owner_name,
            phone_number=phone_number,
        )
        new_lostitem.save()
        return HttpResponse("Lost item details added successfully!")
    
    return render(request, 'lostitem.html')


def found_item(request):
    """Handle found item submission — legacy"""
    if request.method == 'POST':
        item_name = request.POST.get('item_name')
        description = request.POST.get('description')
        found_place = request.POST.get('found_place')
        found_date = request.POST.get('found_date')
        finder_name = request.POST.get('finder_name')
        phone_number = request.POST.get('phone_number')
        
        new_founditem = founditem(
            item_name=item_name,
            description=description,
            found_place=found_place,
            found_date=found_date,
            finder_name=finder_name,
            phone_number=phone_number,
        )
        new_founditem.save()
        return HttpResponse("Found item details added successfully!")
    
    return render(request, 'founditem.html')