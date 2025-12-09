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

from .models import lostitem, founditem, UserProfile, Message, Notification

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

        # Check if user exists
        if User.objects.filter(email=email).exists():
            return render(request, 'signup.html', {'error': 'Account with this email already exists.'})

        # Create user
        username = email.split('@')[0][:150]
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1
        )
        
        if full_name:
            user.first_name = full_name.split()[0]
            user.save()

        # Redirect to login page
        return redirect('login')
    
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
    notifications = Notification.objects.filter(user=request.user, is_read=False)[:5]
    context = {
        'user': request.user,
        'notifications': notifications,
    }
    return render(request, 'dashboard.html', context)


# ===== REPORT VIEWS =====

@login_required(login_url='login')
def report_lost(request):
    """Report a lost item"""
    if request.method == 'POST':
        item_name = request.POST.get('item_name')
        category = request.POST.get('category', 'Others')
        description = request.POST.get('description')
        lost_place = request.POST.get('lost_place')
        lost_date = request.POST.get('lost_date')
        item_image = request.FILES.get('item_image')
        
        if not item_image and 'confirm_save' not in request.POST:
            return render(request, 'lostitem.html', {'error': 'Image is required for better identification'})
        
        if 'confirm_save' in request.POST:
            new_lostitem = lostitem(
                item_name=item_name,
                category=category,
                description=description,
                lost_place=lost_place,
                lost_date=lost_date,
                owner_name=request.user.get_full_name() or request.user.username,
                phone_number="",
                user=request.user,
            )
            # Retrieve image from session if not in FILES
            if not item_image and 'temp_lost_image' in request.session:
                import base64
                from django.core.files.base import ContentFile
                image_data = base64.b64decode(request.session['temp_lost_image'])
                new_lostitem.item_image.save(request.session['temp_lost_image_name'], ContentFile(image_data))
                del request.session['temp_lost_image']
                del request.session['temp_lost_image_name']
            elif item_image:
                new_lostitem.item_image = item_image
            new_lostitem.save()
            return render(request, 'lostitem.html', {'success': True})
        
        # Store image in session for later use
        if item_image:
            import base64
            request.session['temp_lost_image'] = base64.b64encode(item_image.read()).decode('utf-8')
            request.session['temp_lost_image_name'] = item_image.name
        
        from difflib import SequenceMatcher
        matches_with_score = []
        for item in founditem.objects.filter(is_reunited=False):
            name_sim = SequenceMatcher(None, item_name.lower(), item.item_name.lower()).ratio() * 100
            desc_sim = SequenceMatcher(None, description.lower(), item.description.lower()).ratio() * 100
            if max(name_sim, desc_sim) >= 30:
                matches_with_score.append({'item': item, 'similarity': round(max(name_sim, desc_sim))})
        
        if matches_with_score:
            matches_with_score.sort(key=lambda x: x['similarity'], reverse=True)
            return render(request, 'lostitem.html', {'matches': matches_with_score[:5], 'form_data': request.POST})
        
        return render(request, 'lostitem.html', {'no_matches': True, 'form_data': request.POST})
    
    return render(request, 'lostitem.html')


@login_required(login_url='login')
def report_found(request):
    """Report a found item"""
    if request.method == 'POST':
        item_name = request.POST.get('item_name', '')
        category = request.POST.get('category', 'Others')
        description = request.POST.get('description', '')
        found_place = request.POST.get('found_place', '')
        found_date = request.POST.get('found_date', '')
        item_image = request.FILES.get('item_image')
        
        if not item_image and 'confirm_save' not in request.POST:
            return render(request, 'founditem.html', {'error': 'Image is required for better identification'})
        
        if 'confirm_save' in request.POST:
            new_founditem = founditem(
                item_name=item_name,
                category=category,
                description=description,
                found_place=found_place,
                found_date=found_date,
                finder_name=request.user.get_full_name() or request.user.username,
                phone_number="",
                user=request.user,
            )
            # Retrieve image from session if not in FILES
            if not item_image and 'temp_found_image' in request.session:
                import base64
                from django.core.files.base import ContentFile
                image_data = base64.b64decode(request.session['temp_found_image'])
                new_founditem.item_image.save(request.session['temp_found_image_name'], ContentFile(image_data))
                del request.session['temp_found_image']
                del request.session['temp_found_image_name']
            elif item_image:
                new_founditem.item_image = item_image
            new_founditem.save()
            return render(request, 'founditem.html', {'success': True})
        
        # Store image in session for later use
        if item_image:
            import base64
            request.session['temp_found_image'] = base64.b64encode(item_image.read()).decode('utf-8')
            request.session['temp_found_image_name'] = item_image.name
        
        from difflib import SequenceMatcher
        matches_with_score = []
        for item in lostitem.objects.filter(is_reunited=False):
            name_sim = SequenceMatcher(None, item_name.lower(), item.item_name.lower()).ratio() * 100
            desc_sim = SequenceMatcher(None, description.lower(), item.description.lower()).ratio() * 100
            if max(name_sim, desc_sim) >= 30:
                matches_with_score.append({'item': item, 'similarity': round(max(name_sim, desc_sim))})
        
        if matches_with_score:
            matches_with_score.sort(key=lambda x: x['similarity'], reverse=True)
            return render(request, 'founditem.html', {'matches': matches_with_score[:5], 'form_data': request.POST})
        
        return render(request, 'founditem.html', {'no_matches': True, 'form_data': request.POST})
    
    return render(request, 'founditem.html')


@login_required(login_url='login')
def profile(request):
    """User profile page"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        if 'delete_picture' in request.POST:
            profile.profile_picture.delete()
            profile.profile_picture = None
            profile.save()
        elif 'profile_picture' in request.FILES:
            if profile.profile_picture:
                profile.profile_picture.delete()
            profile.profile_picture = request.FILES['profile_picture']
            profile.save()
        elif 'phone' in request.POST:
            profile.phone = request.POST.get('phone', '')
            profile.save()
        return redirect('profile')
    
    user_lost_items = lostitem.objects.filter(user=request.user).order_by('-is_reunited', '-id')
    user_found_items = founditem.objects.filter(user=request.user).order_by('-is_reunited', '-id')
    
    context = {
        'user': request.user,
        'profile': profile,
        'lost_items': user_lost_items,
        'found_items': user_found_items,
    }
    return render(request, 'profile.html', context)


@login_required(login_url='login')
def view_lost(request):
    """View all lost items with search and filter"""
    items = lostitem.objects.filter(is_reunited=False)
    
    q = request.GET.get('q')
    if q:
        items = items.filter(item_name__icontains=q)
    
    loc = request.GET.get('location')
    if loc:
        items = items.filter(lost_place__icontains=loc)
    
    date = request.GET.get('date')
    if date:
        items = items.filter(lost_date=date)
    
    cat = request.GET.get('category')
    if cat:
        items = items.filter(category=cat)
    
    return render(request, 'view_lost.html', {'lost_items': items.order_by('-id')})


@login_required(login_url='login')
def view_found(request):
    """View all found items with search and filter"""
    items = founditem.objects.filter(is_reunited=False)
    
    q = request.GET.get('q')
    if q:
        items = items.filter(item_name__icontains=q)
    
    loc = request.GET.get('location')
    if loc:
        items = items.filter(found_place__icontains=loc)
    
    date = request.GET.get('date')
    if date:
        items = items.filter(found_date=date)
    
    cat = request.GET.get('category')
    if cat:
        items = items.filter(category=cat)
    
    return render(request, 'view_found.html', {'found_items': items.order_by('-id')})


@login_required(login_url='login')
def lost_item_detail(request, item_id):
    """View lost item details"""
    item = lostitem.objects.get(id=item_id)
    return render(request, 'item_detail.html', {'item': item, 'item_type': 'lost'})


@login_required(login_url='login')
def found_item_detail(request, item_id):
    """View found item details"""
    item = founditem.objects.get(id=item_id)
    return render(request, 'item_detail.html', {'item': item, 'item_type': 'found'})


@login_required(login_url='login')
def chat_lost(request, item_id):
    """Chat about a lost item"""
    item = lostitem.objects.get(id=item_id)
    messages = Message.objects.filter(lost_item=item)
    
    if request.method == 'POST':
        message_text = request.POST.get('message')
        if message_text:
            Message.objects.create(
                sender=request.user,
                lost_item=item,
                message=message_text
            )
            # Create notification for item owner
            if item.user and item.user != request.user:
                Notification.objects.create(
                    user=item.user,
                    message=f"New message about your lost item: {item.item_name}",
                    link=f"/main/chat/lost/{item.id}/"
                )
            return redirect('chat_lost', item_id=item_id)
    
    return render(request, 'chat.html', {
        'item': item,
        'messages': messages,
        'item_type': 'lost'
    })


@login_required(login_url='login')
def chat_found(request, item_id):
    """Chat about a found item"""
    item = founditem.objects.get(id=item_id)
    messages = Message.objects.filter(found_item=item)
    
    if request.method == 'POST':
        message_text = request.POST.get('message')
        if message_text:
            Message.objects.create(
                sender=request.user,
                found_item=item,
                message=message_text
            )
            # Create notification for item finder
            if item.user and item.user != request.user:
                Notification.objects.create(
                    user=item.user,
                    message=f"New message about your found item: {item.item_name}",
                    link=f"/main/chat/found/{item.id}/"
                )
            return redirect('chat_found', item_id=item_id)
    
    return render(request, 'chat.html', {
        'item': item,
        'messages': messages,
        'item_type': 'found'
    })


@login_required(login_url='login')
def edit_lost(request, item_id):
    """Edit a lost item"""
    item = lostitem.objects.get(id=item_id)
    if item.user != request.user:
        return redirect('dashboard')
    
    if request.method == 'POST':
        item.item_name = request.POST.get('item_name')
        item.category = request.POST.get('category', 'Others')
        item.description = request.POST.get('description')
        item.lost_place = request.POST.get('lost_place')
        item.lost_date = request.POST.get('lost_date')
        if 'item_image' in request.FILES:
            item.item_image = request.FILES['item_image']
        item.save()
        return redirect('profile')
    
    return render(request, 'edit_lost.html', {'item': item})


@login_required(login_url='login')
def edit_found(request, item_id):
    """Edit a found item"""
    item = founditem.objects.get(id=item_id)
    if item.user != request.user:
        return redirect('dashboard')
    
    if request.method == 'POST':
        item.item_name = request.POST.get('item_name')
        item.category = request.POST.get('category', 'Others')
        item.description = request.POST.get('description')
        item.found_place = request.POST.get('found_place')
        item.found_date = request.POST.get('found_date')
        if 'item_image' in request.FILES:
            item.item_image = request.FILES['item_image']
        item.save()
        return redirect('profile')
    
    return render(request, 'edit_found.html', {'item': item})


@login_required(login_url='login')
def delete_lost(request, item_id):
    """Delete a lost item"""
    item = lostitem.objects.get(id=item_id)
    if item.user == request.user:
        item.delete()
    return redirect('profile')


@login_required(login_url='login')
def delete_found(request, item_id):
    """Delete a found item"""
    item = founditem.objects.get(id=item_id)
    if item.user == request.user:
        item.delete()
    return redirect('profile')


@login_required(login_url='login')
def mark_lost_reunited(request, item_id):
    """Mark a lost item as reunited"""
    item = lostitem.objects.get(id=item_id)
    if item.user == request.user:
        item.is_reunited = True
        item.save()
    return redirect('profile')


@login_required(login_url='login')
def mark_found_reunited(request, item_id):
    """Mark a found item as reunited"""
    item = founditem.objects.get(id=item_id)
    if item.user == request.user:
        item.is_reunited = True
        item.save()
    return redirect('profile')