# Google OAuth Setup Instructions

To enable "Continue with Google" functionality, follow these steps:

## 1. Create Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Set Application type to "Web application"
6. Add authorized redirect URIs:
   - `http://localhost:8000/main/auth/google/callback/`
   - `http://127.0.0.1:8000/main/auth/google/callback/`

## 2. Update Settings

Replace the placeholder values in `findmything/settings.py`:

```python
GOOGLE_CLIENT_ID = 'your-actual-client-id.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'your-actual-client-secret'
```

## 3. Test the Integration

1. Start the Django server: `python manage.py runserver`
2. Go to signup page
3. Click "Continue with Google"
4. Should redirect to Google login

## Current Status

- ✅ Google OAuth code is implemented
- ❌ Credentials need to be configured
- ✅ Fallback error message shows when not configured