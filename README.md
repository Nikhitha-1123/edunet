# FindMyThing - Lost & Found Management System

A Django-based web application that helps people report lost items and connect with those who have found them. The platform facilitates reuniting people with their lost belongings through a secure and user-friendly interface.

## Features

### Core Functionality
- **Lost Item Reporting**: Users can report lost items with detailed descriptions, images, and location information
- **Found Item Reporting**: Users can report found items to help reunite them with their owners
- **Smart Matching**: System helps match lost and found items based on categories and descriptions
- **User Authentication**: Secure login/registration system with email and Google OAuth support
- **Security Questions**: Additional verification layer for item claims
- **Messaging System**: Direct communication between item owners and finders
- **Notifications**: Real-time updates on item matches and messages

### User Management
- **User Profiles**: Customizable profiles with profile pictures and contact information
- **Dashboard**: Personalized dashboard showing user's lost/found items and activities
- **Success Stories**: Feature to share reunion stories and testimonials

### Item Categories
- Electronics
- Documents
- Accessories
- Clothing
- Others

## Technology Stack

- **Backend**: Django 3.2.25
- **Database**: SQLite (development)
- **Authentication**: Django Auth + Google OAuth
- **Frontend**: HTML, CSS, JavaScript
- **File Storage**: Local media storage for images
- **Python Version**: 3.7+

## Project Structure

```
findmything/
├── findmything/          # Main project directory
│   ├── settings.py       # Django settings
│   ├── urls.py          # Main URL configuration
│   └── wsgi.py          # WSGI configuration
├── main/                # Main application
│   ├── models.py        # Database models
│   ├── views.py         # View functions
│   ├── urls.py          # App URL patterns
│   ├── admin.py         # Admin configuration
│   ├── backends.py      # Custom authentication backends
│   ├── templates/       # HTML templates
│   └── static/          # Static files (CSS, JS, images)
├── media/               # User uploaded files
│   ├── lost_items/      # Lost item images
│   ├── found_items/     # Found item images
│   └── profile_pics/    # User profile pictures
├── manage.py            # Django management script
└── db.sqlite3          # SQLite database
```

## Installation & Setup

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### 1. Clone the Repository
```bash
git clone <repository-url>
cd edunet
```

### 2. Create Virtual Environment
```bash
python -m venv project
```

### 3. Activate Virtual Environment
```bash
# Windows
project\Scripts\activate

# macOS/Linux
source project/bin/activate
```

### 4. Install Dependencies
```bash
pip install django==3.2.25
pip install Pillow  # For image handling
```

### 5. Navigate to Project Directory
```bash
cd findmything
```

### 6. Run Database Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. Create Superuser (Optional)
```bash
python manage.py createsuperuser
```

### 8. Run Development Server
```bash
python manage.py runserver
```

The application will be available at `http://127.0.0.1:8000/`

## Configuration

### Google OAuth Setup
1. Create a Google Cloud Project
2. Enable Google+ API
3. Create OAuth 2.0 credentials
4. Update `settings.py` with your credentials:
   ```python
   GOOGLE_CLIENT_ID = 'your-client-id'
   GOOGLE_CLIENT_SECRET = 'your-client-secret'
   ```

### Media Files
Ensure the `media/` directory has proper permissions for file uploads:
- `media/lost_items/` - Lost item images
- `media/found_items/` - Found item images  
- `media/profile_pics/` - User profile pictures

## Database Models

### Core Models
- **UserProfile**: Extended user information with profile pictures and phone numbers
- **lostitem**: Lost item reports with verification questions
- **founditem**: Found item reports
- **Message**: Communication between users
- **Notification**: System notifications
- **SuccessStory**: Reunion testimonials and stories

## Usage

### For Users Who Lost Items
1. Register/Login to the platform
2. Click "Report Lost Item"
3. Fill in item details, upload image, set security question
4. Browse found items or wait for matches
5. Communicate with finders through messaging system

### For Users Who Found Items
1. Register/Login to the platform
2. Click "Report Found Item"
3. Fill in item details and upload image
4. Browse lost items for potential matches
5. Contact item owners through messaging system

### Admin Features
- Access admin panel at `/admin/`
- Manage users, items, and system content
- Moderate success stories and featured content

## Security Features

- CSRF protection enabled
- Secure file upload handling
- Email-based authentication
- Security questions for item verification
- User input validation and sanitization

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the GitHub repository.

## Future Enhancements

- Mobile app development
- Advanced search and filtering
- Email notifications
- Multi-language support
- Integration with social media platforms
- Geolocation-based matching
- AI-powered item recognition