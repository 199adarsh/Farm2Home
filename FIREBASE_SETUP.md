# Firebase Setup Guide for Farm2Home

This guide will help you set up Firebase Authentication and Firestore database for your Farm2Home project.

## Prerequisites

1. A Google account
2. Python 3.7+ installed
3. Your existing Farm2Home project

## Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Create a project" or "Add project"
3. Enter project name: `farm2home` (or your preferred name) - **Your project ID is: farm2home-d0fb2**
4. Enable Google Analytics (optional)
5. Click "Create project"

## Step 2: Enable Authentication

1. In your Firebase project, go to "Authentication" in the left sidebar
2. Click "Get started"
3. Go to "Sign-in method" tab
4. Enable the following providers:
   - **Email/Password**: Click "Email/Password" → Enable → Save
   - **Google**: Click "Google" → Enable → Add your project support email → Save

## Step 3: Create Firestore Database

1. Go to "Firestore Database" in the left sidebar
2. Click "Create database"
3. Choose "Start in test mode" (for development)
4. Select a location close to your users
5. Click "Done"

## Step 4: Generate Service Account Key

1. Go to Project Settings (gear icon) → "Service accounts"
2. Click "Generate new private key"
3. Download the JSON file
4. Rename it to `firebase-service-account.json`
5. Place it in your project root directory

## Step 5: Get Firebase Config

1. Go to Project Settings → "General" tab
2. Scroll down to "Your apps" section
3. Click "Web" icon (`</>`) to add a web app
4. Register your app with a nickname
5. Copy the Firebase configuration object

## Step 6: Update Configuration Files

### Update `templates/login.html`

Replace the Firebase configuration in the script section:

```javascript
const firebaseConfig = {
  apiKey: "AIzaSyCU6V1v4WfvUt6_Phg8SIajJYE8HMdLJA4",
  authDomain: "farm2home-d0fb2.firebaseapp.com",
  projectId: "farm2home-d0fb2",
  storageBucket: "farm2home-d0fb2.firebasestorage.app",
  messagingSenderId: "590976254739",
  appId: "1:590976254739:web:90c9fd497ef91a751310e6",
  measurementId: "G-P26481CVYF",
};
```

**✅ This configuration is already updated in your `templates/login.html` file!**

### Create `.env` file

Create a `.env` file in your project root with your Firebase credentials:

```env
# Firebase Configuration
FIREBASE_PROJECT_ID=farm2home-d0fb2
FIREBASE_PRIVATE_KEY_ID=your-private-key-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your-service-account@farm2home-d0fb2.iam.gserviceaccount.com
FIREBASE_CLIENT_ID=your-client-id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
FIREBASE_AUTH_PROVIDER_X509_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
FIREBASE_CLIENT_X509_CERT_URL=https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40farm2home-d0fb2.iam.gserviceaccount.com

# Flask Configuration
FLASK_SECRET_KEY=your-secret-key-here
FLASK_ENV=development
```

**💡 Quick Setup**: Run `python setup_firebase.py` to automatically create the .env file with your project configuration!

## Step 7: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 8: Run Migration (Optional)

If you have existing data in SQLite, migrate it to Firestore:

```bash
python migrate_to_firebase.py
```

## Step 9: Test the Setup

1. Start your Flask application:

   ```bash
   python backend.py
   ```

2. Open your browser and go to `http://localhost:5000`

3. Try the following:
   - Register a new user with email/password
   - Login with email/password
   - Login with Google (if enabled)
   - Check Firestore console to see your data

## Features Added

### Authentication

- ✅ Firebase Authentication integration
- ✅ Email/Password authentication
- ✅ Google Sign-In
- ✅ Token-based authentication
- ✅ Session management

### Database

- ✅ Firestore integration
- ✅ Firestore models for all entities
- ✅ Data migration script
- ✅ Fallback to SQLAlchemy

### Frontend

- ✅ Firebase SDK integration
- ✅ Google Sign-In button
- ✅ Firebase authentication functions
- ✅ Token handling

## Security Rules (Firestore)

For production, update your Firestore security rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can read/write their own data
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }

    // Products are readable by all authenticated users
    match /products/{productId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null &&
        (resource.data.farmer_id == request.auth.uid ||
         get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
    }

    // Orders are readable by customer and farmer
    match /orders/{orderId} {
      allow read, write: if request.auth != null &&
        (resource.data.customer_id == request.auth.uid ||
         resource.data.farmer_id == request.auth.uid ||
         get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Firebase not initialized**: Check your service account key file path
2. **Authentication failed**: Verify your Firebase config in the frontend
3. **Permission denied**: Check your Firestore security rules
4. **CORS errors**: Make sure your domain is added to Firebase authorized domains

### Debug Mode

Enable debug logging by setting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Next Steps

1. Set up Firebase Hosting for production deployment
2. Configure Firebase Cloud Messaging for notifications
3. Set up Firebase Storage for file uploads
4. Implement Firebase Security Rules
5. Add more authentication providers (Facebook, Twitter, etc.)

## Support

For issues with this setup, check:

- [Firebase Documentation](https://firebase.google.com/docs)
- [Firebase Python SDK](https://firebase.google.com/docs/admin/setup)
- [Firebase Auth Web SDK](https://firebase.google.com/docs/auth/web/start)
