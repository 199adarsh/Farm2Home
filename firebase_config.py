import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
from dotenv import load_dotenv

load_dotenv()

class FirebaseConfig:
    def __init__(self):
        self.cred = None
        self.db = None
        self.auth = None
        self.initialize_firebase()
    
    def initialize_firebase(self):
        """Initialize Firebase Admin SDK"""
        try:
            # Check if Firebase is already initialized
            if not firebase_admin._apps:
                # Try environment variables first (for Vercel)
                if os.getenv('GOOGLE_APPLICATION_CREDENTIALS_JSON'):
                    import json
                    cred_dict = json.loads(os.getenv('GOOGLE_APPLICATION_CREDENTIALS_JSON'))
                    self.cred = credentials.Certificate(cred_dict)
                    firebase_admin.initialize_app(self.cred)
                    print("Firebase initialized with environment variables!")
                elif os.path.exists('firebase-service-account.json'):
                    self.cred = credentials.Certificate('firebase-service-account.json')
                    firebase_admin.initialize_app(self.cred)
                    print("Firebase initialized with service account file!")
                else:
                    # Try to use environment variables
                    try:
                        self.cred = credentials.ApplicationDefault()
                        firebase_admin.initialize_app(self.cred)
                        print("Firebase initialized with Application Default Credentials!")
                    except Exception as env_error:
                        print(f"Application Default Credentials not found: {env_error}")
                        print("Firebase will run in fallback mode (SQLAlchemy only)")
                        self.db = None
                        self.auth = None
                        return
            
            # Initialize Firestore and Auth
            self.db = firestore.client()
            self.auth = auth
            print("Firebase initialized successfully!")
            
        except Exception as e:
            print(f"Error initializing Firebase: {e}")
            print("Firebase will run in fallback mode (SQLAlchemy only)")
            self.db = None
            self.auth = None
    
    def get_firestore(self):
        """Get Firestore database instance"""
        return self.db
    
    def get_auth(self):
        """Get Firebase Auth instance"""
        return self.auth

# Global Firebase instance
firebase = FirebaseConfig()
