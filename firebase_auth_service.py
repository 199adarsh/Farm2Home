import firebase_admin
from firebase_admin import auth as firebase_auth
from firebase_config import firebase
from firestore_models import User
import json

class FirebaseAuthService:
    """Firebase Authentication Service"""
    
    def __init__(self):
        self.auth = firebase.get_auth()
        self.user_model = User()
        self.firebase_available = self.auth is not None
    
    def verify_token(self, token: str) -> dict:
        """Verify Firebase ID token"""
        if not self.firebase_available:
            print("Firebase Auth not available")
            return None
        try:
            decoded_token = firebase_auth.verify_id_token(token)
            return decoded_token
        except Exception as e:
            print(f"Token verification failed: {e}")
            return None
    
    def create_user(self, email: str, password: str, display_name: str = None, **kwargs) -> dict:
        """Create a new user in Firebase Auth"""
        try:
            user_record = firebase_auth.create_user(
                email=email,
                password=password,
                display_name=display_name,
                **kwargs
            )
            
            # Create user document in Firestore
            user_data = {
                'uid': user_record.uid,
                'email': email,
                'name': display_name or '',
                'username': kwargs.get('username', email.split('@')[0]),
                'phone': kwargs.get('phone', ''),
                'address': kwargs.get('address', ''),
                'role': kwargs.get('role', 'customer'),
                'is_active': True,
                'created_at': user_record.metadata.creation_timestamp,
                'updated_at': user_record.metadata.last_sign_in_timestamp
            }
            
            # Add role-specific fields
            if kwargs.get('role') == 'farmer':
                user_data.update({
                    'farm_name': kwargs.get('farm_name', ''),
                    'farm_description': kwargs.get('farm_description', ''),
                    'certifications': kwargs.get('certifications', ''),
                    'id_verification': kwargs.get('id_verification', '')
                })
            elif kwargs.get('role') == 'customer':
                user_data.update({
                    'delivery_address': kwargs.get('delivery_address', ''),
                    'pin_code': kwargs.get('pin_code', ''),
                    'profile_picture': kwargs.get('profile_picture', '')
                })
            
            # Save to Firestore
            user_id = self.user_model.create_user(user_data)
            
            return {
                'success': True,
                'uid': user_record.uid,
                'user_id': user_id,
                'user_data': user_data
            }
            
        except Exception as e:
            print(f"Error creating user: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_user_by_uid(self, uid: str) -> dict:
        """Get user by Firebase UID"""
        try:
            user_record = firebase_auth.get_user(uid)
            
            # Get additional data from Firestore
            firestore_user = self.user_model.get_by_field('uid', uid)
            if firestore_user:
                user_data = firestore_user[0]
                user_data['firebase_user'] = {
                    'uid': user_record.uid,
                    'email': user_record.email,
                    'display_name': user_record.display_name,
                    'email_verified': user_record.email_verified,
                    'disabled': user_record.disabled,
                    'metadata': {
                        'creation_timestamp': user_record.metadata.creation_timestamp,
                        'last_sign_in_timestamp': user_record.metadata.last_sign_in_timestamp
                    }
                }
                return user_data
            
            return None
            
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def update_user(self, uid: str, **kwargs) -> bool:
        """Update user in Firebase Auth and Firestore"""
        try:
            # Update Firebase Auth
            if 'email' in kwargs:
                firebase_auth.update_user(uid, email=kwargs['email'])
            if 'display_name' in kwargs:
                firebase_auth.update_user(uid, display_name=kwargs['display_name'])
            if 'password' in kwargs:
                firebase_auth.update_user(uid, password=kwargs['password'])
            
            # Update Firestore
            firestore_data = {k: v for k, v in kwargs.items() 
                            if k not in ['email', 'display_name', 'password']}
            
            if firestore_data:
                firestore_user = self.user_model.get_by_field('uid', uid)
                if firestore_user:
                    self.user_model.update(firestore_user[0]['id'], firestore_data)
            
            return True
            
        except Exception as e:
            print(f"Error updating user: {e}")
            return False
    
    def delete_user(self, uid: str) -> bool:
        """Delete user from Firebase Auth and Firestore"""
        try:
            # Delete from Firebase Auth
            firebase_auth.delete_user(uid)
            
            # Delete from Firestore
            firestore_user = self.user_model.get_by_field('uid', uid)
            if firestore_user:
                self.user_model.delete(firestore_user[0]['id'])
            
            return True
            
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False
    
    def disable_user(self, uid: str) -> bool:
        """Disable user account"""
        try:
            firebase_auth.update_user(uid, disabled=True)
            
            # Update Firestore
            firestore_user = self.user_model.get_by_field('uid', uid)
            if firestore_user:
                self.user_model.update(firestore_user[0]['id'], {'is_active': False})
            
            return True
            
        except Exception as e:
            print(f"Error disabling user: {e}")
            return False
    
    def enable_user(self, uid: str) -> bool:
        """Enable user account"""
        try:
            firebase_auth.update_user(uid, disabled=False)
            
            # Update Firestore
            firestore_user = self.user_model.get_by_field('uid', uid)
            if firestore_user:
                self.user_model.update(firestore_user[0]['id'], {'is_active': True})
            
            return True
            
        except Exception as e:
            print(f"Error enabling user: {e}")
            return False
    
    def list_users(self, max_results: int = 1000) -> list:
        """List all users"""
        try:
            users = []
            page = firebase_auth.list_users(max_results=max_results)
            
            for user in page.users:
                firestore_user = self.user_model.get_by_field('uid', user.uid)
                if firestore_user:
                    user_data = firestore_user[0]
                    user_data['firebase_user'] = {
                        'uid': user.uid,
                        'email': user.email,
                        'display_name': user.display_name,
                        'email_verified': user.email_verified,
                        'disabled': user.disabled
                    }
                    users.append(user_data)
            
            return users
            
        except Exception as e:
            print(f"Error listing users: {e}")
            return []
    
    def create_custom_token(self, uid: str, additional_claims: dict = None) -> str:
        """Create custom token for testing"""
        try:
            return firebase_auth.create_custom_token(uid, additional_claims)
        except Exception as e:
            print(f"Error creating custom token: {e}")
            return None

# Global auth service instance
auth_service = FirebaseAuthService()
