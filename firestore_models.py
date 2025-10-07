from datetime import datetime
from typing import Dict, Any, Optional, List
from firebase_config import firebase

class FirestoreModel:
    """Base class for Firestore models"""
    
    def __init__(self, collection_name: str):
        self.collection_name = collection_name
        self.db = firebase.get_firestore()
        self.firebase_available = self.db is not None
    
    def _check_firebase(self):
        """Check if Firebase is available"""
        if not self.firebase_available:
            print(f"Firebase not available, cannot perform operation on {self.collection_name}")
            return False
        return True
    
    def create(self, data: Dict[str, Any]) -> str:
        """Create a new document"""
        if not self._check_firebase():
            return None
        data['created_at'] = datetime.utcnow()
        data['updated_at'] = datetime.utcnow()
        doc_ref = self.db.collection(self.collection_name).add(data)
        return doc_ref[1].id
    
    def get_by_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Get document by ID"""
        if not self._check_firebase():
            return None
        doc = self.db.collection(self.collection_name).document(doc_id).get()
        if doc.exists:
            data = doc.to_dict()
            data['id'] = doc.id
            return data
        return None
    
    def get_by_field(self, field: str, value: Any) -> List[Dict[str, Any]]:
        """Get documents by field value"""
        if not self._check_firebase():
            return []
        docs = self.db.collection(self.collection_name).where(field, '==', value).get()
        return [{'id': doc.id, **doc.to_dict()} for doc in docs]
    
    def get_all(self) -> List[Dict[str, Any]]:
        """Get all documents"""
        if not self._check_firebase():
            return []
        docs = self.db.collection(self.collection_name).get()
        return [{'id': doc.id, **doc.to_dict()} for doc in docs]
    
    def update(self, doc_id: str, data: Dict[str, Any]) -> bool:
        """Update document"""
        if not self._check_firebase():
            return False
        try:
            data['updated_at'] = datetime.utcnow()
            self.db.collection(self.collection_name).document(doc_id).update(data)
            return True
        except Exception as e:
            print(f"Error updating document: {e}")
            return False
    
    def delete(self, doc_id: str) -> bool:
        """Delete document"""
        if not self._check_firebase():
            return False
        try:
            self.db.collection(self.collection_name).document(doc_id).delete()
            return True
        except Exception as e:
            print(f"Error deleting document: {e}")
            return False
    
    def query(self, filters: List[tuple] = None, order_by: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """Query documents with filters"""
        if not self._check_firebase():
            return []
        query = self.db.collection(self.collection_name)
        
        if filters:
            for field, operator, value in filters:
                query = query.where(field, operator, value)
        
        if order_by:
            query = query.order_by(order_by)
        
        if limit:
            query = query.limit(limit)
        
        docs = query.get()
        return [{'id': doc.id, **doc.to_dict()} for doc in docs]

class User(FirestoreModel):
    """User model for Firestore"""
    
    def __init__(self):
        super().__init__('users')
    
    def create_user(self, user_data: Dict[str, Any]) -> str:
        """Create a new user"""
        # Add default values
        user_data.setdefault('is_active', True)
        user_data.setdefault('role', 'customer')
        user_data.setdefault('created_at', datetime.utcnow())
        user_data.setdefault('updated_at', datetime.utcnow())
        
        return self.create(user_data)
    
    def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        users = self.get_by_field('username', username)
        return users[0] if users else None
    
    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        users = self.get_by_field('email', email)
        return users[0] if users else None
    
    def get_by_role(self, role: str) -> List[Dict[str, Any]]:
        """Get users by role"""
        return self.get_by_field('role', role)
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user (for migration - will be replaced with Firebase Auth)"""
        user = self.get_by_username(username)
        if user and user.get('is_active', False):
            # For now, we'll use the existing password hash
            # In production, this should use Firebase Auth
            return user
        return None

class Product(FirestoreModel):
    """Product model for Firestore"""
    
    def __init__(self):
        super().__init__('products')
    
    def create_product(self, product_data: Dict[str, Any]) -> str:
        """Create a new product"""
        product_data.setdefault('is_approved', True)
        product_data.setdefault('in_stock', True)
        product_data.setdefault('created_at', datetime.utcnow())
        product_data.setdefault('updated_at', datetime.utcnow())
        
        return self.create(product_data)
    
    def get_by_farmer(self, farmer_id: str) -> List[Dict[str, Any]]:
        """Get products by farmer ID"""
        return self.get_by_field('farmer_id', farmer_id)
    
    def get_approved_products(self) -> List[Dict[str, Any]]:
        """Get all approved products"""
        return self.get_by_field('is_approved', True)
    
    def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get products by category"""
        return self.get_by_field('category', category)
    
    def search_products(self, search_term: str) -> List[Dict[str, Any]]:
        """Search products by name or description"""
        # Firestore doesn't support full-text search, so we'll filter client-side
        all_products = self.get_approved_products()
        search_term = search_term.lower()
        
        return [
            product for product in all_products
            if search_term in product.get('name', '').lower() or 
               search_term in product.get('description', '').lower()
        ]

class Order(FirestoreModel):
    """Order model for Firestore"""
    
    def __init__(self):
        super().__init__('orders')
    
    def create_order(self, order_data: Dict[str, Any]) -> str:
        """Create a new order"""
        order_data.setdefault('status', 'pending')
        order_data.setdefault('order_date', datetime.utcnow())
        order_data.setdefault('created_at', datetime.utcnow())
        order_data.setdefault('updated_at', datetime.utcnow())
        
        return self.create(order_data)
    
    def get_by_customer(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get orders by customer ID"""
        return self.get_by_field('customer_id', customer_id)
    
    def get_by_farmer(self, farmer_id: str) -> List[Dict[str, Any]]:
        """Get orders by farmer ID"""
        return self.get_by_field('farmer_id', farmer_id)
    
    def get_by_status(self, status: str) -> List[Dict[str, Any]]:
        """Get orders by status"""
        return self.get_by_field('status', status)

class OrderItem(FirestoreModel):
    """OrderItem model for Firestore"""
    
    def __init__(self):
        super().__init__('order_items')
    
    def create_order_item(self, item_data: Dict[str, Any]) -> str:
        """Create a new order item"""
        item_data.setdefault('created_at', datetime.utcnow())
        item_data.setdefault('updated_at', datetime.utcnow())
        
        return self.create(item_data)
    
    def get_by_order(self, order_id: str) -> List[Dict[str, Any]]:
        """Get order items by order ID"""
        return self.get_by_field('order_id', order_id)

class Notification(FirestoreModel):
    """Notification model for Firestore"""
    
    def __init__(self):
        super().__init__('notifications')
    
    def create_notification(self, notification_data: Dict[str, Any]) -> str:
        """Create a new notification"""
        notification_data.setdefault('is_read', False)
        notification_data.setdefault('created_at', datetime.utcnow())
        notification_data.setdefault('updated_at', datetime.utcnow())
        
        return self.create(notification_data)
    
    def get_by_user(self, user_id: str) -> List[Dict[str, Any]]:
        """Get notifications by user ID"""
        return self.get_by_field('user_id', user_id)
    
    def mark_as_read(self, notification_id: str) -> bool:
        """Mark notification as read"""
        return self.update(notification_id, {'is_read': True})

class BulkOrder(FirestoreModel):
    """BulkOrder model for Firestore"""
    
    def __init__(self):
        super().__init__('bulk_orders')
    
    def create_bulk_order(self, bulk_order_data: Dict[str, Any]) -> str:
        """Create a new bulk order"""
        bulk_order_data.setdefault('status', 'pending')
        bulk_order_data.setdefault('created_at', datetime.utcnow())
        bulk_order_data.setdefault('updated_at', datetime.utcnow())
        
        return self.create(bulk_order_data)
    
    def get_by_customer(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get bulk orders by customer ID"""
        return self.get_by_field('customer_id', customer_id)
