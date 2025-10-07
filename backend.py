# =============================================================================
# IMPORTS
# =============================================================================
from flask import (
    Flask, render_template, request, redirect, url_for, flash, 
    session, jsonify, Blueprint, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, 
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest
from datetime import datetime
from functools import wraps
from flask import json as flask_json
import os
import secrets
import csv
from io import StringIO

# Firebase imports
from firebase_config import firebase
from firestore_models import User as FirestoreUser, Product as FirestoreProduct, Order as FirestoreOrder, OrderItem as FirestoreOrderItem, Notification as FirestoreNotification, BulkOrder as FirestoreBulkOrder
from firebase_auth_service import auth_service

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_csrf_token():
    """Generate CSRF token for form protection."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']


def add_admin_commission(price):
    """Add 3% commission to the farmer's price for admin revenue."""
    return round(price * 1.03, 2)


def validate_quantity(val):
    """Validate that quantity is a positive number."""
    try:
        q = float(val)
        return q > 0
    except Exception:
        return False


def validate_price(val):
    """Validate that price is a positive number."""
    try:
        p = float(val)
        return p > 0
    except Exception:
        return False

# =============================================================================
# FLASK APP CONFIGURATION
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')
# Use in-memory database for Vercel (serverless) or file-based for local development
if os.getenv('VERCEL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///farm2home.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max upload size

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Firebase (lazy initialization for serverless)
firebase_initialized = False
firestore_user = None
firestore_product = None
firestore_order = None
firestore_order_item = None
firestore_notification = None
firestore_bulk_order = None

def initialize_firebase_if_needed():
    global firebase_initialized, firestore_user, firestore_product, firestore_order, firestore_order_item, firestore_notification, firestore_bulk_order
    
    if not firebase_initialized:
        try:
            firebase.initialize_firebase()
            print("Firebase initialized successfully!")
            firebase_initialized = True
            
            # Initialize Firestore models
            firestore_user = FirestoreUser()
            firestore_product = FirestoreProduct()
            firestore_order = FirestoreOrder()
            firestore_order_item = FirestoreOrderItem()
            firestore_notification = FirestoreNotification()
            firestore_bulk_order = FirestoreBulkOrder()
        except Exception as e:
            print(f"Firebase initialization failed: {e}")
            print("Continuing with SQLAlchemy fallback...")
            firebase_initialized = True  # Mark as attempted to avoid retries

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set Jinja2 global for CSRF token after app is defined
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Initialize Firebase on first request (serverless-friendly)
@app.before_request
def before_request():
    initialize_firebase_if_needed()

def get_product_image(product_name, image_filename=None):
    """Get the appropriate image for a product based on its name."""
    if image_filename:
        return url_for('static', filename='uploads/' + image_filename)
    
    # Default images to cycle through when no image is uploaded
    default_images = ['01.jpg', '02.jpg', '03.jpg', '04.jpg']
    
    # Use default images based on product name hash for consistency
    import hashlib
    hash_value = int(hashlib.md5(product_name.encode()).hexdigest(), 16)
    default_image = default_images[hash_value % len(default_images)]
    return url_for('static', filename='img/' + default_image)

# Make the function available in templates
app.jinja_env.globals['get_product_image'] = get_product_image

# =============================================================================
# MIDDLEWARE & REQUEST HANDLERS
# =============================================================================
@app.before_request
def csrf_protect():
    """Protect against CSRF attacks for POST requests."""
    if request.method == "POST" and not request.path.startswith('/api/'):
        token = session.get('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return jsonify({'error': 'CSRF token missing or invalid'}), 400

def verify_firebase_token():
    """Verify Firebase token from request headers"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split('Bearer ')[1]
    try:
        decoded_token = auth_service.verify_token(token)
        return decoded_token
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None

def get_current_firebase_user():
    """Get current user from Firebase token"""
    decoded_token = verify_firebase_token()
    if decoded_token:
        uid = decoded_token.get('uid')
        return auth_service.get_user_by_uid(uid)
    return None

# =============================================================================
# DATABASE MODELS
# =============================================================================

class User(UserMixin, db.Model):
    """User model for customers, farmers, and admins."""
    
    __tablename__ = 'user'
    
    # Basic user fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    role = db.Column(db.String(20), nullable=False, default='customer')  # customer, farmer, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Farmer specific fields
    farm_name = db.Column(db.String(100))
    farm_description = db.Column(db.Text)
    certifications = db.Column(db.String(200))
    id_verification = db.Column(db.String(200))  # Farmer ID verification file
    
    # Customer specific fields
    delivery_address = db.Column(db.Text)
    pin_code = db.Column(db.String(10))
    profile_picture = db.Column(db.String(200))

class Product(db.Model):
    """Product model for farm products."""
    
    __tablename__ = 'product'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price_per_kg = db.Column(db.Float, nullable=False)
    available_quantity = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(200))
    harvest_date = db.Column(db.DateTime)
    expiry_date = db.Column(db.DateTime)
    category = db.Column(db.String(50))
    is_organic = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    in_stock = db.Column(db.Boolean, default=True)
    
    # Relationships
    farmer = db.relationship('User', backref='products')

class Order(db.Model):
    """Order model for customer orders."""
    
    __tablename__ = 'order'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    farmer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    delivery_address = db.Column(db.Text, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)  # COD, UPI
    status = db.Column(db.String(20), default='pending')  # pending, accepted, packed, delivered, cancelled
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    delivery_date = db.Column(db.DateTime)
    
    # Relationships
    customer = db.relationship('User', foreign_keys=[customer_id], backref='customer_orders')
    farmer = db.relationship('User', foreign_keys=[farmer_id], backref='farmer_orders')

class OrderItem(db.Model):
    """Order item model for individual products in orders."""
    
    __tablename__ = 'order_item'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    price_per_kg = db.Column(db.Float, nullable=False)
    
    # Relationships
    order = db.relationship('Order', backref='items')
    product = db.relationship('Product', backref='order_items')



class Notification(db.Model):
    """Notification model for user notifications."""
    
    __tablename__ = 'notification'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)




class BulkOrder(db.Model):
    """Bulk order model for large quantity orders."""
    
    __tablename__ = 'bulk_order'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.Column(db.Text, nullable=False)  # JSON string of items/quantities
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    customer = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))

# =============================================================================
# ROLE-BASED ACCESS CONTROL & DECORATORS
# =============================================================================
def farmer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'farmer':
            flash('Farmer access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def customer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'customer':
            flash('Customer access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# BLUEPRINT DEFINITIONS
# =============================================================================
farmer_bp = Blueprint('farmer', __name__, url_prefix='/farmer')
customer_bp = Blueprint('customer', __name__, url_prefix='/customer')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# =============================================================================
# BLUEPRINT ROUTES
# =============================================================================

# =============================================================================
# FARMER BLUEPRINT ROUTES
# =============================================================================
@farmer_bp.route('/dashboard')
@login_required
@farmer_required
def farmer_dashboard():
    """Render the farmer dashboard with products, orders, and notifications for the current farmer."""
    products = Product.query.filter_by(farmer_id=current_user.id).all()
    # Get current/pending orders (not delivered or cancelled)
    current_orders = Order.query.filter_by(farmer_id=current_user.id).filter(
        Order.status.in_(['pending', 'accepted', 'packed'])
    ).order_by(Order.order_date.desc()).all()
    
    # Get previous orders (delivered or cancelled)
    previous_orders = Order.query.filter_by(farmer_id=current_user.id).filter(
        Order.status.in_(['delivered', 'cancelled'])
    ).order_by(Order.order_date.desc()).limit(20).all()
    
    # Process products to add required attributes for template
    processed_products = []
    for product in products:
        # Calculate stock percentage
        stock_percent = min(100, int((product.available_quantity / 100) * 100)) if product.available_quantity > 0 else 0
        
        # Create product object with required attributes
        product_data = {
            'id': product.id,
            'name': product.name,
            'stock': product.available_quantity,
            'stock_percent': stock_percent,
            'status': 'In Stock' if product.available_quantity > 0 else 'Out of Stock'
        }
        processed_products.append(product_data)
    
    # Process current orders to add required attributes for template
    processed_current_orders = []
    for order in current_orders:
        # Calculate product count from order items
        product_count = sum(item.quantity for item in order.items)
        # Gather product info for each item
        products_list = []
        for item in order.items:
            products_list.append({
                'name': item.product.name,
                'quantity': item.quantity,
                'category': item.product.category,
                'image': item.product.image_filename,
                'price_per_kg': item.price_per_kg
            })
        # Create order object with required attributes
        order_data = {
            'id': order.id,
            'customer_name': order.customer.name if order.customer else 'Unknown Customer',
            'location': order.delivery_address,
            'price': order.total_amount,
            'product_count': product_count,
            'status': order.status,
            'order_date': order.order_date,
            'products': products_list
        }
        processed_current_orders.append(order_data)
    
    # Process previous orders to add required attributes for template
    processed_previous_orders = []
    for order in previous_orders:
        # Calculate product count from order items
        product_count = sum(item.quantity for item in order.items)
        # Gather product info for each item
        products_list = []
        for item in order.items:
            products_list.append({
                'name': item.product.name,
                'quantity': item.quantity,
                'category': item.product.category,
                'image': item.product.image_filename,
                'price_per_kg': item.price_per_kg
            })
        # Create order object with required attributes
        order_data = {
            'id': order.id,
            'customer_name': order.customer.name if order.customer else 'Unknown Customer',
            'location': order.delivery_address,
            'price': order.total_amount,
            'product_count': product_count,
            'status': order.status,
            'order_date': order.order_date,
            'date': order.order_date.strftime('%Y-%m-%d') if order.order_date else 'N/A',
            'products': products_list
        }
        processed_previous_orders.append(order_data)
    
    total_products = len(products)
    total_orders = len(current_orders) + len(previous_orders)
    total_revenue = sum([o.total_amount for o in current_orders + previous_orders])
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    # Calculate stock percentage for stats
    total_stock = sum(p.available_quantity for p in products) if products else 0
    stock_percent = min(100, int((total_stock / 100) * 100)) if total_stock > 0 else 0
    
    stats = {
        'revenue': total_revenue,
        'stock': total_products,
        'total_orders': total_orders,
        'stock_percent': stock_percent
    }
    
    return render_template(
        'farmer_dashboard.html',
        products=processed_products,
        orders=processed_current_orders,
        previous_orders=processed_previous_orders,
        total_products=total_products,
        total_orders=total_orders,
        total_revenue=total_revenue,
        notifications=notifications,
        stats=stats
    )

# =============================================================================
# CUSTOMER BLUEPRINT ROUTES
# =============================================================================
@customer_bp.route('/dashboard')
@login_required
@customer_required
def customer_dashboard():
    """Render the customer dashboard with orders and recommendations."""
    # Get recommended/featured products (e.g., top 8 by rating or recent)
    products = Product.query.filter_by(is_approved=True).order_by(Product.created_at.desc()).limit(8).all()
    
    # Add default values for rating and reviews count
    for product in products:
        product.rating = 0
        product.reviews_count = 0
    
    # Get categories (distinct)
    categories = db.session.query(Product.category).distinct().all()
    categories = [{'name': c[0], 'active': False} for c in categories]
    # Set first as active for demo
    if categories:
        categories[0]['active'] = True
    # Cart count from session
    cart_count = sum(session.get('cart', {}).values()) if 'cart' in session else 0
    
    # Get notifications for the customer
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()
    
    return render_template(
        'customer_dashboard.html',
        products=products,
        categories=categories,
        current_category=categories[0]['name'] if categories else 'All',
        cart_count=cart_count,
        notifications=notifications
    )

# =============================================================================
# ADMIN BLUEPRINT ROUTES
# =============================================================================
@admin_bp.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Render the admin dashboard with stats and analytics."""
    total_users = User.query.count()
    total_farmers = User.query.filter_by(role='farmer').count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    total_products = Product.query.count()
    
    # Get all users for the Users section
    users = User.query.all()
    
    # Get all products for the Products section
    products = Product.query.all()
    
    # Get all orders for the Orders section
    all_orders = Order.query.order_by(Order.order_date.desc()).all()
    
    # Recent orders for overview
    recent_orders = Order.query.order_by(Order.order_date.desc()).limit(10).all()
    
    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_orders=total_orders,
        total_revenue=total_revenue,
        total_products=total_products,
        users=users,
        products=products,
        all_orders=all_orders,
        recent_orders=recent_orders
    )

# =============================================================================
# MAIN APPLICATION ROUTES
# =============================================================================

@app.route('/')
def index():
    """Home page - redirects to login."""
    return render_template('login.html')


@app.route('/customer')
@login_required
@customer_required
def customer_page():
    """Customer page."""
    return render_template('Customer.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        # Check if this is a Firebase Auth registration
        if request.headers.get('Content-Type') == 'application/json':
            data = request.get_json()
            firebase_token = data.get('firebase_token')
            
            if firebase_token:
                try:
                    decoded_token = auth_service.verify_token(firebase_token)
                    if decoded_token:
                        uid = decoded_token.get('uid')
                        email = decoded_token.get('email', '')
                        name = decoded_token.get('name', '')
                        
                        # Check if user already exists
                        existing_user = firestore_user.get_by_field('uid', uid)
                        if existing_user:
                            return jsonify({'success': False, 'error': 'User already registered'}), 400
                        
                        # Create user in Firestore
                        user_data = {
                            'uid': uid,
                            'email': email,
                            'name': name,
                            'username': data.get('username', email.split('@')[0]),
                            'phone': data.get('phone', ''),
                            'address': data.get('address', ''),
                            'role': data.get('role', 'customer')
                        }
                        
                        # Add role-specific fields
                        if data.get('role') == 'farmer':
                            user_data.update({
                                'farm_name': data.get('farm_name', ''),
                                'farm_description': data.get('farm_description', ''),
                                'certifications': data.get('certifications', ''),
                                'id_verification': data.get('id_verification', '')
                            })
                        elif data.get('role') == 'customer':
                            user_data.update({
                                'delivery_address': data.get('delivery_address', ''),
                                'pin_code': data.get('pin_code', ''),
                                'profile_picture': data.get('profile_picture', '')
                            })
                        
                        user_id = firestore_user.create_user(user_data)
                        
                        return jsonify({
                            'success': True,
                            'message': 'Registration successful!',
                            'user_id': user_id
                        })
                    else:
                        return jsonify({'success': False, 'error': 'Invalid token'}), 401
                except Exception as e:
                    return jsonify({'success': False, 'error': 'Registration failed'}), 500
        
        # Traditional form registration
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        role = request.form['role']
        
        # Check if user exists in Firestore first
        if firestore_user.get_by_username(username):
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        if firestore_user.get_by_email(email):
            flash('Email already exists!', 'error')
            return redirect(url_for('register'))
        
        # Check SQLAlchemy as fallback
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'error')
            return redirect(url_for('register'))
        
        # Validate password confirmation
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        # Try to create user in Firestore first
        try:
            user_data = {
                'username': username,
                'email': email,
                'password_hash': generate_password_hash(password),  # Keep for migration
                'name': name,
                'phone': phone,
                'address': address,
                'role': role
            }
            
            # Add farmer-specific fields
            if role == 'farmer':
                user_data.update({
                    'farm_name': request.form.get('farm_name', ''),
                    'farm_description': request.form.get('farm_description', ''),
                    'certifications': request.form.get('certifications', '')
                })
                # Handle ID verification file upload
                id_file = request.files.get('id_verification')
                if id_file and id_file.filename and allowed_file(id_file.filename):
                    id_filename = secure_filename(id_file.filename)
                    id_file.save(os.path.join(app.config['UPLOAD_FOLDER'], id_filename))
                    user_data['id_verification'] = id_filename
                else:
                    flash('ID verification document is required for farmers and must be a valid file type.', 'error')
                    return redirect(url_for('register'))
            
            # Add customer-specific fields
            if role == 'customer':
                user_data.update({
                    'delivery_address': request.form.get('delivery_address', ''),
                    'pin_code': request.form.get('pin_code', '')
                })
            
            firestore_user.create_user(user_data)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Firestore registration failed: {e}")
            # Fallback to SQLAlchemy
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                name=name,
                phone=phone,
                address=address,
                role=role
            )
            
            # Add farmer-specific fields
            if role == 'farmer':
                user.farm_name = request.form.get('farm_name')
                user.farm_description = request.form.get('farm_description')
                user.certifications = request.form.get('certifications')
                # Handle ID verification file upload
                id_file = request.files.get('id_verification')
                if id_file and id_file.filename and allowed_file(id_file.filename):
                    id_filename = secure_filename(id_file.filename)
                    id_file.save(os.path.join(app.config['UPLOAD_FOLDER'], id_filename))
                    user.id_verification = id_filename
                else:
                    flash('ID verification document is required for farmers and must be a valid file type.', 'error')
                    return redirect(url_for('register'))
            
            # Add customer-specific fields
            if role == 'customer':
                user.delivery_address = request.form.get('delivery_address')
                user.pin_code = request.form.get('pin_code', user.pin_code)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        # Check if this is a Firebase Auth request
        if request.headers.get('Content-Type') == 'application/json':
            data = request.get_json()
            firebase_token = data.get('firebase_token')
            
            if firebase_token:
                try:
                    decoded_token = auth_service.verify_token(firebase_token)
                    if decoded_token:
                        uid = decoded_token.get('uid')
                        user_data = auth_service.get_user_by_uid(uid)
                        
                        if user_data and user_data.get('is_active', False):
                            # Create a session for the user
                            session['user_id'] = user_data['id']
                            session['user_uid'] = uid
                            session['user_role'] = user_data.get('role', 'customer')
                            
                            return jsonify({
                                'success': True,
                                'message': 'Login successful!',
                                'user': {
                                    'id': user_data['id'],
                                    'name': user_data.get('name', ''),
                                    'email': user_data.get('email', ''),
                                    'role': user_data.get('role', 'customer')
                                },
                                'redirect': get_redirect_url(user_data.get('role', 'customer'))
                            })
                        else:
                            return jsonify({'success': False, 'error': 'Account deactivated or not found'}), 401
                    else:
                        return jsonify({'success': False, 'error': 'Invalid token'}), 401
                except Exception as e:
                    return jsonify({'success': False, 'error': 'Authentication failed'}), 401
        
        # Traditional username/password login (fallback)
        username = request.form['username']
        password = request.form['password']
        
        # Try Firebase first
        try:
            firebase_user = firestore_user.get_by_username(username)
            if firebase_user and firebase_user.get('is_active', False):
                # For migration purposes, check if user has password_hash
                if 'password_hash' in firebase_user and check_password_hash(firebase_user['password_hash'], password):
                    session['user_id'] = firebase_user['id']
                    session['user_uid'] = firebase_user.get('uid', '')
                    session['user_role'] = firebase_user.get('role', 'customer')
                    
                    flash('Login successful!', 'success')
                    return redirect(get_redirect_url(firebase_user.get('role', 'customer')))
        except Exception as e:
            print(f"Firebase login error: {e}")
        
        # Fallback to SQLAlchemy
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if user.is_active:
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(get_redirect_url(user.role))
            else:
                flash('Your account has been deactivated.', 'error')
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

def get_redirect_url(role):
    """Get redirect URL based on user role"""
    if role == 'admin':
        return url_for('admin.admin_dashboard')
    elif role == 'farmer':
        return url_for('farmer.farmer_dashboard')
    elif role == 'customer':
        return url_for('customer.customer_dashboard')
    else:
        return url_for('index')

@app.route('/logout')
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files."""
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# API endpoint for products (public access)
@app.route('/api/products', methods=['GET'])
def api_products():
    """
    Get all approved products with optional filters.
    
    Query parameters:
    - category: Filter by product category
    - search: Search in name and description
    - in_stock: Filter by stock availability
    - organic: Filter organic products only
    - sort: Sort by price_low, price_high, or newest
    - page: Page number for pagination
    - harvest_date_from: Filter by harvest date from
    - harvest_date_to: Filter by harvest date to
    
    Returns JSON list of products with id, name, description, price, 
    quantity, category, image, farmer_name, harvest_date.
    """
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')
    organic_only = request.args.get('organic', False, type=lambda v: v.lower() == 'true')
    sort_by = request.args.get('sort', 'newest')
    in_stock = request.args.get('in_stock', False, type=lambda v: v.lower() == 'true')
    location = request.args.get('location', '')
    search = request.args.get('search', '').strip()
    harvest_date_from = request.args.get('harvest_date_from', None)
    harvest_date_to = request.args.get('harvest_date_to', None)

    query = Product.query.filter_by(is_approved=True)
    if category:
        query = query.filter(Product.category == category)
    if organic_only:
        query = query.filter(Product.is_organic == True)
    if in_stock:
        query = query.filter(Product.available_quantity > 0)
    if location:
        query = query.join(User).filter(User.address.ilike(f"%{location}%"))
    if search:
        query = query.filter(
            (Product.name.ilike(f"%{search}%")) |
            (Product.description.ilike(f"%{search}%"))
        )
    if harvest_date_from:
        try:
            dt_from = datetime.strptime(harvest_date_from, '%Y-%m-%d')
            query = query.filter(Product.harvest_date >= dt_from)
        except Exception:
            pass
    if harvest_date_to:
        try:
            dt_to = datetime.strptime(harvest_date_to, '%Y-%m-%d')
            query = query.filter(Product.harvest_date <= dt_to)
        except Exception:
            pass
    if sort_by == 'price_low':
        query = query.order_by(Product.price_per_kg.asc())
    elif sort_by == 'price_high':
        query = query.order_by(Product.price_per_kg.desc())
    elif sort_by == 'newest':
        query = query.order_by(Product.created_at.desc())
    else:
        query = query.order_by(Product.created_at.desc())

    products = query.paginate(page=page, per_page=12, error_out=False)
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'description': p.description,
            'price': p.price_per_kg,
            'quantity': p.available_quantity,
            'category': p.category,
            'image': get_product_image(p.name, p.image_filename),
            'farmer_name': p.farmer.name if p.farmer else '',
            'harvest_date': p.harvest_date.strftime('%Y-%m-%d') if p.harvest_date else None
        } for p in products.items
    ])

@app.route('/product/<int:id>')
def product_detail(id):
    """Render product detail page."""
    product = Product.query.get_or_404(id)
    # Redirect to customer dashboard for now since product_detail.html doesn't exist
    flash(f'Product: {product.name} - ${product.price_per_kg}/kg', 'info')
    return redirect(url_for('customer.customer_dashboard'))

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    if current_user.role != 'customer':
        flash('Only customers can add items to cart.', 'error')
        return redirect(url_for('product_detail', id=product_id))
    
    quantity = float(request.form.get('quantity', 1))
    
    if 'cart' not in session:
        session['cart'] = {}
    
    cart = session['cart']
    if str(product_id) in cart:
        cart[str(product_id)] += quantity
    else:
        cart[str(product_id)] = quantity
    
    session['cart'] = cart
    flash('Item added to cart!', 'success')
    return redirect(url_for('product_detail', id=product_id))

@app.route('/cart')
@login_required
def cart():
    if current_user.role != 'customer':
        flash('Only customers can view cart.', 'error')
        return redirect(url_for('index'))
    
    cart = session.get('cart', {})
    cart_items = []
    total = 0
    
    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            item_total = product.price_per_kg * quantity
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'total': item_total
            })
            total += item_total
    
    # Render cart directly in customer dashboard template
    return render_template('customer_dashboard.html', 
                         cart_items=cart_items, 
                         cart_total=total,
                         show_cart=True,
                         products=[],
                         categories=[],
                         cart_count=sum(cart.values()) if cart else 0,
                         today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if current_user.role != 'customer':
        flash('Only customers can checkout.', 'error')
        return redirect(url_for('index'))
    
    cart = session.get('cart', {})
    if not cart:
        flash('Your cart is empty.', 'error')
        return redirect(url_for('customer.customer_dashboard'))
    
    if request.method == 'POST':
        delivery_address = request.form['delivery_address']
        payment_method = request.form['payment_method']
        delivery_date_str = request.form.get('delivery_date')
        delivery_date = None
        if delivery_date_str:
            try:
                delivery_date = datetime.strptime(delivery_date_str, '%Y-%m-%d')
            except Exception:
                delivery_date = None
        # Group items by farmer
        farmer_orders = {}
        for product_id, quantity in cart.items():
            product = Product.query.get(int(product_id))
            if product:
                farmer_id = product.farmer_id
                if farmer_id not in farmer_orders:
                    farmer_orders[farmer_id] = []
                farmer_orders[farmer_id].append({
                    'product': product,
                    'quantity': quantity
                })
        # Create orders for each farmer
        for farmer_id, items in farmer_orders.items():
            total_amount = sum(item['product'].price_per_kg * item['quantity'] for item in items)
            order = Order(
                customer_id=current_user.id,
                farmer_id=farmer_id,
                total_amount=total_amount,
                delivery_address=delivery_address,
                payment_method=payment_method,
                delivery_date=delivery_date
            )
            db.session.add(order)
            db.session.flush()
            # Add order items
            for item in items:
                order_item = OrderItem(
                    order_id=order.id,
                    product_id=item['product'].id,
                    quantity=item['quantity'],
                    price_per_kg=item['product'].price_per_kg
                )
                db.session.add(order_item)
        db.session.commit()
        session.pop('cart', None)
        flash('Order placed successfully!', 'success')
        return redirect(url_for('order_history'))
    
    # Show checkout form in customer dashboard
    cart = session.get('cart', {})
    cart_items = []
    total = 0
    
    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            item_total = product.price_per_kg * quantity
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'total': item_total
            })
            total += item_total
    
    return render_template('customer_dashboard.html', 
                         cart_items=cart_items, 
                         cart_total=total,
                         show_checkout=True,
                         products=[],
                         categories=[],
                         cart_count=sum(cart.values()) if cart else 0,
                         today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/order_history')
@login_required
def order_history():
    orders = Order.query.filter_by(customer_id=current_user.id).order_by(Order.order_date.desc()).all()
    # Redirect to customer dashboard for now since order_history.html doesn't exist
    flash(f'You have {len(orders)} orders', 'info')
    return redirect(url_for('customer.customer_dashboard'))


# =============================================================================
# FARMER ROUTES
# =============================================================================
@app.route('/farmer/add_product', methods=['GET', 'POST'])
@login_required
@farmer_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price_per_kg = request.form['price_per_kg']
        available_quantity = request.form['available_quantity']
        category = request.form['category']
        is_organic = bool(request.form.get('is_organic'))
        if not validate_price(price_per_kg):
            flash('Price must be a positive number.', 'error')
            return redirect(url_for('add_product'))
        if not validate_quantity(available_quantity):
            flash('Quantity must be a positive number.', 'error')
            return redirect(url_for('add_product'))
        # Add 3% admin commission to the farmer's price
        final_price = add_admin_commission(float(price_per_kg))
        
        product = Product(
            name=name,
            description=description,
            price_per_kg=final_price,
            available_quantity=float(available_quantity),
            category=category,
            is_organic=is_organic,
            farmer_id=current_user.id
        )
        
        # Handle file upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_filename = filename
            elif file and file.filename:
                flash('Invalid file type.', 'error')
                return redirect(url_for('add_product'))
        # Handle harvest and expiry dates
        harvest_date = request.form.get('harvest_date')
        expiry_date = request.form.get('expiry_date')
        if harvest_date:
            product.harvest_date = datetime.strptime(harvest_date, '%Y-%m-%d')
        if expiry_date:
            product.expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d')
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('farmer.farmer_dashboard'))
    # For GET, redirect to dashboard (form is there)
    return redirect(url_for('farmer.farmer_dashboard'))

@app.route('/farmer/orders')
@login_required
@farmer_required
def farmer_orders():
    orders = Order.query.filter_by(farmer_id=current_user.id).order_by(Order.order_date.desc()).all()
    # Redirect to farmer dashboard for now since farmer_orders.html doesn't exist
    flash(f'You have {len(orders)} orders', 'info')
    return redirect(url_for('farmer.farmer_dashboard'))

@app.route('/farmer/update_order_status/<int:order_id>', methods=['POST'])
@login_required
@farmer_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    if order.farmer_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    
    new_status = request.form['status']
    
    # Validate status transition
    valid_transitions = {
        'accepted': ['packed', 'cancelled', 'delivered'],  # allow direct delivery
        'packed': ['delivered'],
        'delivered': [],
        'cancelled': []
    }
    
    if order.status not in valid_transitions or new_status not in valid_transitions[order.status]:
        flash('Invalid status transition!', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    
    order.status = new_status
    
    # Set delivery date when marked as delivered
    if new_status == 'delivered':
        order.delivery_date = datetime.utcnow()
    
    # Create notification for customer
    status_messages = {
        'packed': f'Your order #{order.id} has been packed and is ready for delivery!',
        'delivered': f'Your order #{order.id} has been delivered successfully! Thank you for choosing us.',
        'cancelled': f'Your order #{order.id} has been cancelled. Please contact us if you have any questions.'
    }
    
    if new_status in status_messages:
        notification = Notification(
            user_id=order.customer_id,
            message=status_messages[new_status]
        )
        db.session.add(notification)
    
    db.session.commit()
    flash(f'Order #{order.id} status updated to {new_status}!', 'success')
    return redirect(url_for('farmer.farmer_dashboard'))

@app.route('/farmer/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@farmer_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.farmer_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        # Add 3% admin commission to the farmer's price
        product.price_per_kg = add_admin_commission(float(request.form['price_per_kg']))
        product.available_quantity = float(request.form['available_quantity'])
        product.category = request.form['category']
        product.is_organic = bool(request.form.get('is_organic'))
        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_filename = filename
        # Handle harvest and expiry dates
        harvest_date = request.form.get('harvest_date')
        expiry_date = request.form.get('expiry_date')
        if harvest_date:
            product.harvest_date = datetime.strptime(harvest_date, '%Y-%m-%d')
        if expiry_date:
            product.expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d')
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('farmer.farmer_dashboard'))
    # Redirect to farmer dashboard for now since edit_product.html doesn't exist
    flash(f'Editing product: {product.name}', 'info')
    return redirect(url_for('farmer.farmer_dashboard'))

@app.route('/farmer/delete_product/<int:product_id>', methods=['POST'])
@login_required
@farmer_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.farmer_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('farmer.farmer_dashboard'))

@app.route('/farmer/accept_order/<int:order_id>', methods=['POST'])
@login_required
@farmer_required
def accept_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.farmer_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    
    # Check if order is already processed
    if order.status != 'pending':
        flash('Order has already been processed!', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    
    # Update order status
    order.status = 'accepted'
    
    # Update product stock (reduce available quantity)
    for item in order.items:
        product = item.product
        if product.available_quantity >= item.quantity:
            product.available_quantity -= item.quantity
            # Mark as out of stock if quantity becomes 0
            if product.available_quantity == 0:
                product.in_stock = False
        else:
            flash(f'Insufficient stock for {product.name}!', 'error')
            return redirect(url_for('farmer.farmer_dashboard'))
    
    # Create notification for customer
    notification = Notification(
        user_id=order.customer_id,
        message=f'Your order #{order.id} has been accepted by {current_user.farm_name or current_user.name}. We will start preparing your order soon!'
    )
    db.session.add(notification)
    
    db.session.commit()
    flash(f'Order #{order.id} accepted successfully! Customer has been notified.', 'success')
    return redirect(url_for('farmer.farmer_dashboard'))

@app.route('/farmer/reject_order/<int:order_id>', methods=['POST'])
@login_required
@farmer_required
def reject_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.farmer_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    
    # Check if order is already processed
    if order.status != 'pending':
        flash('Order has already been processed!', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    
    # Update order status
    order.status = 'cancelled'
    
    # Create notification for customer
    notification = Notification(
        user_id=order.customer_id,
        message=f'Sorry! Your order #{order.id} has been rejected by {current_user.farm_name or current_user.name}. We apologize for any inconvenience. Please contact us if you have any questions or would like to place a new order.'
    )
    db.session.add(notification)
    
    db.session.commit()
    flash(f'Order #{order.id} rejected successfully! Customer has been notified.', 'success')
    return redirect(url_for('farmer.farmer_dashboard'))

# =============================================================================
# ADMIN ROUTES
# =============================================================================
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    # Redirect to admin dashboard for now since admin_users.html doesn't exist
    flash(f'Total users: {users.total}', 'info')
    return redirect(url_for('admin.admin_dashboard'))

@app.route('/admin/products')
@login_required
@admin_required
def admin_products():
    products = Product.query.all()
    # Redirect to admin dashboard for now since admin_products.html doesn't exist
    flash(f'Total products: {len(products)}', 'info')
    return redirect(url_for('admin.admin_dashboard'))

@app.route('/admin/orders')
@login_required
@admin_required
def admin_orders():
    status = request.args.get('status', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = Order.query
    if status:
        query = query.filter(Order.status == status)
    orders = query.order_by(Order.order_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    # Redirect to admin dashboard for now since admin_orders.html doesn't exist
    flash(f'Total orders: {orders.total}', 'info')
    return redirect(url_for('admin.admin_dashboard'))

@app.route('/admin/toggle_user_status/<int:user_id>')
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f'User {"activated" if user.is_active else "deactivated"} successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.name = request.form['name']
        user.phone = request.form['phone']
        user.address = request.form['address']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    # Redirect to admin dashboard for now since admin_edit_user.html doesn't exist
    flash(f'Editing user: {user.name}', 'info')
    return redirect(url_for('admin.admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/approve_user/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'farmer':
        user.is_active = True
        db.session.commit()
        flash('Farmer account approved!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/reject_user/<int:user_id>')
@login_required
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'farmer':
        user.is_active = False
        db.session.commit()
        flash('Farmer account rejected/suspended!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/approve_product/<int:product_id>')
@login_required
@admin_required
def approve_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_approved = True
    db.session.commit()
    flash('Product approved!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/reject_product/<int:product_id>')
@login_required
@admin_required
def reject_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_approved = False
    db.session.commit()
    flash('Product rejected!', 'success')
    return redirect(url_for('admin_products'))

# =============================================================================
# API ROUTES
# =============================================================================
@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
@login_required
@customer_required
def remove_from_cart(product_id):
    if current_user.role != 'customer':
        flash('Only customers can remove items from cart.', 'error')
        return redirect(url_for('index'))
    cart = session.get('cart', {})
    product_id_str = str(product_id)
    if product_id_str in cart:
        cart.pop(product_id_str)
        session['cart'] = cart
        flash('Item removed from cart!', 'success')
    else:
        flash('Item not found in cart.', 'error')
    return redirect(url_for('cart'))

# Profile picture upload in profile edit (farmer & customer)
@farmer_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@farmer_required
def edit_profile():
    user = current_user
    if request.method == 'POST':
        user.name = request.form.get('name', user.name)
        user.email = request.form.get('email', user.email)
        user.phone = request.form.get('phone', user.phone)
        user.address = request.form.get('address', user.address)
        user.farm_name = request.form.get('farm_name', user.farm_name)
        user.farm_description = request.form.get('farm_description', user.farm_description)
        user.certifications = request.form.get('certifications', user.certifications)
        id_file = request.files.get('id_verification')
        if id_file and id_file.filename and allowed_file(id_file.filename):
            id_filename = secure_filename(id_file.filename)
            id_file.save(os.path.join(app.config['UPLOAD_FOLDER'], id_filename))
            user.id_verification = id_filename
        # Profile picture
        pic_file = request.files.get('profile_picture')
        if pic_file and pic_file.filename and allowed_file(pic_file.filename):
            pic_filename = secure_filename(pic_file.filename)
            pic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_filename))
            user.profile_picture = pic_filename
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('farmer.edit_profile'))
    # Redirect to farmer dashboard for now since farmer_edit_profile.html doesn't exist
    flash(f'Editing profile for: {user.name}', 'info')
    return redirect(url_for('farmer.farmer_dashboard'))

# Farmer: Change Password
@farmer_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
@farmer_required
def change_password():
    """GET: Render farmer password change form. POST: Change password after validation."""
    user = current_user
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not check_password_hash(user.password_hash, old_password):
            flash('Old password is incorrect.', 'error')
            return redirect(url_for('farmer.change_password'))
        if not new_password or new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('farmer.change_password'))
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('farmer.change_password'))
    # Redirect to farmer dashboard for now since farmer_change_password.html doesn't exist
    flash('Password change functionality will be available soon.', 'info')
    return redirect(url_for('farmer.farmer_dashboard'))

# Farmer: Toggle Product Status
@farmer_bp.route('/toggle_product_status/<int:product_id>', methods=['POST'])
@login_required
@farmer_required
def toggle_product_status(product_id):
    product = Product.query.get_or_404(product_id)
    if product.farmer_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    # Optionally, only allow marking as in stock if quantity > 0
    if not product.in_stock and product.available_quantity <= 0:
        flash('Cannot mark as in stock: quantity is zero.', 'error')
        return redirect(url_for('farmer.farmer_dashboard'))
    product.in_stock = not product.in_stock
    db.session.commit()
    flash(f'Product marked as {"in stock" if product.in_stock else "out of stock"}!', 'success')
    return redirect(url_for('farmer.farmer_dashboard'))

# Customer: Edit Profile
@customer_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@customer_required
def customer_edit_profile():
    """GET: Render customer profile edit form. POST: Update customer profile fields."""
    user = current_user
    if request.method == 'POST':
        user.name = request.form.get('name', user.name)
        user.email = request.form.get('email', user.email)
        user.phone = request.form.get('phone', user.phone)
        user.address = request.form.get('address', user.address)
        user.delivery_address = request.form.get('delivery_address', user.delivery_address)
        user.pin_code = request.form.get('pin_code', user.pin_code)
        # Profile picture
        pic_file = request.files.get('profile_picture')
        if pic_file and pic_file.filename and allowed_file(pic_file.filename):
            pic_filename = secure_filename(pic_file.filename)
            pic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_filename))
            user.profile_picture = pic_filename
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('customer.customer_edit_profile'))
    # Redirect to customer dashboard for now since customer_edit_profile.html doesn't exist
    flash(f'Editing profile for: {user.name}', 'info')
    return redirect(url_for('customer.customer_dashboard'))

# Customer: Edit Address
@customer_bp.route('/edit_address', methods=['GET', 'POST'])
@login_required
@customer_required
def customer_edit_address():
    user = current_user
    if request.method == 'POST':
        address = request.form.get('address', user.address)
        delivery_address = request.form.get('delivery_address', user.delivery_address)
        pin_code = request.form.get('pin_code', user.pin_code)
        if not address or not delivery_address or not pin_code or not pin_code.isdigit():
            flash('Invalid address or pin code.', 'error')
            return redirect(url_for('customer.customer_edit_address'))
        user.address = address
        user.delivery_address = delivery_address
        user.pin_code = pin_code
        db.session.commit()
        flash('Address updated!', 'success')
        return redirect(url_for('customer.customer_edit_address'))
    # Redirect to customer dashboard for now since customer_edit_address.html doesn't exist
    flash(f'Editing address for: {user.name}', 'info')
    return redirect(url_for('customer.customer_dashboard'))

# Customer: Add Review/Rating (disabled - no rating system)
@customer_bp.route('/review/<int:product_id>', methods=['GET', 'POST'])
@login_required
@customer_required
def add_review(product_id):
    """Review system disabled."""
    product = Product.query.get_or_404(product_id)
    flash('Review system is currently disabled.', 'info')
    return redirect(url_for('customer.customer_dashboard'))

# Admin: Analytics/Reports
@admin_bp.route('/reports', methods=['GET'])
@login_required
@admin_required
def admin_reports():
    """Render admin reports page with daily sales and product stock trends as JSON for charting."""
    # Daily sales
    sales = db.session.query(
        db.func.date(Order.order_date),
        db.func.sum(Order.total_amount)
    ).group_by(db.func.date(Order.order_date)).all()
    sales_data = [
        {'date': str(date), 'total_sales': float(total)} for date, total in sales
    ]
    # Product stock trends (current stock per product)
    stock_trends = db.session.query(
        Product.name, Product.available_quantity
    ).all()
    stock_data = [
        {'product': name, 'stock': qty} for name, qty in stock_trends
    ]
    # Redirect to admin dashboard for now since admin_reports.html doesn't exist
    flash('Reports functionality will be available soon.', 'info')
    return redirect(url_for('admin.admin_dashboard'))

# Admin: Review Moderation
@admin_bp.route('/reviews', methods=['GET', 'POST', 'DELETE'])
@login_required
@admin_required
def admin_reviews():
    """Review system disabled."""
    flash('Review system is currently disabled.', 'info')
    return redirect(url_for('admin.admin_dashboard'))

# =============================================================================
# RESTful API ENDPOINTS
# =============================================================================

# =============================================================================
# FARMER API ENDPOINTS
# =============================================================================

@app.route('/api/farmer/dashboard', methods=['GET'])
@login_required
@farmer_required
def api_farmer_dashboard():
    products = Product.query.filter_by(farmer_id=current_user.id).all()
    orders = Order.query.filter_by(farmer_id=current_user.id).all()
    total_products = len(products)
    total_orders = len(orders)
    total_revenue = sum([o.total_amount for o in orders])
    return jsonify({
        'products': [
            {
                'id': p.id,
                'name': p.name,
                'price': p.price_per_kg,
                'quantity': p.available_quantity,
                'category': p.category,
                'date': p.created_at.strftime('%Y-%m-%d'),
                'image': get_product_image(p.name, p.image_filename),
            } for p in products
        ],
        'orders': [
            {
                'id': o.id,
                'total_amount': o.total_amount,
                'status': o.status,
                'order_date': o.order_date.strftime('%Y-%m-%d'),
            } for o in orders
        ],
        'total_products': total_products,
        'total_orders': total_orders,
        'total_revenue': total_revenue
    })

@app.route('/api/farmer/products', methods=['GET', 'POST'])
@login_required
@farmer_required
def api_farmer_products():
    """
    GET: List all products for the current farmer.
    POST: Add a new product for the current farmer. Form data: name, description, price, quantity, category, image (file)
    Returns JSON list or success.
    """
    if request.method == 'GET':
        products = Product.query.filter_by(farmer_id=current_user.id).all()
        return jsonify([
            {
                'id': p.id,
                'name': p.name,
                'description': p.description,
                'price': p.price_per_kg,
                'quantity': p.available_quantity,
                'category': p.category,
                'date': p.created_at.strftime('%Y-%m-%d'),
                'image': get_product_image(p.name, p.image_filename),
            } for p in products
        ])
    # POST: Add product
    data = request.form
    name = data.get('name')
    description = data.get('description')
    price = float(data.get('price', 0))
    # Add 3% admin commission to the farmer's price
    final_price = add_admin_commission(price)
    quantity = float(data.get('quantity', 0))
    category = data.get('category')
    image_file = request.files.get('image')
    image_filename = None
    if image_file and image_file.filename and allowed_file(image_file.filename):
        image_filename = secure_filename(image_file.filename)
        image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    product = Product(
        name=name,
        description=description,
        price_per_kg=final_price,
        available_quantity=quantity,
        category=category,
        image_filename=image_filename,
        farmer_id=current_user.id
    )
    db.session.add(product)
    db.session.commit()
    return jsonify({'success': True, 'id': product.id})

@app.route('/api/farmer/products/<int:product_id>', methods=['GET', 'POST'])
@login_required
@farmer_required
def api_farmer_edit_product(product_id):
    product = Product.query.filter_by(id=product_id, farmer_id=current_user.id).first_or_404()
    if request.method == 'GET':
        return jsonify({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price_per_kg,
            'quantity': product.available_quantity,
            'category': product.category,
            'date': product.created_at.strftime('%Y-%m-%d'),
            'image': get_product_image(product.name, product.image_filename),
        })
    # POST: Edit product
    data = request.form
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    # Add 3% admin commission to the farmer's price
    if 'price' in data and data['price']:
        product.price_per_kg = add_admin_commission(float(data['price']))
    product.available_quantity = float(data.get('quantity', product.available_quantity))
    product.category = data.get('category', product.category)
    image_file = request.files.get('image')
    if image_file and image_file.filename and allowed_file(image_file.filename):
        image_filename = secure_filename(image_file.filename)
        image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        product.image_filename = image_filename
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/farmer/orders', methods=['GET'])
@login_required
@farmer_required
def api_farmer_orders():
    orders = Order.query.filter_by(farmer_id=current_user.id).all()
    return jsonify([
        {
            'id': o.id,
            'customer': o.customer.name if o.customer else '',
            'total_amount': o.total_amount,
            'status': o.status,
            'order_date': o.order_date.strftime('%Y-%m-%d'),
            'delivery_date': o.delivery_date.strftime('%Y-%m-%d') if o.delivery_date else '',
            'delivery_stage': 'In Transit' if o.status == 'packed' else 'Pending',
            'items': [
                {
                    'product': item.product.name,
                    'quantity': item.quantity,
                    'price': item.price_per_kg
                } for item in o.items
            ]
        } for o in orders
    ])

@app.route('/api/farmer/profile', methods=['GET', 'POST'])
@login_required
@farmer_required
def api_farmer_profile():
    if request.method == 'GET':
        user = current_user
        return jsonify({
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address,
            'farm_name': user.farm_name,
            'farm_description': user.farm_description,
            'certifications': user.certifications,
            'id_verification': url_for('static', filename='uploads/' + user.id_verification) if user.id_verification else '',
            'profile_picture': url_for('static', filename='uploads/' + user.profile_picture) if user.profile_picture else ''
        })
    # POST: Update profile
    data = request.form
    user = current_user
    user.name = data.get('name', user.name)
    user.phone = data.get('phone', user.phone)
    user.address = data.get('address', user.address)
    user.farm_name = data.get('farm_name', user.farm_name)
    user.farm_description = data.get('farm_description', user.farm_description)
    user.certifications = data.get('certifications', user.certifications)
    id_file = request.files.get('id_verification')
    if id_file and id_file.filename and allowed_file(id_file.filename):
        id_filename = secure_filename(id_file.filename)
        id_file.save(os.path.join(app.config['UPLOAD_FOLDER'], id_filename))
        user.id_verification = id_filename
    # Profile picture
    pic_file = request.files.get('profile_picture')
    if pic_file and pic_file.filename and allowed_file(pic_file.filename):
        pic_filename = secure_filename(pic_file.filename)
        pic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_filename))
        user.profile_picture = pic_filename
    db.session.commit()
    return jsonify({'success': True})

# =============================================================================
# CUSTOMER API ENDPOINTS
# =============================================================================
@app.route('/api/customer/dashboard', methods=['GET'])
@login_required
@customer_required
def api_customer_dashboard():
    orders = Order.query.filter_by(customer_id=current_user.id).order_by(Order.order_date.desc()).all()
    total_orders = len(orders)
    total_spent = sum([o.total_amount for o in orders])
    return jsonify({
        'orders': [
            {
                'id': o.id,
                'total_amount': o.total_amount,
                'status': o.status,
                'order_date': o.order_date.strftime('%Y-%m-%d'),
                'delivery_date': o.delivery_date.strftime('%Y-%m-%d') if o.delivery_date else '',
                'delivery_stage': 'In Transit' if o.status == 'packed' else 'Pending',
                'items': [
                    {
                        'product': item.product.name,
                        'quantity': item.quantity,
                        'price': item.price_per_kg
                    } for item in o.items
                ]
            } for o in orders
        ],
        'total_orders': total_orders,
        'total_spent': total_spent
    })

@app.route('/api/cart', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@customer_required
def api_cart():
    """
    GET: Return current cart items for the logged-in customer.
    POST: Add a product to cart. JSON: {product_id, quantity}
    PUT: Update quantity for a product in cart. JSON: {product_id, quantity}
    DELETE: Remove a product from cart. JSON: {product_id}
    Returns JSON success or error.
    """
    if 'cart' not in session:
        session['cart'] = {}
    cart = session['cart']
    if request.method == 'GET':
        items = []
        for product_id, quantity in cart.items():
            product = Product.query.get(int(product_id))
            if product:
                items.append({
                    'id': product.id,
                    'name': product.name,
                    'price': product.price_per_kg,
                    'quantity': quantity,
                    'image': get_product_image(product.name, product.image_filename)
                })
        return jsonify(items)
    data = request.get_json() or {}
    if request.method == 'POST':
        product_id = str(data.get('product_id'))
        quantity = float(data.get('quantity', 1))
        cart[product_id] = cart.get(product_id, 0) + quantity
        session['cart'] = cart
        return jsonify({'success': True})
    if request.method == 'PUT':
        product_id = str(data.get('product_id'))
        quantity = float(data.get('quantity', 1))
        if quantity <= 0:
            cart.pop(product_id, None)
        else:
            cart[product_id] = quantity
        session['cart'] = cart
        return jsonify({'success': True})
    if request.method == 'DELETE':
        product_id = str(data.get('product_id'))
        cart.pop(product_id, None)
        session['cart'] = cart
        return jsonify({'success': True})

@app.route('/api/checkout', methods=['POST'])
@login_required
@customer_required
def api_checkout():
    """
    POST: Place an order for all items in the current cart for the logged-in customer.
    Form data: delivery_address, payment_method, delivery_date (optional)
    Returns JSON success or error.
    """
    cart = session.get('cart', {})
    if not cart:
        return jsonify({'success': False, 'error': 'Cart is empty'}), 400
    data = request.form
    delivery_address = data.get('delivery_address', current_user.delivery_address)
    payment_method = data.get('payment_method', 'COD')
    delivery_date_str = data.get('delivery_date')
    delivery_date = None
    if delivery_date_str:
        try:
            delivery_date = datetime.strptime(delivery_date_str, '%Y-%m-%d')
        except Exception:
            delivery_date = None
    # Group items by farmer
    farmer_orders = {}
    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            farmer_id = product.farmer_id
            if farmer_id not in farmer_orders:
                farmer_orders[farmer_id] = []
            farmer_orders[farmer_id].append({
                'product': product,
                'quantity': quantity
            })
    # Create orders for each farmer
    for farmer_id, items in farmer_orders.items():
        total_amount = sum([item['product'].price_per_kg * item['quantity'] for item in items])
        order = Order(
            customer_id=current_user.id,
            farmer_id=farmer_id,
            total_amount=total_amount,
            delivery_address=delivery_address,
            payment_method=payment_method,
            status='pending',
            delivery_date=delivery_date
        )
        db.session.add(order)
        db.session.flush()  # Get order.id
        for item in items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item['product'].id,
                quantity=item['quantity'],
                price_per_kg=item['product'].price_per_kg
            )
            db.session.add(order_item)
    db.session.commit()
    session['cart'] = {}
    return jsonify({'success': True})

@app.route('/api/customer/orders', methods=['GET'])
@login_required
@customer_required
def api_customer_orders():
    orders = Order.query.filter_by(customer_id=current_user.id).order_by(Order.order_date.desc()).all()
    
    orders_data = []
    for order in orders:
        order_data = {
            'id': f'ORD{order.id:03d}',
            'date': order.order_date.strftime('%Y-%m-%d'),
            'total': f'₹{order.total_amount}',
            'status': order.status.title(),
            'items': [f'{item.product.name} {item.quantity}kg' for item in order.items]
        }
        orders_data.append(order_data)
    
    return jsonify(orders_data)

@app.route('/api/customer/profile', methods=['GET', 'POST'])
@login_required
@customer_required
def api_customer_profile():
    if request.method == 'GET':
        user = current_user
        return jsonify({
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address,
            'delivery_address': user.delivery_address,
            'pin_code': user.pin_code,
            'profile_picture': url_for('static', filename='uploads/' + user.profile_picture) if user.profile_picture else ''
        })
    # POST: Update profile
    data = request.form
    user = current_user
    user.name = data.get('name', user.name)
    user.phone = data.get('phone', user.phone)
    user.address = data.get('address', user.address)
    user.delivery_address = data.get('delivery_address', user.delivery_address)
    user.pin_code = data.get('pin_code', user.pin_code)
    # Profile picture
    pic_file = request.files.get('profile_picture')
    if pic_file and pic_file.filename and allowed_file(pic_file.filename):
        pic_filename = secure_filename(pic_file.filename)
        pic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_filename))
        user.profile_picture = pic_filename
    db.session.commit()
    return jsonify({'success': True})

    

# =============================================================================
# DEVELOPMENT & TESTING ROUTES
# =============================================================================
@app.route('/dev_create_users')
def dev_create_users():
    # Admin
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@farm2home.com',
            password_hash=generate_password_hash('admin123'),
            name='Admin User',
            role='admin',
            is_active=True
        )
        db.session.add(admin)
    else:
        admin.email = 'admin@farm2home.com'
        admin.password_hash = generate_password_hash('admin123')
        admin.is_active = True
    # Farmer
    farmer = User.query.filter_by(username='farmer1').first()
    if not farmer:
        farmer = User(
            username='farmer1',
            email='farmer1@farm2home.com',
            password_hash=generate_password_hash('farmerpass'),
            name='Farmer One',
            role='farmer',
            is_active=True
        )
        db.session.add(farmer)
    else:
        farmer.email = 'farmer1@farm2home.com'
        farmer.password_hash = generate_password_hash('farmerpass')
        farmer.is_active = True
    # Customer
    customer = User.query.filter_by(username='customer1').first()
    if not customer:
        customer = User(
            username='customer1',
            email='customer1@farm2home.com',
            password_hash=generate_password_hash('customerpass'),
            name='Customer One',
            role='customer',
            is_active=True
        )
        db.session.add(customer)
    else:
        customer.email = 'customer1@farm2home.com'
        customer.password_hash = generate_password_hash('customerpass')
        customer.is_active = True
    db.session.commit()
    return {
        'admin': {'username': 'admin', 'password': 'admin123', 'email': 'admin@farm2home.com'},
        'farmer': {'username': 'farmer1', 'password': 'farmerpass', 'email': 'farmer1@farm2home.com'},
        'customer': {'username': 'customer1', 'password': 'customerpass', 'email': 'customer1@farm2home.com'}
    }

@app.route('/dev_reset_products')
def dev_reset_products():
    """Clear all existing products and add fresh sample data"""
    from datetime import datetime, timedelta
    
    # Clear all existing products
    Product.query.delete()
    db.session.commit()
    
    # Get or create farmers
    farmer1 = User.query.filter_by(username='farmer1').first()
    if not farmer1:
        farmer1 = User(
            username='farmer1',
            email='farmer1@farm2home.com',
            password_hash=generate_password_hash('farmerpass'),
            name='John Smith',
            role='farmer',
            farm_name='Green Valley Farm',
            address='123 Farm Road, Rural Area',
            is_active=True
        )
        db.session.add(farmer1)
        db.session.commit()
    
    farmer2 = User.query.filter_by(username='farmer2').first()
    if not farmer2:
        farmer2 = User(
            username='farmer2',
            email='farmer2@farm2home.com',
            password_hash=generate_password_hash('farmerpass'),
            name='Maria Garcia',
            role='farmer',
            farm_name='Sunshine Organic Farm',
            address='456 Organic Lane, Countryside',
            is_active=True
        )
        db.session.add(farmer2)
        db.session.commit()
    
    # Sample product data
    products_data = [
        # Vegetables
        {
            'name': 'Fresh Tomatoes',
            'description': 'Ripe, juicy tomatoes grown without pesticides. Perfect for salads and cooking.',
            'price_per_kg': 2.50,
            'available_quantity': 50.0,
            'category': 'Vegetables',
            'is_organic': True,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now() - timedelta(days=2),
            'expiry_date': datetime.now() + timedelta(days=7),
            'image_filename': 'fresh_tomatoes.jpg'
        },
        {
            'name': 'Organic Carrots',
            'description': 'Sweet, crunchy organic carrots rich in vitamins and minerals.',
            'price_per_kg': 1.80,
            'available_quantity': 75.0,
            'category': 'Vegetables',
            'is_organic': True,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now() - timedelta(days=1),
            'expiry_date': datetime.now() + timedelta(days=14),
            'image_filename': 'organic_carrots.jpg'
        },
        {
            'name': 'Fresh Spinach',
            'description': 'Nutrient-rich spinach leaves, perfect for salads and smoothies.',
            'price_per_kg': 3.20,
            'available_quantity': 30.0,
            'category': 'Vegetables',
            'is_organic': False,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=5)
        },
        {
            'name': 'Bell Peppers',
            'description': 'Colorful bell peppers - red, yellow, and green varieties available.',
            'price_per_kg': 4.00,
            'available_quantity': 40.0,
            'category': 'Vegetables',
            'is_organic': True,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now() - timedelta(days=3),
            'expiry_date': datetime.now() + timedelta(days=10)
        },
        {
            'name': 'Fresh Onions',
            'description': 'Large, fresh onions perfect for cooking and salads.',
            'price_per_kg': 1.50,
            'available_quantity': 100.0,
            'category': 'Vegetables',
            'is_organic': False,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now() - timedelta(days=5),
            'expiry_date': datetime.now() + timedelta(days=21)
        },
        
        # Fruits
        {
            'name': 'Sweet Apples',
            'description': 'Crisp, sweet apples perfect for eating fresh or making pies.',
            'price_per_kg': 3.50,
            'available_quantity': 60.0,
            'category': 'Fruits',
            'is_organic': True,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now() - timedelta(days=1),
            'expiry_date': datetime.now() + timedelta(days=14),
            'image_filename': 'sweet_apples.jpg'
        },
        {
            'name': 'Fresh Bananas',
            'description': 'Ripe, yellow bananas rich in potassium and natural sweetness.',
            'price_per_kg': 2.00,
            'available_quantity': 80.0,
            'category': 'Fruits',
            'is_organic': False,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=7)
        },
        {
            'name': 'Organic Strawberries',
            'description': 'Sweet, juicy organic strawberries perfect for desserts.',
            'price_per_kg': 6.50,
            'available_quantity': 25.0,
            'category': 'Fruits',
            'is_organic': True,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=5)
        },
        {
            'name': 'Fresh Oranges',
            'description': 'Juicy oranges rich in vitamin C, perfect for juicing or eating.',
            'price_per_kg': 2.80,
            'available_quantity': 70.0,
            'category': 'Fruits',
            'is_organic': False,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now() - timedelta(days=2),
            'expiry_date': datetime.now() + timedelta(days=12)
        },
        
        # Dairy & Eggs
        {
            'name': 'Fresh Eggs',
            'description': 'Farm-fresh eggs from free-range chickens, sold by dozen.',
            'price_per_kg': 4.50,
            'available_quantity': 20.0,
            'category': 'Dairy & Eggs',
            'is_organic': True,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=21)
        },
        {
            'name': 'Organic Milk',
            'description': 'Fresh organic milk from grass-fed cows, pasteurized and safe.',
            'price_per_kg': 3.80,
            'available_quantity': 40.0,
            'category': 'Dairy & Eggs',
            'is_organic': True,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=7)
        },
        
        # Grains & Pulses
        {
            'name': 'Brown Rice',
            'description': 'Organic brown rice rich in fiber and nutrients.',
            'price_per_kg': 2.20,
            'available_quantity': 150.0,
            'category': 'Grains & Pulses',
            'is_organic': True,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now() - timedelta(days=30),
            'expiry_date': datetime.now() + timedelta(days=180)
        },
        {
            'name': 'Lentils',
            'description': 'High-protein lentils perfect for soups and stews.',
            'price_per_kg': 1.90,
            'available_quantity': 100.0,
            'category': 'Grains & Pulses',
            'is_organic': False,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now() - timedelta(days=45),
            'expiry_date': datetime.now() + timedelta(days=365)
        },
        
        # Herbs & Spices
        {
            'name': 'Fresh Basil',
            'description': 'Aromatic fresh basil perfect for Italian dishes and pesto.',
            'price_per_kg': 8.00,
            'available_quantity': 15.0,
            'category': 'Herbs & Spices',
            'is_organic': True,
            'farmer_id': farmer1.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=7)
        },
        {
            'name': 'Fresh Mint',
            'description': 'Refreshing mint leaves perfect for teas and garnishes.',
            'price_per_kg': 6.50,
            'available_quantity': 20.0,
            'category': 'Herbs & Spices',
            'is_organic': True,
            'farmer_id': farmer2.id,
            'harvest_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=5)
        }
    ]
    
    # Add products to database
    for product_data in products_data:
        product = Product(**product_data)
        db.session.add(product)
    
    db.session.commit()
    
    # Create sample orders for demonstration
    customer1 = User.query.filter_by(username='customer1').first()
    if not customer1:
        customer1 = User(
            username='customer1',
            email='customer1@farm2home.com',
            password_hash=generate_password_hash('customerpass'),
            name='Alice Johnson',
            role='customer',
            address='789 City Street, Urban Area',
            delivery_address='789 City Street, Urban Area, 12345',
            is_active=True
        )
        db.session.add(customer1)
        db.session.commit()
    
    # Get some products for sample orders
    tomatoes = Product.query.filter_by(name='Fresh Tomatoes').first()
    carrots = Product.query.filter_by(name='Organic Carrots').first()
    apples = Product.query.filter_by(name='Sweet Apples').first()
    
    # Create sample orders
    sample_orders = [
        {
            'customer_id': customer1.id,
            'farmer_id': farmer1.id,
            'total_amount': 12.50,
            'delivery_address': '789 City Street, Urban Area, 12345',
            'payment_method': 'COD',
            'status': 'pending',
            'items': [
                {'product': tomatoes, 'quantity': 2.0, 'price_per_kg': 2.50},
                {'product': apples, 'quantity': 2.0, 'price_per_kg': 3.50}
            ]
        },
        {
            'customer_id': customer1.id,
            'farmer_id': farmer2.id,
            'total_amount': 8.30,
            'delivery_address': '789 City Street, Urban Area, 12345',
            'payment_method': 'UPI',
            'status': 'accepted',
            'items': [
                {'product': carrots, 'quantity': 3.0, 'price_per_kg': 1.80}
            ]
        }
    ]
    
    for order_data in sample_orders:
        items = order_data.pop('items')
        order = Order(**order_data)
        db.session.add(order)
        db.session.flush()  # Get the order ID
        
        for item_data in items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item_data['product'].id,
                quantity=item_data['quantity'],
                price_per_kg=item_data['price_per_kg']
            )
            db.session.add(order_item)
    
    db.session.commit()
    
    return {
        'message': 'Products and sample orders reset successfully!',
        'products_added': len(products_data),
        'orders_added': len(sample_orders),
        'categories': ['Vegetables', 'Fruits', 'Dairy & Eggs', 'Grains & Pulses', 'Herbs & Spices'],
        'farmers': [
            {'name': farmer1.name, 'farm': farmer1.farm_name},
            {'name': farmer2.name, 'farm': farmer2.farm_name}
        ]
    }

# =============================================================================
# BLUEPRINT REGISTRATION & APP INITIALIZATION
# =============================================================================
# Register blueprints (must be after all blueprints and their routes are defined)
app.register_blueprint(admin_bp)
app.register_blueprint(customer_bp)
app.register_blueprint(farmer_bp)

# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================
def create_tables():
    """Create database tables if they don't exist."""
    try:
        with app.app_context():
            db.create_all()
    except Exception as e:
        print(f"Database initialization error: {e}")

# Add a simple health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Farm2Home API is running',
        'timestamp': datetime.now().isoformat()
    })

# Initialize database tables
create_tables()

if __name__ == "__main__":
    app.run(debug=True)