from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask import send_from_directory
import sqlite3
import os
import random
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import re
import hashlib
from datetime import datetime, timedelta
import time
import threading

# Initialize Flask
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DB_PATH = os.path.join(os.path.dirname(__file__), 'contacts.db')

# Database lock for thread safety
db_lock = threading.Lock()

# Admin password (better: use env var in production)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "arihantadmin")
ADMIN_SETUP_KEY = os.environ.get("ADMIN_SETUP_KEY", "shree_nakoda_arihant_2025")
SESSION_TIMEOUT_MINUTES = 30
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 15


# ---------------- DB Initialization ----------------
def migrate_existing_products():
    """Migrate existing file-based products to database for admin management"""
    try:
        # Check if products already exist in database
        existing_count = execute_db_query('SELECT COUNT(*) as count FROM products', fetch_one=True)
        if existing_count and existing_count['count'] > 0:
            return existing_count['count']  # Return existing count
        
        img_dir = os.path.join(app.root_path, 'static', 'img', 'Arihant')
        if not os.path.exists(img_dir):
            return 0
        
        # Granite descriptions and categories
        granite_descriptions = {
            'Astoria Ivory Pink': 'Elegant pink granite with ivory veining, perfect for modern kitchens and bathrooms.',
            'Canyon Gold': 'Rich golden granite with natural patterns, ideal for luxury interiors.',
            'Colonial Gold': 'Classic gold granite with timeless appeal for traditional and contemporary spaces.',
            'Colonial White': 'Pure white granite with subtle veining, perfect for minimalist designs.',
            'Crystal Gold': 'Crystal-infused gold granite with sparkling finish for premium projects.',
            'Imperial Gold': 'Royal gold granite with imperial patterns, perfect for grand entrances.',
            'Kashmir Gold': 'Exotic Kashmir gold granite with unique veining patterns.',
            'Millenium Ivory Gold': 'Millennium collection ivory gold granite with sophisticated patterns.',
            'Shiva Gold': 'Divine gold granite with spiritual elegance for sacred spaces.',
            'Shiva Ivory Pink': 'Sacred pink granite with ivory accents, perfect for temples and homes.',
            'Vegas Gold': 'Vibrant gold granite with Vegas-style glamour for luxury projects.',
            'Olivia Green': 'Rich green granite with natural patterns for elegant interiors.',
            'Royal Pink': 'Royal pink granite with luxurious appeal for premium spaces.',
            'Millenium': 'Classic millennium granite with timeless beauty.',
            'Mani White': 'Pure white granite with subtle patterns for modern designs.',
            'Ghibli Ivory': 'Soft ivory granite with gentle patterns for elegant spaces.',
            'Flamingo Pink': 'Vibrant pink granite with bold patterns for statement designs.',
            'Colombo Jubarna': 'Exotic granite with unique patterns and rich colors.',
            'Classic Ivory': 'Timeless ivory granite with classic appeal.',
            'Bhama Ivory Pink': 'Beautiful pink granite with ivory undertones.',
            'Astoria Ivory': 'Elegant ivory granite with sophisticated patterns.',
            'Astoria': 'Premium granite with exceptional quality and beauty.'
        }
        
        granite_categories = {
            'Astoria Ivory Pink': 'Pink Collection',
            'Canyon Gold': 'Gold Collection',
            'Colonial Gold': 'Gold Collection',
            'Colonial White': 'White Collection',
            'Crystal Gold': 'Gold Collection',
            'Imperial Gold': 'Gold Collection',
            'Kashmir Gold': 'Gold Collection',
            'Millenium Ivory Gold': 'Gold Collection',
            'Shiva Gold': 'Gold Collection',
            'Shiva Ivory Pink': 'Pink Collection',
            'Vegas Gold': 'Gold Collection',
            'Olivia Green': 'Premium Series & Others',
            'Royal Pink': 'Pink Collection',
            'Millenium': 'White Collection',
            'Mani White': 'White Collection',
            'Ghibli Ivory': 'White Collection',
            'Flamingo Pink': 'Pink Collection',
            'Colombo Jubarna': 'Premium Series & Others',
            'Classic Ivory': 'Premium Series & Others',
            'Bhama Ivory Pink': 'Pink Collection',
            'Astoria Ivory': 'White Collection',
            'Astoria': 'Premium Series & Others'
        }
        
        migrated_count = 0
        all_files = [f for f in os.listdir(img_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png', '.webp'))]
        
        for filename in all_files:
            base_name = os.path.splitext(filename)[0]
            clean_name = base_name.replace('_', ' ').replace('-', ' ').title()
            
            # Get description and category
            description = granite_descriptions.get(clean_name, f'Premium {clean_name} granite from Arihant\'s exclusive collection.')
            category = granite_categories.get(clean_name, 'Beige & Creme Collection')
            
            # Random but realistic values for demonstration
            availability = random.choice(['In Stock', 'In Stock', 'In Stock', 'Limited Stock'])
            thickness = random.choice(['2cm', '3cm', '2-3cm'])
            finish = random.choice(['Polished', 'Polished', 'Polished', 'Honed', 'Leathered'])
            price = round(random.uniform(150, 450), 2)
            
            # Insert into database
            execute_db_query('''INSERT INTO products (name, category, description, image_url, availability, thickness, finish, price_per_sqft) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                         (clean_name, category, description, f'/static/img/Arihant/{filename}', 
                          availability, thickness, finish, price), commit=True)
            migrated_count += 1
        
        return migrated_count
        
    except Exception as e:
        print(f"Error migrating products: {e}")
        return 0


def init_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            project_type TEXT,
            message TEXT NOT NULL,
            urgent TEXT DEFAULT 'normal',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Add new columns if they don't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE contacts ADD COLUMN phone TEXT')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE contacts ADD COLUMN project_type TEXT')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE contacts ADD COLUMN urgent TEXT DEFAULT "normal"')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE contacts ADD COLUMN contact_id TEXT')
        except:
            pass  # Column might already exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            image_url TEXT,
            availability TEXT DEFAULT 'In Stock',
            thickness TEXT,
            finish TEXT DEFAULT 'Polished',
            price_per_sqft REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Add products table columns if they don't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN name TEXT NOT NULL')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN category TEXT NOT NULL')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN description TEXT')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN image_url TEXT')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN availability TEXT DEFAULT "In Stock"')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN thickness TEXT')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN finish TEXT DEFAULT "Polished"')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN price_per_sqft REAL')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        except:
            pass  # Column might already exist
        try:
            cursor.execute('ALTER TABLE products ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        except:
            pass  # Column might already exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            stars INTEGER NOT NULL,
            message TEXT NOT NULL,
            show_on_home BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Add show_on_home column if it doesn't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE reviews ADD COLUMN show_on_home BOOLEAN DEFAULT 0')
        except:
            pass  # Column might already exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id TEXT,
            session_token TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admins (admin_id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            success BOOLEAN,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )''')
        
        conn.commit()
    finally:
        conn.close()
    
    # Migrate existing products to database
    try:
        migrated_count = migrate_existing_products()
        if migrated_count > 0:
            print(f"Successfully migrated {migrated_count} products to database")
    except Exception as e:
        print(f"Product migration failed: {e}")


# ---------------- Database Helper Functions ----------------
def get_db_connection():
    """Get a database connection with proper error handling"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30.0)  # 30 second timeout
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode for better concurrency
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            return conn
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                continue
            else:
                raise e

def execute_db_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """Execute database query with proper locking and error handling"""
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            if commit:
                conn.commit()
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                return cursor.lastrowid
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
def validate_password_strength(password):
    """Validate password strength requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password meets requirements"

def generate_admin_id():
    """Generate unique admin ID"""
    while True:
        admin_id = f"ADM{datetime.now().year}{random.randint(1000, 9999)}"
        result = execute_db_query('SELECT admin_id FROM admins WHERE admin_id = ?', (admin_id,), fetch_one=True)
        if not result:
            return admin_id

def log_security_event(admin_id, action, ip_address, user_agent, success, details=""):
    """Log security events"""
    try:
        execute_db_query('''INSERT INTO security_logs (admin_id, action, ip_address, user_agent, success, details) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (admin_id, action, ip_address, user_agent, success, details), commit=True)
    except Exception as e:
        # Log error but don't fail the main operation
        print(f"Error logging security event: {e}")

def is_account_locked(admin_id):
    """Check if admin account is locked"""
    result = execute_db_query('SELECT locked_until FROM admins WHERE admin_id = ?', (admin_id,), fetch_one=True)
    if result and result['locked_until']:
        locked_until = datetime.fromisoformat(result['locked_until'])
        return datetime.now() < locked_until
    return False

def update_login_attempts(admin_id, success):
    """Update login attempts and handle lockouts"""
    if success:
        execute_db_query('UPDATE admins SET login_attempts = 0, locked_until = NULL, last_login = ? WHERE admin_id = ?',
                     (datetime.now().isoformat(), admin_id), commit=True)
    else:
        execute_db_query('UPDATE admins SET login_attempts = login_attempts + 1 WHERE admin_id = ?', (admin_id,), commit=True)
        result = execute_db_query('SELECT login_attempts FROM admins WHERE admin_id = ?', (admin_id,), fetch_one=True)
        attempts = result['login_attempts'] if result else 0
        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            execute_db_query('UPDATE admins SET locked_until = ? WHERE admin_id = ?', (locked_until.isoformat(), admin_id), commit=True)

def cleanup_expired_sessions():
    """Clean up expired admin sessions"""
    try:
        execute_db_query('DELETE FROM admin_sessions WHERE expires_at < ?', (datetime.now().isoformat(),), commit=True)
    except Exception as e:
        print(f"Error cleaning up sessions: {e}")

# ---------------- Authentication Functions ----------------
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session or 'session_token' not in session:
            flash('Admin login required.', 'error')
            return redirect(url_for('admin_login'))
        
        # Validate session
        result = execute_db_query('''SELECT admin_id FROM admin_sessions 
                     WHERE session_token = ? AND expires_at > ? AND admin_id = ?''',
                     (session['session_token'], datetime.now().isoformat(), session['admin_id']), fetch_one=True)
        if not result:
            session.clear()
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


# ---------------- Routes ----------------
@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload():
    message = ''
    if request.method == 'POST':
        password = request.form.get('password')
        file = request.files.get('file')

        if password != ADMIN_PASSWORD:
            message = '❌ Incorrect admin password.'
        elif not file or file.filename == '':
            message = '⚠️ No file selected.'
        else:
            fname = secure_filename(file.filename)
            save_dir = os.path.join(app.root_path, 'static', 'img', 'Arihant')
            os.makedirs(save_dir, exist_ok=True)
            file.save(os.path.join(save_dir, fname))
            message = f'✅ File {fname} uploaded successfully!'

    return render_template('admin_upload.html', message=message)


@app.route('/why-choose-us')
def why_choose_us():
    return render_template('why_choose_us.html')


@app.route('/')
def home():
    img_dir = os.path.join(app.root_path, 'static', 'img', 'Arihant')
    all_imgs = [f for f in os.listdir(img_dir) if f.lower().endswith(('.jpg', '.jpeg', '.png', '.webp'))] if os.path.exists(img_dir) else []
    featured_imgs = random.sample(all_imgs, min(6, len(all_imgs))) if all_imgs else []

    # Enhanced product descriptions based on granite names
    granite_descriptions = {
        'Astoria Ivory Pink': 'Elegant pink granite with ivory veining, perfect for modern kitchens and bathrooms.',
        'Canyon Gold': 'Rich golden granite with natural patterns, ideal for luxury interiors.',
        'Colonial Gold': 'Classic gold granite with timeless appeal for traditional and contemporary spaces.',
        'Colonial White': 'Pure white granite with subtle veining, perfect for minimalist designs.',
        'Crystal Gold': 'Crystal-infused gold granite with sparkling finish for premium projects.',
        'Imperial Gold': 'Royal gold granite with imperial patterns, perfect for grand entrances.',
        'Kashmir Gold': 'Exotic Kashmir gold granite with unique veining patterns.',
        'Millenium Ivory Gold': 'Millennium collection ivory gold granite with sophisticated patterns.',
        'Shiva Gold': 'Divine gold granite with spiritual elegance for sacred spaces.',
        'Shiva Ivory Pink': 'Sacred pink granite with ivory accents, perfect for temples and homes.',
        'Vegas Gold': 'Vibrant gold granite with Vegas-style glamour for luxury projects.'
    }

    featured = []
    for fname in featured_imgs:
        base_name = os.path.splitext(fname)[0]
        clean_name = base_name.replace('_', ' ').replace('-', ' ').title()
        description = granite_descriptions.get(clean_name, f'Premium {clean_name} granite from Arihant\'s exclusive collection.')
        
        featured.append({
            'title': clean_name,
            'image': f'/static/img/Arihant/{fname}',
            'category': 'Biege & Creme Collection',
            'description': description,
           
        })

    # Dynamic testimonials with more variety
    testimonials = [
        {"text": "The quality and finish of Arihant's granite is unmatched. Our home looks stunning!", "author": "Priya S., Chennai", "rating": 5},
        {"text": "Professional service and beautiful granite. Highly recommended for any project.", "author": "Ramesh K., Bangalore", "rating": 5},
        {"text": "Arihant Granites team helped us choose the perfect stone for our hotel lobby.", "author": "Hotel Grand, Madurai", "rating": 5},
        {"text": "Excellent quality and timely delivery. The Kashmir Gold looks amazing in our living room!", "author": "Anita M., Delhi", "rating": 5},
        {"text": "Great variety and competitive prices. Very satisfied with our purchase.", "author": "Rajesh P., Mumbai", "rating": 4},
        {"text": "The Imperial Gold granite transformed our office reception area completely.", "author": "Corporate Client, Hyderabad", "rating": 5}
    ]
    
    # Get recent reviews for homepage
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT name, stars, message FROM reviews WHERE show_on_home = 1 ORDER BY created_at DESC LIMIT 3')
        recent_reviews = c.fetchall()
    
    return render_template('home.html', featured=featured, testimonials=testimonials, recent_reviews=recent_reviews)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/explore')
def explore():
    # Get products from database with admin management
    products = execute_db_query('SELECT * FROM products ORDER BY name', fetch_all=True)
    
    # Convert to listings format for template compatibility
    listings = []
    for product in products:
        listings.append({
            'title': product['name'],
            'image': product['image_url'],
            'category': product['category'],
            'description': product['description'],
            'availability': product['availability'],
            'thickness': product['thickness'] or '2cm',
            'finish': product['finish']
        })
    
    return render_template('explore.html', listings=listings)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone', '')  # New field
        project_type = request.form.get('project_type', '')  # New field
        message = request.form['message']
        urgent = 'yes' if request.form.get('urgent') == 'yes' else 'normal'  # New field
        
        # Generate contact_id
        contact_id = f"C{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"
        
        execute_db_query('INSERT INTO contacts (name, email, phone, project_type, message, urgent, contact_id) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                     (name, email, phone, project_type, message, urgent, contact_id), commit=True)
        flash('✅ Thank you for contacting us! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')


@app.route('/admin/reviews-management')
@admin_required
def admin_reviews_management():
    # Get all reviews with their featured status
    reviews = execute_db_query('SELECT id, name, email, phone, stars, message, show_on_home, created_at FROM reviews ORDER BY created_at DESC', fetch_all=True)
    
    # Calculate statistics
    total_reviews = len(reviews) if reviews else 0
    featured_reviews = len([r for r in reviews if r['show_on_home']]) if reviews else 0
    
    return render_template('admin_reviews_management.html', reviews=reviews, 
                         total_reviews=total_reviews, featured_reviews=featured_reviews)


@app.route('/admin/toggle-review-feature', methods=['POST'])
@admin_required
def toggle_review_feature():
    data = request.get_json()
    review_id = data.get('review_id')
    featured = data.get('featured', False)
    
    execute_db_query('UPDATE reviews SET show_on_home = ? WHERE id = ?', 
                    (1 if featured else 0, review_id), commit=True)
    
    return jsonify({'success': True})


@app.route('/admin/bulk-feature-reviews', methods=['POST'])
@admin_required
def bulk_feature_reviews():
    data = request.get_json()
    review_ids = data.get('review_ids', [])
    
    if not review_ids:
        return jsonify({'success': False, 'error': 'No reviews selected'})
    
    placeholders = ','.join(['?' for _ in review_ids])
    execute_db_query(f'UPDATE reviews SET show_on_home = 1 WHERE id IN ({placeholders})', 
                    review_ids, commit=True)
    
    return jsonify({'success': True})


@app.route('/admin/bulk-unfeature-reviews', methods=['POST'])
@admin_required
def bulk_unfeature_reviews():
    data = request.get_json()
    review_ids = data.get('review_ids', [])
    
    if not review_ids:
        return jsonify({'success': False, 'error': 'No reviews selected'})
    
    placeholders = ','.join(['?' for _ in review_ids])
    execute_db_query(f'UPDATE reviews SET show_on_home = 0 WHERE id IN ({placeholders})', 
                    review_ids, commit=True)
    
    return jsonify({'success': True})


@app.route('/admin/bulk-delete-reviews', methods=['POST'])
@admin_required
def bulk_delete_reviews():
    data = request.get_json()
    review_ids = data.get('review_ids', [])
    
    if not review_ids:
        return jsonify({'success': False, 'error': 'No reviews selected'})
    
    placeholders = ','.join(['?' for _ in review_ids])
    execute_db_query(f'DELETE FROM reviews WHERE id IN ({placeholders})', 
                    review_ids, commit=True)
    
    return jsonify({'success': True})


@app.route('/admin/review-details/<int:review_id>')
@admin_required
def review_details(review_id):
    review = execute_db_query('SELECT * FROM reviews WHERE id = ?', (review_id,), fetch_one=True)
    
    if review:
        return jsonify({'success': True, 'review': dict(review)})
    else:
        return jsonify({'success': False, 'error': 'Review not found'})


@app.route('/admin/delete-review/<int:review_id>', methods=['POST'])
@admin_required
def delete_review(review_id):
    execute_db_query('DELETE FROM reviews WHERE id = ?', (review_id,), commit=True)
    return jsonify({'success': True})


@app.route('/admin/delete-contact/<int:contact_id>', methods=['POST'])
@admin_required
def delete_contact(contact_id):
    execute_db_query('DELETE FROM contacts WHERE id = ?', (contact_id,), commit=True)
    return jsonify({'success': True})


@app.route('/admin/bulk-delete-contacts', methods=['POST'])
@admin_required
def bulk_delete_contacts():
    data = request.get_json()
    contact_ids = data.get('contact_ids', [])
    
    if not contact_ids:
        return jsonify({'success': False, 'error': 'No contacts selected'})
    
    placeholders = ','.join(['?' for _ in contact_ids])
    execute_db_query(f'DELETE FROM contacts WHERE id IN ({placeholders})', 
                    contact_ids, commit=True)
    
    return jsonify({'success': True})


@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        stars = int(request.form['stars'])
        message = request.form['message']
        execute_db_query('INSERT INTO reviews (name, email, phone, stars, message) VALUES (?, ?, ?, ?, ?)',
                     (name, email, phone, stars, message), commit=True)
        flash('✅ Thank you for your review!')
        return redirect(url_for('reviews'))

    reviews = execute_db_query('SELECT name, stars, message, created_at FROM reviews ORDER BY created_at DESC LIMIT 20', fetch_all=True)

    return render_template('reviews.html', reviews=reviews)


@app.route('/admin/products-management')
@admin_required
def admin_products_management():
    # Get all products
    products = execute_db_query('SELECT * FROM products ORDER BY created_at DESC', fetch_all=True)
    
    # Calculate statistics
    total_products = len(products) if products else 0
    in_stock_products = len([p for p in products if p['availability'] == 'In Stock']) if products else 0
    out_of_stock_products = len([p for p in products if p['availability'] == 'Out of Stock']) if products else 0
    
    return render_template('admin_products_management.html', products=products, 
                         total_products=total_products, in_stock_products=in_stock_products, 
                         out_of_stock_products=out_of_stock_products)


@app.route('/admin/add-product', methods=['POST'])
@admin_required
def add_product():
    # Handle file upload
    if 'product_image' not in request.files:
        return jsonify({'success': False, 'error': 'No image file provided'})
    
    file = request.files['product_image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No image file selected'})
    
    # Validate file
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type. Allowed: JPG, PNG, JPEG, WebP'})
    
    # Get form data
    name = request.form.get('name', '').strip()
    category = request.form.get('category', '').strip()
    description = request.form.get('description', '').strip()
    availability = request.form.get('availability', '').strip()
    thickness = request.form.get('thickness', '').strip()
    finish = request.form.get('finish', '').strip()
    price_per_sqft = request.form.get('price_per_sqft', '').strip()
    
    # Validate required fields
    if not name or not category or not availability or not finish:
        return jsonify({'success': False, 'error': 'Name, category, availability, and finish are required'})
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        # Add timestamp to avoid filename conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name_prefix = name.lower().replace(' ', '_').replace('-', '_')
        filename = f"{name_prefix}_{timestamp}_{filename}"
        
        save_dir = os.path.join(app.root_path, 'static', 'img', 'Arihant')
        os.makedirs(save_dir, exist_ok=True)
        file_path = os.path.join(save_dir, filename)
        file.save(file_path)
        
        # Create image URL
        image_url = f'/static/img/Arihant/{filename}'
        
        # Insert product into database
        execute_db_query('''INSERT INTO products (name, category, description, image_url, availability, thickness, finish, price_per_sqft, updated_at) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (name, category, description, image_url, availability, thickness, finish, 
                      price_per_sqft, datetime.now().isoformat()), commit=True)
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def allowed_file(filename):
    """Check if file has allowed extension"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/admin/delete-product/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    try:
        execute_db_query('DELETE FROM products WHERE id = ?', (product_id,), commit=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/admin/get-product/<int:product_id>')
@admin_required
def get_product(product_id):
    try:
        product = execute_db_query('SELECT * FROM products WHERE id = ?', (product_id,), fetch_one=True)
        
        if product:
            return jsonify({'success': True, 'product': dict(product)})
        else:
            return jsonify({'success': False, 'error': 'Product not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/admin/update-product/<int:product_id>', methods=['POST'])
@admin_required
def update_product(product_id):
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'category', 'availability', 'finish']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'{field} is required'})
    
    try:
        execute_db_query('''UPDATE products SET name = ?, category = ?, description = ?, image_url = ?, 
                         availability = ?, thickness = ?, finish = ?, price_per_sqft = ?, updated_at = ? 
                         WHERE id = ?''',
                     (data['name'], data['category'], data.get('description', ''), data.get('image_url', ''), 
                      data['availability'], data.get('thickness', ''), data['finish'], 
                      data.get('price_per_sqft'), datetime.now().isoformat(), product_id), commit=True)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/admin/contacts-management')
@admin_required
def admin_contacts_management():
    # Get all contacts with full details
    contacts = execute_db_query('SELECT * FROM contacts ORDER BY created_at DESC', fetch_all=True)
    
    # Calculate statistics
    total_contacts = len(contacts) if contacts else 0
    urgent_contacts = len([c for c in contacts if c['urgent'] == 'yes']) if contacts else 0
    today_contacts = len([c for c in contacts if c['created_at'][:10] == datetime.now().strftime('%Y-%m-%d')]) if contacts else 0
    
    return render_template('admin_contacts_management.html', contacts=contacts, 
                         total_contacts=total_contacts, urgent_contacts=urgent_contacts, 
                         today_contacts=today_contacts)


@app.route('/admin/contact-details/<int:contact_id>')
@admin_required
def contact_details(contact_id):
    contact = execute_db_query('SELECT * FROM contacts WHERE id = ?', (contact_id,), fetch_one=True)
    
    if contact:
        return jsonify({'success': True, 'contact': dict(contact)})
    else:
        return jsonify({'success': False, 'error': 'Contact not found'})


@app.route('/admin/contacts')
@admin_required
def admin_contacts():
    contacts = execute_db_query('SELECT id, name, email, message, created_at FROM contacts ORDER BY created_at DESC', fetch_all=True)
    return render_template('admin_contacts.html', contacts=contacts)


# ---------------- Admin Authentication Routes ----------------
@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    """Initial admin setup route"""
    # Check if any admin exists
    result = execute_db_query('SELECT COUNT(*) as count FROM admins', fetch_one=True)
    admin_count = result['count'] if result else 0
    
    if admin_count > 0:
        flash('Admin account already exists. Please login.', 'info')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        setup_key = request.form.get('setup_key')
        
        if setup_key != ADMIN_SETUP_KEY:
            log_security_event('SYSTEM', 'SETUP_ATTEMPT', request.remote_addr, request.headers.get('User-Agent'), False, 'Invalid setup key')
            flash('❌ Invalid setup key.', 'error')
            return render_template('admin_setup.html')
        
        return redirect(url_for('admin_register'))
    
    return render_template('admin_setup.html')


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    """Admin registration route"""
    # Check if any admin exists
    result = execute_db_query('SELECT COUNT(*) as count FROM admins', fetch_one=True)
    admin_count = result['count'] if result else 0
    
    if admin_count > 0:
        flash('Admin account already exists. Please login.', 'info')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name']
        phone = request.form.get('phone', '')
        
        # Validate inputs
        if not username or not email or not password or not full_name:
            flash('❌ All required fields must be filled.', 'error')
            return render_template('admin_register.html')
        
        if password != confirm_password:
            flash('❌ Passwords do not match.', 'error')
            return render_template('admin_register.html')
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            flash(f'❌ {message}', 'error')
            return render_template('admin_register.html')
        
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('❌ Invalid email format.', 'error')
            return render_template('admin_register.html')
        
        # Validate username (alphanumeric only)
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('❌ Username must be 3-20 characters and contain only letters, numbers, and underscores.', 'error')
            return render_template('admin_register.html')
        
        # Generate admin ID and hash password
        admin_id = generate_admin_id()
        password_hash = generate_password_hash(password)
        
        try:
            execute_db_query('''INSERT INTO admins (admin_id, username, email, password_hash, full_name, phone) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                         (admin_id, username, email, password_hash, full_name, phone), commit=True)
            
            log_security_event(admin_id, 'ADMIN_REGISTER', request.remote_addr, request.headers.get('User-Agent'), True)
            flash('✅ Admin account created successfully! Please login.', 'success')
            return redirect(url_for('admin_login'))
            
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                flash('❌ Username already exists.', 'error')
            elif 'email' in str(e):
                flash('❌ Email already exists.', 'error')
            else:
                flash('❌ Registration failed. Please try again.', 'error')
    
    return render_template('admin_register.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Enhanced admin login with security features"""
    # Clean up expired sessions
    cleanup_expired_sessions()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('❌ Username and password are required.', 'error')
            return render_template('admin_login.html')
        
        admin = execute_db_query('''SELECT admin_id, username, email, password_hash, full_name, 
                    is_active, login_attempts, locked_until 
                    FROM admins WHERE username = ? OR email = ?''', 
                 (username, username), fetch_one=True)
        
        if not admin:
            log_security_event('UNKNOWN', 'LOGIN_ATTEMPT', request.remote_addr, request.headers.get('User-Agent'), False, f'Username: {username}')
            flash('❌ Invalid username or password.', 'error')
            return render_template('admin_login.html')
        
        admin_id = admin['admin_id']
        db_username = admin['username']
        db_email = admin['email']
        password_hash = admin['password_hash']
        full_name = admin['full_name']
        is_active = admin['is_active']
        login_attempts = admin['login_attempts']
        locked_until = admin['locked_until']
        
        # Check if account is active
        if not is_active:
            log_security_event(admin_id, 'LOGIN_ATTEMPT', request.remote_addr, request.headers.get('User-Agent'), False, 'Account inactive')
            flash('❌ Account is deactivated. Contact support.', 'error')
            return render_template('admin_login.html')
        
        # Check if account is locked
        if is_account_locked(admin_id):
            log_security_event(admin_id, 'LOGIN_ATTEMPT', request.remote_addr, request.headers.get('User-Agent'), False, 'Account locked')
            flash(f'❌ Account locked. Try again after {LOCKOUT_DURATION_MINUTES} minutes.', 'error')
            return render_template('admin_login.html')
        
        # Verify password
        if check_password_hash(password_hash, password):
            # Successful login
            update_login_attempts(admin_id, True)
            
            # Create session
            session_token = secrets.token_hex(32)
            expires_at = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
            
            execute_db_query('''INSERT INTO admin_sessions (admin_id, session_token, ip_address, user_agent, expires_at) 
                         VALUES (?, ?, ?, ?, ?)''',
                         (admin_id, session_token, request.remote_addr, request.headers.get('User-Agent'), expires_at.isoformat()), commit=True)
            
            # Update session
            session['admin_id'] = admin_id
            session['username'] = db_username
            session['full_name'] = full_name
            session['session_token'] = session_token
            
            log_security_event(admin_id, 'LOGIN_SUCCESS', request.remote_addr, request.headers.get('User-Agent'), True)
            flash('✅ Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            # Failed login
            update_login_attempts(admin_id, False)
            log_security_event(admin_id, 'LOGIN_ATTEMPT', request.remote_addr, request.headers.get('User-Agent'), False, 'Invalid password')
            flash('❌ Invalid username or password.', 'error')
    
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    """Enhanced admin logout"""
    if 'admin_id' in session and 'session_token' in session:
        # Remove session from database
        execute_db_query('DELETE FROM admin_sessions WHERE session_token = ? AND admin_id = ?', 
                     (session['session_token'], session['admin_id']), commit=True)
        
        log_security_event(session['admin_id'], 'LOGOUT', request.remote_addr, request.headers.get('User-Agent'), True)
    
    session.clear()
    flash('✅ You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get admin info
    admin_info = execute_db_query('''SELECT admin_id, username, full_name, email, last_login, created_at 
                 FROM admins WHERE admin_id = ?''', (session['admin_id'],), fetch_one=True)
    
    # Get statistics
    contacts_result = execute_db_query('SELECT COUNT(*) as count FROM contacts', fetch_one=True)
    total_contacts = contacts_result['count'] if contacts_result else 0
    
    reviews_result = execute_db_query('SELECT COUNT(*) as count FROM reviews', fetch_one=True)
    total_reviews = reviews_result['count'] if reviews_result else 0
    
    rating_result = execute_db_query('SELECT AVG(stars) as avg FROM reviews', fetch_one=True)
    avg_rating = rating_result['avg'] if rating_result and rating_result['avg'] else 0
    
    # Get recent activity
    recent_contacts = execute_db_query('''SELECT name, email, phone, project_type, message, urgent, created_at, contact_id 
                                     FROM contacts ORDER BY created_at DESC LIMIT 5''', fetch_all=True)
    
    recent_reviews = execute_db_query('SELECT name, stars, message, created_at FROM reviews ORDER BY created_at DESC LIMIT 5', fetch_all=True)
    
    # Get recent security logs
    security_logs = execute_db_query('''SELECT action, success, timestamp, ip_address, details 
                 FROM security_logs WHERE admin_id = ? 
                 ORDER BY timestamp DESC LIMIT 5''', (session['admin_id'],), fetch_all=True)
    
    stats = {
        'total_contacts': total_contacts,
        'total_reviews': total_reviews,
        'avg_rating': round(avg_rating, 1)
    }
    return render_template('admin_dashboard.html', admin_info=admin_info, stats=stats, 
                         recent_contacts=recent_contacts, recent_reviews=recent_reviews, security_logs=security_logs)


@app.route('/admin/update-profile', methods=['POST'])
@admin_required
def update_profile():
    setup_key = request.form.get('setup_key')
    username = request.form.get('username', '').strip()
    full_name = request.form.get('full_name', '').strip()
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    
    # Verify admin setup key
    if setup_key != ADMIN_SETUP_KEY:
        log_security_event(session['admin_id'], 'PROFILE_UPDATE_FAILED', request.remote_addr, request.headers.get('User-Agent'), False, 'Invalid setup key')
        flash('❌ Invalid admin setup key. Profile update denied.', 'error')
        return redirect(url_for('admin_profile'))
    
    # Validate inputs
    if not username or not full_name or not email:
        flash('❌ Username, full name, and email are required.', 'error')
        return redirect(url_for('admin_profile'))
    
    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        flash('❌ Invalid email format.', 'error')
        return redirect(url_for('admin_profile'))
    
    # Validate username (alphanumeric only)
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        flash('❌ Username must be 3-20 characters and contain only letters, numbers, and underscores.', 'error')
        return redirect(url_for('admin_profile'))
    
    try:
        # Check if username or email already exists (excluding current admin)
        admin_id = session['admin_id']
        existing_admin = execute_db_query('''SELECT admin_id FROM admins 
                                         WHERE (username = ? OR email = ?) AND admin_id != ?''', 
                                      (username, email, admin_id), fetch_one=True)
        
        if existing_admin:
            flash('❌ Username or email already exists.', 'error')
            return redirect(url_for('admin_profile'))
        
        # Update admin profile
        execute_db_query('''UPDATE admins SET username = ?, full_name = ?, email = ?, phone = ? 
                         WHERE admin_id = ?''',
                     (username, full_name, email, phone, admin_id), commit=True)
        
        # Update session with new username
        session['username'] = username
        session['full_name'] = full_name
        
        log_security_event(admin_id, 'PROFILE_UPDATE_SUCCESS', request.remote_addr, request.headers.get('User-Agent'), True, f'Updated profile: {username}')
        flash('✅ Profile updated successfully!', 'success')
        
    except sqlite3.IntegrityError as e:
        flash('❌ Update failed. Please try again.', 'error')
    except Exception as e:
        flash('❌ An error occurred. Please try again.', 'error')
    
    return redirect(url_for('admin_profile'))


@app.route('/admin/profile')
@admin_required
def admin_profile():
    # Get admin info
    admin_info = execute_db_query('''SELECT admin_id, username, email, full_name, phone, created_at, last_login 
                                 FROM admins WHERE admin_id = ?''', (session['admin_id'],), fetch_one=True)
    
    # Calculate login statistics (last 30 days)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_logins = execute_db_query('''SELECT COUNT(*) as count FROM security_logs 
                                       WHERE admin_id = ? AND action = 'LOGIN_SUCCESS' 
                                       AND timestamp > ?''', 
                                    (session['admin_id'], thirty_days_ago.isoformat()), fetch_one=True)
    
    failed_attempts = execute_db_query('''SELECT COUNT(*) as count FROM security_logs 
                                         WHERE admin_id = ? AND action = 'LOGIN_ATTEMPT' 
                                         AND timestamp > ?''', 
                                      (session['admin_id'], thirty_days_ago.isoformat()), fetch_one=True)
    
    return render_template('admin_profile.html', admin_info=admin_info, 
                         recent_logins=recent_logins['count'] if recent_logins else 0,
                         failed_attempts=failed_attempts['count'] if failed_attempts else 0)


@app.route('/admin/change-password', methods=['GET', 'POST'])
@admin_required
def admin_change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            flash('❌ All fields are required.', 'error')
            return redirect(url_for('admin_change_password'))
        
        if new_password != confirm_password:
            flash('❌ New passwords do not match.', 'error')
            return redirect(url_for('admin_change_password'))
        
        # Validate new password strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            flash(f'❌ {message}', 'error')
            return redirect(url_for('admin_change_password'))
        
        # Verify current password
        result = execute_db_query('SELECT password_hash FROM admins WHERE admin_id = ?', (session['admin_id'],), fetch_one=True)
        
        if result and check_password_hash(result['password_hash'], current_password):
            # Update password
            new_password_hash = generate_password_hash(new_password)
            execute_db_query('UPDATE admins SET password_hash = ? WHERE admin_id = ?', 
                         (new_password_hash, session['admin_id']), commit=True)
            
            log_security_event(session['admin_id'], 'PASSWORD_CHANGE', request.remote_addr, 
                            request.headers.get('User-Agent'), True)
            flash('✅ Password changed successfully!', 'success')
            return redirect(url_for('admin_profile'))
        else:
            log_security_event(session['admin_id'], 'PASSWORD_CHANGE_ATTEMPT', request.remote_addr, 
                            request.headers.get('User-Agent'), False, 'Invalid current password')
            flash('❌ Current password is incorrect.', 'error')
    
    return render_template('admin_change_password.html')


# ---------------- Run App ----------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
