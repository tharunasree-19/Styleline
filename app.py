from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import uuid
from functools import wraps
import json
from decimal import Decimal
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'stylelane_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'StyleLaneUsers')
PRODUCTS_TABLE_NAME = os.environ.get('PRODUCTS_TABLE_NAME', 'StyleLaneProducts')
INVENTORY_TABLE_NAME = os.environ.get('INVENTORY_TABLE_NAME', 'StyleLaneInventory')
SALES_TABLE_NAME = os.environ.get('SALES_TABLE_NAME', 'StyleLaneSales')
STORES_TABLE_NAME = os.environ.get('STORES_TABLE_NAME', 'StyleLaneStores')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# Low stock threshold
LOW_STOCK_THRESHOLD = int(os.environ.get('LOW_STOCK_THRESHOLD', 10))

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
products_table = dynamodb.Table(PRODUCTS_TABLE_NAME)
inventory_table = dynamodb.Table(INVENTORY_TABLE_NAME)
sales_table = dynamodb.Table(SALES_TABLE_NAME)
stores_table = dynamodb.Table(STORES_TABLE_NAME)

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def decimal_default(obj):
    """JSON encoder for DynamoDB Decimal types"""
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_role' not in session or session['user_role'] != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def send_sns_notification(message, subject="StyleLane Notification"):
    """Send SNS notification"""
    if ENABLE_SNS and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=subject,
                Message=message
            )
        except Exception as e:
            app.logger.error(f"SNS notification failed: {str(e)}")

def check_low_inventory():
    """Check for low inventory and send notifications"""
    try:
        response = inventory_table.scan()
        low_stock_items = []
        
        for item in response['Items']:
            if item['stock_quantity'] <= LOW_STOCK_THRESHOLD:
                low_stock_items.append({
                    'product_id': item['product_id'],
                    'store_id': item['store_id'],
                    'stock_quantity': item['stock_quantity']
                })
        
        if low_stock_items:
            message = f"Low inventory alert! {len(low_stock_items)} items are below threshold."
            send_sns_notification(message, "Low Inventory Alert")
            
        return low_stock_items
    except Exception as e:
        app.logger.error(f"Error checking low inventory: {str(e)}")
        return []

# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/')
def home():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            response = users_table.get_item(Key={'email': email})
            
            if 'Item' in response:
                user = response['Item']
                # In production, use proper password hashing
                if user['password'] == password:
                    session['user_id'] = user['user_id']
                    session['user_email'] = user['email']
                    session['user_role'] = user['role']
                    session['user_name'] = user['name']
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password!', 'error')
            else:
                flash('User not found!', 'error')
                
        except Exception as e:
            flash(f'Login error: {str(e)}', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'staff')
        store_id = request.form.get('store_id', '')
        
        try:
            # Check if user already exists
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                flash('User already exists!', 'error')
                return render_template('register.html')
            
            # Create new user
            user_id = str(uuid.uuid4())
            users_table.put_item(Item={
                'user_id': user_id,
                'email': email,
                'name': name,
                'password': password,  # In production, hash this
                'role': role,
                'store_id': store_id,
                'created_at': datetime.now().isoformat(),
                'is_active': True
            })
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

# ---------------------------------------
# Dashboard Routes
# ---------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    try:
        # Get summary statistics
        total_products = products_table.scan()['Count']
        
        # Get low stock items
        low_stock_items = check_low_inventory()
        
        # Get recent sales (last 7 days)
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        recent_sales = sales_table.scan(
            FilterExpression='sale_date >= :date',
            ExpressionAttributeValues={':date': week_ago}
        )['Items']
        
        total_revenue = sum(Decimal(str(sale.get('total_amount', 0))) for sale in recent_sales)
        
        stats = {
            'total_products': total_products,
            'low_stock_count': len(low_stock_items),
            'recent_sales_count': len(recent_sales),
            'weekly_revenue': float(total_revenue)
        }
        
        return render_template('dashboard.html', stats=stats, low_stock_items=low_stock_items[:5])
        
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('dashboard.html', stats={}, low_stock_items=[])

# ---------------------------------------
# Product Management Routes
# ---------------------------------------
@app.route('/products')
@login_required
def products():
    """List all products"""
    try:
        response = products_table.scan()
        products_list = response['Items']
        return render_template('products.html', products=products_list)
    except Exception as e:
        flash(f'Error loading products: {str(e)}', 'error')
        return render_template('products.html', products=[])

@app.route('/products/add', methods=['GET', 'POST'])
@login_required
def add_product():
    """Add new product"""
    if request.method == 'POST':
        try:
            product_id = str(uuid.uuid4())
            product_data = {
                'product_id': product_id,
                'name': request.form['name'],
                'category': request.form['category'],
                'brand': request.form['brand'],
                'size': request.form['size'],
                'color': request.form['color'],
                'price': Decimal(str(request.form['price'])),
                'cost': Decimal(str(request.form['cost'])),
                'description': request.form.get('description', ''),
                'sku': request.form['sku'],
                'created_at': datetime.now().isoformat(),
                'created_by': session['user_id'],
                'is_active': True
            }
            
            products_table.put_item(Item=product_data)
            flash('Product added successfully!', 'success')
            return redirect(url_for('products'))
            
        except Exception as e:
            flash(f'Error adding product: {str(e)}', 'error')
    
    return render_template('add_product.html')

@app.route('/products/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    """Edit existing product"""
    try:
        response = products_table.get_item(Key={'product_id': product_id})
        
        if 'Item' not in response:
            flash('Product not found!', 'error')
            return redirect(url_for('products'))
        
        product = response['Item']
        
        if request.method == 'POST':
            update_data = {
                'name': request.form['name'],
                'category': request.form['category'],
                'brand': request.form['brand'],
                'size': request.form['size'],
                'color': request.form['color'],
                'price': Decimal(str(request.form['price'])),
                'cost': Decimal(str(request.form['cost'])),
                'description': request.form.get('description', ''),
                'sku': request.form['sku'],
                'updated_at': datetime.now().isoformat(),
                'updated_by': session['user_id']
            }
            
            products_table.update_item(
                Key={'product_id': product_id},
                UpdateExpression='SET #n = :name, category = :category, brand = :brand, #s = :size, color = :color, price = :price, cost = :cost, description = :description, sku = :sku, updated_at = :updated_at, updated_by = :updated_by',
                ExpressionAttributeNames={
                    '#n': 'name',
                    '#s': 'size'
                },
                ExpressionAttributeValues={
                    ':name': update_data['name'],
                    ':category': update_data['category'],
                    ':brand': update_data['brand'],
                    ':size': update_data['size'],
                    ':color': update_data['color'],
                    ':price': update_data['price'],
                    ':cost': update_data['cost'],
                    ':description': update_data['description'],
                    ':sku': update_data['sku'],
                    ':updated_at': update_data['updated_at'],
                    ':updated_by': update_data['updated_by']
                }
            )
            
            flash('Product updated successfully!', 'success')
            return redirect(url_for('products'))
        
        return render_template('edit_product.html', product=product)
        
    except Exception as e:
        flash(f'Error editing product: {str(e)}', 'error')
        return redirect(url_for('products'))

# ---------------------------------------
# Inventory Management Routes
# ---------------------------------------
@app.route('/inventory')
@login_required
def inventory():
    """List inventory for all stores"""
    try:
        response = inventory_table.scan()
        inventory_items = response['Items']
        
        # Enrich with product details
        for item in inventory_items:
            try:
                product_response = products_table.get_item(Key={'product_id': item['product_id']})
                if 'Item' in product_response:
                    item['product_name'] = product_response['Item']['name']
                    item['product_sku'] = product_response['Item']['sku']
            except:
                item['product_name'] = 'Unknown'
                item['product_sku'] = 'N/A'
        
        return render_template('inventory.html', inventory=inventory_items)
        
    except Exception as e:
        flash(f'Error loading inventory: {str(e)}', 'error')
        return render_template('inventory.html', inventory=[])

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    """Add inventory for a product"""
    if request.method == 'POST':
        try:
            product_id = request.form['product_id']
            store_id = request.form['store_id']
            quantity = int(request.form['quantity'])
            
            # Check if inventory record exists
            inventory_id = f"{product_id}#{store_id}"
            response = inventory_table.get_item(Key={'inventory_id': inventory_id})
            
            if 'Item' in response:
                # Update existing inventory
                current_quantity = response['Item']['stock_quantity']
                new_quantity = current_quantity + quantity
                
                inventory_table.update_item(
                    Key={'inventory_id': inventory_id},
                    UpdateExpression='SET stock_quantity = :quantity, last_updated = :updated, updated_by = :user',
                    ExpressionAttributeValues={
                        ':quantity': new_quantity,
                        ':updated': datetime.now().isoformat(),
                        ':user': session['user_id']
                    }
                )
            else:
                # Create new inventory record
                inventory_table.put_item(Item={
                    'inventory_id': inventory_id,
                    'product_id': product_id,
                    'store_id': store_id,
                    'stock_quantity': quantity,
                    'reserved_quantity': 0,
                    'last_updated': datetime.now().isoformat(),
                    'created_by': session['user_id'],
                    'updated_by': session['user_id']
                })
            
            flash('Inventory updated successfully!', 'success')
            return redirect(url_for('inventory'))
            
        except Exception as e:
            flash(f'Error updating inventory: {str(e)}', 'error')
    
    # Get products for dropdown
    try:
        products_response = products_table.scan()
        products_list = products_response['Items']
        
        stores_response = stores_table.scan()
        stores_list = stores_response['Items']
        
        return render_template('add_inventory.html', products=products_list, stores=stores_list)
    except Exception as e:
        flash(f'Error loading form data: {str(e)}', 'error')
        return render_template('add_inventory.html', products=[], stores=[])

# ---------------------------------------
# Sales Management Routes
# ---------------------------------------
@app.route('/sales')
@login_required
def sales():
    """List all sales"""
    try:
        response = sales_table.scan()
        sales_list = response['Items']
        
        # Sort by sale date (newest first)
        sales_list.sort(key=lambda x: x.get('sale_date', ''), reverse=True)
        
        return render_template('sales.html', sales=sales_list)
        
    except Exception as e:
        flash(f'Error loading sales: {str(e)}', 'error')
        return render_template('sales.html', sales=[])

@app.route('/sales/add', methods=['GET', 'POST'])
@login_required
def add_sale():
    """Record a new sale"""
    if request.method == 'POST':
        try:
            sale_id = str(uuid.uuid4())
            product_id = request.form['product_id']
            store_id = request.form['store_id']
            quantity = int(request.form['quantity'])
            unit_price = Decimal(str(request.form['unit_price']))
            total_amount = quantity * unit_price
            
            # Check inventory availability
            inventory_id = f"{product_id}#{store_id}"
            inventory_response = inventory_table.get_item(Key={'inventory_id': inventory_id})
            
            if 'Item' not in inventory_response:
                flash('No inventory found for this product in this store!', 'error')
                return redirect(url_for('add_sale'))
            
            current_stock = inventory_response['Item']['stock_quantity']
            if current_stock < quantity:
                flash(f'Insufficient stock! Available: {current_stock}', 'error')
                return redirect(url_for('add_sale'))
            
            # Record sale
            sales_table.put_item(Item={
                'sale_id': sale_id,
                'product_id': product_id,
                'store_id': store_id,
                'quantity': quantity,
                'unit_price': unit_price,
                'total_amount': total_amount,
                'sale_date': datetime.now().isoformat(),
                'sold_by': session['user_id'],
                'customer_name': request.form.get('customer_name', ''),
                'customer_email': request.form.get('customer_email', '')
            })
            
            # Update inventory
            new_stock = current_stock - quantity
            inventory_table.update_item(
                Key={'inventory_id': inventory_id},
                UpdateExpression='SET stock_quantity = :quantity, last_updated = :updated',
                ExpressionAttributeValues={
                    ':quantity': new_stock,
                    ':updated': datetime.now().isoformat()
                }
            )
            
            # Check if stock is low and send notification
            if new_stock <= LOW_STOCK_THRESHOLD:
                message = f"Low stock alert for product {product_id} at store {store_id}. Current stock: {new_stock}"
                send_sns_notification(message, "Low Stock Alert")
            
            flash('Sale recorded successfully!', 'success')
            return redirect(url_for('sales'))
            
        except Exception as e:
            flash(f'Error recording sale: {str(e)}', 'error')
    
    # Get products and stores for dropdown
    try:
        products_response = products_table.scan()
        products_list = products_response['Items']
        
        stores_response = stores_table.scan()
        stores_list = stores_response['Items']
        
        return render_template('add_sale.html', products=products_list, stores=stores_list)
    except Exception as e:
        flash(f'Error loading form data: {str(e)}', 'error')
        return render_template('add_sale.html', products=[], stores=[])

# ---------------------------------------
# Store Management Routes
# ---------------------------------------
@app.route('/stores')
@login_required
def stores():
    """List all stores"""
    try:
        response = stores_table.scan()
        stores_list = response['Items']
        return render_template('stores.html', stores=stores_list)
    except Exception as e:
        flash(f'Error loading stores: {str(e)}', 'error')
        return render_template('stores.html', stores=[])

@app.route('/stores/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_store():
    """Add new store"""
    if request.method == 'POST':
        try:
            store_id = str(uuid.uuid4())
            store_data = {
                'store_id': store_id,
                'name': request.form['name'],
                'address': request.form['address'],
                'city': request.form['city'],
                'state': request.form['state'],
                'zip_code': request.form['zip_code'],
                'phone': request.form['phone'],
                'email': request.form['email'],
                'manager_name': request.form['manager_name'],
                'created_at': datetime.now().isoformat(),
                'created_by': session['user_id'],
                'is_active': True
            }
            
            stores_table.put_item(Item=store_data)
            flash('Store added successfully!', 'success')
            return redirect(url_for('stores'))
            
        except Exception as e:
            flash(f'Error adding store: {str(e)}', 'error')
    
    return render_template('add_store.html')

# ---------------------------------------
# Reporting Routes
# ---------------------------------------
@app.route('/reports')
@login_required
def reports():
    """Reports dashboard"""
    return render_template('reports.html')

@app.route('/reports/inventory')
@login_required
def inventory_report():
    """Inventory report"""
    try:
        # Get all inventory with product details
        inventory_response = inventory_table.scan()
        inventory_items = inventory_response['Items']
        
        report_data = []
        total_value = Decimal('0')
        
        for item in inventory_items:
            try:
                product_response = products_table.get_item(Key={'product_id': item['product_id']})
                if 'Item' in product_response:
                    product = product_response['Item']
                    item_value = item['stock_quantity'] * product.get('cost', Decimal('0'))
                    total_value += item_value
                    
                    report_data.append({
                        'product_name': product['name'],
                        'sku': product['sku'],
                        'category': product['category'],
                        'store_id': item['store_id'],
                        'stock_quantity': item['stock_quantity'],
                        'cost': float(product.get('cost', 0)),
                        'total_value': float(item_value)
                    })
            except Exception as e:
                app.logger.error(f"Error processing inventory item: {str(e)}")
                continue
        
        return render_template('inventory_report.html', 
                             report_data=report_data, 
                             total_value=float(total_value))
        
    except Exception as e:
        flash(f'Error generating inventory report: {str(e)}', 'error')
        return render_template('inventory_report.html', report_data=[], total_value=0)

@app.route('/reports/sales')
@login_required
def sales_report():
    """Sales report"""
    try:
        # Get sales for last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        response = sales_table.scan(
            FilterExpression='sale_date >= :date',
            ExpressionAttributeValues={':date': thirty_days_ago}
        )
        
        sales_data = response['Items']
        total_revenue = sum(Decimal(str(sale.get('total_amount', 0))) for sale in sales_data)
        total_units = sum(sale.get('quantity', 0) for sale in sales_data)
        
        # Group by product
        product_sales = {}
        for sale in sales_data:
            product_id = sale['product_id']
            if product_id not in product_sales:
                product_sales[product_id] = {
                    'quantity': 0,
                    'revenue': Decimal('0')
                }
            product_sales[product_id]['quantity'] += sale.get('quantity', 0)
            product_sales[product_id]['revenue'] += Decimal(str(sale.get('total_amount', 0)))
        
        return render_template('sales_report.html',
                             sales_data=sales_data,
                             total_revenue=float(total_revenue),
                             total_units=total_units,
                             product_sales=product_sales)
        
    except Exception as e:
        flash(f'Error generating sales report: {str(e)}', 'error')
        return render_template('sales_report.html', 
                             sales_data=[], 
                             total_revenue=0, 
                             total_units=0,
                             product_sales={})

# ---------------------------------------
# API Routes
# ---------------------------------------
@app.route('/api/inventory/check-low-stock')
@login_required
def api_check_low_stock():
    """API endpoint to check low stock items"""
    try:
        low_stock_items = check_low_inventory()
        return jsonify({
            'success': True,
            'count': len(low_stock_items),
            'items': low_stock_items
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/inventory/<product_id>/<store_id>')
@login_required
def api_get_inventory(product_id, store_id):
    """Get inventory for specific product and store"""
    try:
        inventory_id = f"{product_id}#{store_id}"
        response = inventory_table.get_item(Key={'inventory_id': inventory_id})
        
        if 'Item' in response:
            return jsonify({
                'success': True,
                'data': json.loads(json.dumps(response['Item'], default=decimal_default))
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Inventory not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error_message="Internal server error"), 500

# ---------------------------------------
# Main Application
# ---------------------------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)