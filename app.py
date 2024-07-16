from flask import Flask, flash, render_template, request, redirect, url_for,jsonify,flash,session, send_from_directory
import socket
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_required, current_user, logout_user, login_user 
from functools import wraps
from flask_bcrypt import Bcrypt
from datetime import timedelta
import mysql.connector
from decimal import Decimal

from datetime import timedelta
import os


#------------------------------------------------------------------

#currency_addproduct = "USD"
#brandsearch = "Mitsubishi"
#brandsearch = "plc"
#brandsearch = "inverter"
#brandsearch = "power_supply"
filtered_products = ""
product = 0

categories = ['plc','hmi','inverter','power_supply','relay','servo_accessories','servo_drive','servo_motor', 'photocell']
#------------------------------------------------------------------

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)

#print("Your Computer Name is:" + hostname)
#print("Your Computer IP Address is:" + IPAddr)

if hostname == "DESKTOP-31N7F10":
    hostname2 = "DESKTOP-31N7F10\\SQLEXPRESS"
else:
    hostname2 = hostname
#------------------------------------------------------------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

bcrypt = Bcrypt(app)
app.secret_key = 'egregww'
#------------------ database tables names ---------------------------

setting_table = "setting"
plc_table = "plc"
hmi_table = "hmi"
power_supply_table = "power_supply"
inveter_table = "inverter"
servo_drive_table = "servo_drive"
servo_motor_table = "servo_motor"
servo_accessories_table = "servo_accessories"
relay_table = "relay"
photocell_table = "photocell"

useres_table = "users"
solutions_table = "solutions"
solutions_products_table = "solutions_products"
solution_fees_table = "solutions_fees"

customers_table = "customers"
customers_contacts_table = "customers_contacts"

#------------------------------ database connect ------------------------------------

#mysql--------------------
db_config = {
    'host': 'localhost',
    'user': 'emtecheg_emroot',
    'password': 'Ms~l-IahD5kq',
    'database': 'emtecheg_emtech_products',
}

# Establish a connection to the database
conn = mysql.connector.connect(**db_config)
cur = conn.cursor()

#---------------------------------------------------------------------------------------
def create_table(conn):

    cur.execute("CREATE TABLE IF NOT EXISTS plc (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL,  digitalinput INT, digitaloutput INT, analoginput INT, analogoutput INT,communication TEXT, inputvoltage TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS hmi (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT,  series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL,  size TEXT, communication TEXT, inputvoltage TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS power_supply (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT,  series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL,  inputvoltage TEXT, outputvoltage TEXT, outputcurrent TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS inverter (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL,  inputvoltage TEXT, outputpower REAL, outputcurrent REAL, communication TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS servo_drive (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL, inputvoltage TEXT, power REAL, series TEXT, control_type TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS servo_motor (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL, brake TEXT, power REAL, series TEXT, encoder TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS servo_accessories (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL, accessory_type TEXT, cable_length REAL, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS relay (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL,  coil_voltage TEXT, pins INT,  `current` REAL, base TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS photocell (id INT AUTO_INCREMENT PRIMARY KEY, brand TEXT, series TEXT, model TEXT NOT NULL, purchase_price FLOAT, currency TEXT, description TEXT, end_user_sales_price_egypt REAL, end_user_sales_price_uae REAL, end_user_sales_price_turkey REAL, distributor_sales_price_egypt REAL, distributor_sales_price_uae REAL, distributor_sales_price_turkey REAL,cost_factor_egypt REAL, cost_factor_uae REAL, cost_factor_turkey REAL, cost_price_egypt REAL, cost_price_uae REAL, cost_price_turkey REAL,  photocell_type TEXT, photocell_shape TEXT, photocell_size TEXT, photocell_distance FLOAT, photocell_connection TEXT, output_type TEXT, inputvoltage TEXT, origin TEXT, product_image TEXT, quantity_egypt INT, quantity_uae INT, quantity_turkey INT)")
 
    cur.execute("CREATE TABLE IF NOT EXISTS setting (id INT AUTO_INCREMENT PRIMARY KEY, country VARCHAR(50) NOT NULL, exchange_rate_usd DECIMAL(10, 2) NOT NULL, exchange_rate_eur DECIMAL(10, 2) NOT NULL, end_user_profit_rate DECIMAL(10, 2) NOT NULL, distributor_profit_rate DECIMAL(10, 2) NOT NULL)")
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, email NVARCHAR(50) UNIQUE NOT NULL, username NVARCHAR(50) NOT NULL, password_hash NVARCHAR(255) NOT NULL, role NVARCHAR(50) NOT NULL, authority TEXT)")

    cur.execute("CREATE TABLE IF NOT EXISTS solutions (id INT AUTO_INCREMENT PRIMARY KEY, solution_name VARCHAR(100) NOT NULL, solution_description VARCHAR(200), solution_total_price FLOAT, solution_total_fees FLOAT)")
    cur.execute("CREATE TABLE IF NOT EXISTS solutions_products (id INT AUTO_INCREMENT PRIMARY KEY, solution_id INT, product_name VARCHAR(100), product_description VARCHAR(200), product_quantity INTEGER, product_price FLOAT, product_discount FLOAT, product_total FLOAT)")
    cur.execute("CREATE TABLE IF NOT EXISTS solutions_fees (id INT AUTO_INCREMENT PRIMARY KEY, solution_id INT, fee_name VARCHAR(100), fee_price FLOAT)")


    cur.execute("CREATE TABLE IF NOT EXISTS estimates (id INT AUTO_INCREMENT PRIMARY KEY, estimate_name VARCHAR(100) NOT NULL, estimate_description VARCHAR(200), estimate_total_price FLOAT, estimate_total_fees FLOAT, customer_name TEXT, contact_name TEXT, contact_job TEXT, contact_phone TEXT, contact_email TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS estimates_products (id INT AUTO_INCREMENT PRIMARY KEY, estimate_id INT, product_name VARCHAR(100), product_description VARCHAR(200), product_quantity INTEGER, product_price FLOAT, product_discount FLOAT, product_total FLOAT)")
    cur.execute("CREATE TABLE IF NOT EXISTS estimates_fees (id INT AUTO_INCREMENT PRIMARY KEY, estimate_id INT, fee_name VARCHAR(100), fee_price FLOAT)")

    cur.execute("CREATE TABLE IF NOT EXISTS customers (id INT AUTO_INCREMENT PRIMARY KEY, customer_name TEXT, tin_vat INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS customers_contacts (id INT AUTO_INCREMENT PRIMARY KEY, customer_id INT, contact_name TEXT, contact_job TEXT, contact_phone TEXT, contact_email TEXT)")


    cur.execute("CREATE TABLE IF NOT EXISTS orders (id INT AUTO_INCREMENT PRIMARY KEY, order_name VARCHAR(100) NOT NULL, order_description VARCHAR(200), order_total_price FLOAT, order_total_fees FLOAT, supplier_name TEXT, contact_name TEXT, contact_job TEXT, contact_phone TEXT, contact_email TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS orders_products (id INT AUTO_INCREMENT PRIMARY KEY, order_id INT, product_name VARCHAR(100), product_description VARCHAR(200), product_quantity INTEGER, product_price FLOAT, product_discount FLOAT, product_total FLOAT)")
    cur.execute("CREATE TABLE IF NOT EXISTS orders_fees (id INT AUTO_INCREMENT PRIMARY KEY, order_id INT, fee_name VARCHAR(100), fee_price FLOAT)")

    cur.execute("CREATE TABLE IF NOT EXISTS suppliers (id INT AUTO_INCREMENT PRIMARY KEY, supplier_name TEXT, tin_vat INT)")
    cur.execute("CREATE TABLE IF NOT EXISTS suppliers_contacts (id INT AUTO_INCREMENT PRIMARY KEY, supplier_id INT, contact_name TEXT, contact_job TEXT, contact_phone TEXT, contact_email TEXT)")

    cur.execute("CREATE TABLE IF NOT EXISTS invoices (id INT AUTO_INCREMENT PRIMARY KEY, invoice_name VARCHAR(100) NOT NULL, invoice_description VARCHAR(200), invoice_total_price FLOAT, invoice_total_fees FLOAT, customer_name TEXT, contact_name TEXT, contact_job TEXT, contact_phone TEXT, contact_email TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS invoices_products (id INT AUTO_INCREMENT PRIMARY KEY, invoice_id INT, product_name VARCHAR(100), product_description VARCHAR(200), product_quantity INTEGER, product_price FLOAT, product_discount FLOAT, product_total FLOAT)")
    cur.execute("CREATE TABLE IF NOT EXISTS invoices_fees (id INT AUTO_INCREMENT PRIMARY KEY, invoice_id INT, fee_name VARCHAR(100), fee_price FLOAT)")

    conn.commit()

create_table(conn)
solutions = []
customers = []
#================================================================
#login
#================================================================
# Registration route

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, id, email, username, role, authority):
        self.id = id
        self.email = email
        self.username = username
        self.role = role
        self.authority = authority


# User loader function
@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        return User(user[0], user[1], user[2], user[4], user[5])
    return None

#------------------------------------------------------------------
# Example of protecting a route for authenticated users
@app.route('/dashboard')
@login_required
def dashboard():
    #print("role = ",current_user.role)
    return f'Hello, {current_user.username}! You are in the dashboard.'
#------------------------------------------------------------------
# Custom decorator for role-based access control
def role_required(roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            roles_list = current_user.role.split(',')
            #print("role list = ",roles_list)
            if any(role in roles_list for role in roles):
                return fn(*args, **kwargs)
            else:
                flash('Permission denied.', 'danger')
                #return redirect(url_for('dashboard'))
                return render_template('home.html')
        return wrapper
    return decorator

#------------------------------------------------------------------
# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

#------------------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)

        if user:
            if bcrypt.check_password_hash(user[3], password):
                login_user(User(user[0], user[1], user[2], user[4], user[5]))
                flash('Login successful!', 'success')
                return jsonify({'status': 'success', 'redirect': url_for('home')})
            else:
                flash('Login failed. Check your password.', 'danger')
                return jsonify({'status': 'error', 'message': 'Incorrect password.'})
        else:
            flash('Login failed. Check your username.', 'danger')
            return jsonify({'status': 'error', 'message': 'User not found.'})

    return render_template('login.html')


#----------------------------------------------------
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()

    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']        

        authority_list = request.form.getlist('authority')
        authority = ','.join(authority_list)       
      
        if (role == 'Admin'):
            authority = ' All, Technical Information, Sales Information (EG), Sales Information (UAE), Sales Information (TR), Cost Information (EG), Cost Information (UAE), Cost Information (TR), Balance Information (EG), Balance Information (UAE), Balance Information (TR)'
        else:
            authority = authority
      
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Save user to the database
        # You should validate and handle errors appropriately
        
        cur.execute('SELECT email FROM users WHERE email = %s', (email,))
        mail_check = cur.fetchone()

        if mail_check:
            flash('Registeration Failed. You Used registered user.', 'danger')
            return redirect(url_for('add_user'))
        else:
            cur.execute("INSERT INTO users (email,username, password_hash, role, authority) VALUES (%s, %s, %s, %s, %s)",
                        (email,username, hashed_password, role, authority))
            conn.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")

    columns = [column[0] for column in cur.description]
    users = [dict(zip(columns, row)) for row in cur.fetchall()]
    
    #users = cur.fetchall()

    #print("users = ",users)
    return render_template('add_user.html',users = users)

#----------------------------------------------------
@app.route('/edit_user', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def edit_user():

    user_id = request.args.get('user_id')
    #print("user id = ",user_id)

    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        role = request.form['role']        

        authority_list = request.form.getlist('authority')
        authority = ','.join(authority_list)
        if (role == 'Admin'):
            authority = ' All, Technical Information, Sales Information (EG), Sales Information (UAE), Sales Information (TR), Cost Information (EG), Cost Information (UAE), Cost Information (TR), Balance Information (EG), Balance Information (UAE), Balance Information (TR)'
        else:
            authority = authority
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute('''
            UPDATE users 
            SET email=%s, username=%s, password_hash=%s, role=%s, authority=%s 
            WHERE id=%s
        ''', (email, username, hashed_password, role, authority, user_id))
        conn.commit()
        return redirect(url_for('add_user'))

    if user_id:
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        #user = cur.fetchone()
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        user = dict(zip(columns, row)) if row else None

        if user:
            return render_template('edit_user.html', user=user)

        return redirect(url_for('add_user'))
    """
     user_id = request.args.get('user_id')
    #print("user id = ",user_id)

    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  
             
        authority_list = request.form.getlist('authority')
        authority = ','.join(authority_list)
 
        if (role == 'Admin'):
            authority = ' All, Technical Information, Sales Information (EG), Sales Information (UAE), Sales Information (TR), Cost Information (EG), Cost Information (UAE), Cost Information (TR), Balance Information (EG), Balance Information (UAE), Balance Information (TR)'
        else:
            authority = authority
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cur.execute('SELECT email FROM users WHERE email = %s', (email,))
        mail_check = cur.fetchone()

        if mail_check:
            flash('Registeration Failed. You Used registered user.', 'danger')
            return redirect(url_for('add_user'))
        else:
            cur.execute('''
            UPDATE users 
                    SET email=%s, username=%s, password_hash=%s, role=%s  
                    WHERE id=%s
            ''', (email, username, hashed_password, role, user_id))
            conn.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")

    columns = [column[0] for column in cur.description]
    users = [dict(zip(columns, row)) for row in cur.fetchall()]
    #print("users = ",users)

    return render_template('edit_user.html',user=user, users=users)
"""
#----------------------------------------------------
@app.route('/delete_user', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_user():
    user_id = request.form.get('user_id')

    if user_id:
        #conn = sqlite3.connect(DATABASE)
        '''
        conn = pyodbc.connect(
            "Driver={"+driver+"};"
            "Server="+server+";"
            "Database="+database+";"
            "Trusted_Connection=yes;"
        )
        cur = conn.cursor()
        '''
        cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        #conn.close()

    return redirect(url_for('add_user'))

#------------------------------------------------------------------
def get_user_by_id(user_id):
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

#------------------------------------------------------------------

def get_user_by_email(email):
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cur.fetchone()
    #print("user = ",user)
    return user


@app.route('/home',methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Viewer'])
def home():
    return render_template('home.html')
#================================================================
#solution section
#================================================================

@app.route('/searchProducts', methods=['POST'])
def search_products():

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #search_category = request.form.get('searchCategory')
    search_model = request.form.get('searchModel')
    # Assuming you have an empty list called rows before executing queries
    rows = []

    for category in categories:
        cur.execute(f"SELECT * FROM {category} WHERE model LIKE %s", ('%' + search_model + '%',))
        rows.extend(cur.fetchall())

    
    #print("rows = ",rows)

    # Convert rows to a list of dictionaries
    products = [dict(zip([column[0] for column in cur.description], row)) for row in rows]

    return jsonify(products)

#----------------------------------------------------------------------------------------------
@app.route('/add_solution', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def add_solution():
        
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
        
        solutionname = data.get('solutionName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        product_packet = data.get('products')
        fees_packet = data.get('fees')

        #print("sol name: ",solutionname)
        #print("sol dec: ",description)
        #print("sol price: ",total_price)
        #print("solution_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)

        #solution_id = generate_unique_solution_id()
        #solution_id = "rgerherherhseg"
        #print("solution_id: ",solution_id)
        #print("type solution_id: ",type(solution_id))

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute('''
            INSERT INTO solutions (solution_name, solution_description, solution_total_price, solution_total_fees)
            VALUES (%s, %s, %s, %s)
        ''', (solutionname, description, total_price,total_fees))
        conn.commit()
        
        # Get the ID of the last inserted solution (assuming it's an identity column)
        #cur.execute("select IDENT_CURRENT('solutions')")
        #solution_id = cur.fetchone()[0]
        cur.execute("SELECT LAST_INSERT_ID()")
        solution_id = cur.fetchone()[0]


        # Insert solutions_products into solutions_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO solutions_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    solution_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                solution_id  # Assuming solution_id is associated with the current solution
            ))
        conn.commit()

        for fee in fees_packet:
            cur.execute('''
                INSERT INTO solutions_fees (
                    solution_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                solution_id,
                fee['fee_name'],
                fee['fee_amount']
                # Assuming solution_id is associated with the current solution
            ))
        conn.commit()
        
        #print("sql send success ")
        
        #flash('ADD Success.', 'success')
        #return jsonify({"success": True, "message": "Solution added successfully"})
        #return render_template('add_solution.html')
        #return redirect(url_for('view_solutions'))
    return render_template('add_solution.html')
         
#-----------------------------------------------------------------------------------------------

@app.route('/view_solutions', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def view_solutions():

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM solutions')
    #solutions = cur.fetchall()
    columns = [column[0] for column in cur.description]
    solutions = [dict(zip(columns, row)) for row in cur.fetchall()]
        
    return render_template('view_solutions.html',solutions = solutions)

#--------------------------------------------------------------------------------------------
@app.route('/solution_details', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def solution_details():
    
    solution_id = request.args.get('solution_id')
    
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
        
        solutionid = int(data.get('solutionID'))
        solutionname = data.get('solutionName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0

        product_packet = data.get('products')
        fees_packet = data.get('fees')

        #print("sol id: ",solutionid)
        #print("sol name: ",solutionname)
        #print("sol dec: ",description)
        #print("sol price: ",total_price)
        #print("solution_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute('''
            UPDATE solutions 
            SET solution_name=%s, solution_description=%s, solution_total_price=%s, solution_total_fees=%s 
            WHERE id=%s
        ''', (solutionname, description, total_price, total_fees, solutionid))
        conn.commit()

        cur.execute('DELETE FROM solutions_products WHERE solution_id = %s', (solutionid,))
        conn.commit()

        cur.execute('DELETE FROM solutions_fees WHERE solution_id = %s', (solutionid,))
        conn.commit()

        # Insert solutions_products into solutions_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO solutions_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    solution_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                solutionid  # Assuming solution_id is associated with the current solution
            ))
        conn.commit()

        for fee in fees_packet:
            cur.execute('''
                INSERT INTO solutions_fees (
                    solution_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                solutionid,
                fee['fee_name'],
                fee['fee_amount']
                # Assuming solution_id is associated with the current solution
            ))
        conn.commit()
        
        #print("sql send success ")
        
        #flash('ADD Success.', 'success')
        #return jsonify({"success": True, "message": "Solution added successfully"})
        #return render_template('add_solution.html')
        #return redirect(url_for('view_solutions'))
        return redirect(url_for('view_solutions'))

    if solution_id: 

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM solutions WHERE id = %s', (solution_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        solution = dict(zip(columns, row)) if row else None


        cur.execute('SELECT * FROM solutions_products WHERE solution_id = %s', (solution_id,))
        columns = [column[0] for column in cur.description]
        solution_products = [dict(zip(columns, row)) for row in cur.fetchall()]

        cur.execute('SELECT * FROM solutions_fees WHERE solution_id = %s', (solution_id,))
        columns = [column[0] for column in cur.description]
        solution_fees = [dict(zip(columns, row)) for row in cur.fetchall()]

        return render_template('solution_details.html',solution_info = solution, solution_products = solution_products, solution_fees = solution_fees)

#--------------------------------------------------------------------------------------------

def update_solution_prices(model, end_user_sales_price_egypt):
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()

    cur.execute("SELECT * FROM solutions_products WHERE product_name = %s", (model,))
    columns = [column[0] for column in cur.description]
    solutions_products = [dict(zip(columns, row)) for row in cur.fetchall()]

    for product in solutions_products:
        product_quantity = product['product_quantity']
        product_price = end_user_sales_price_egypt
        product_discount = product['product_discount']
        
        product_total = float(product_quantity) * float(product_price) * float(product_discount)
        
        product_solution_id = product['solution_id']    
        
        product_total_last = product['product_total']
        if product_total_last is not None:
            product_total_diff = product_total - product_total_last
        else:
            product_total_diff = product_total  # Assuming this is the initial update
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        cur.execute('''
            UPDATE solutions_products
            SET product_price=%s, product_total=%s
            WHERE id=%s
        ''', (product_price, product_total, product['id']))
        conn.commit()

        cur.execute("SELECT * FROM solutions WHERE id = %s", (product_solution_id,))
        columns = [column[0] for column in cur.description]

        row = cur.fetchone()
        solution = dict(zip(columns, row)) if row else None

        if solution:
            solution_total_price_last = solution.get('solution_total_price', 0)
            solution_total_price_new = solution_total_price_last + product_total_diff

            cur.execute('''
                UPDATE solutions
                SET solution_total_price=%s
                WHERE id=%s
            ''', (solution_total_price_new, product_solution_id))
            conn.commit()
            cur.close()

#--------------------------------------------------------------------------------------------
@app.route('/delete_solution', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_solution():
    solution_id = request.form.get('solution_id')

    if solution_id:
        
        cur.execute('DELETE FROM solutions WHERE id = %s', (solution_id,))
        conn.commit()

        cur.execute('DELETE FROM solutions_products WHERE solution_id = %s', (solution_id,))
        conn.commit()

        cur.execute('DELETE FROM solutions_fees WHERE solution_id = %s', (solution_id,))
        conn.commit()
        #conn.close()

    return redirect(url_for('view_solutions'))

#================================================================
#fn related to product
#================================================================
"""
def calculate_product_price(currency,purchase_price,cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey):
    
    if currency == 'EGP':
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute("SELECT  end_user_profit_rate , distributor_profit_rate FROM setting WHERE id =1")
        result = cur.fetchone()
        result = [dict(zip([column[0] for column in cur.description], result)) if result else None]

        #print("result: ",result)
        end_user_profit_rate = result[0]['end_user_profit_rate']
        distributor_profit_rate  = result[0]['distributor_profit_rate']
        

        distributor_sales_price = purchase_price * cost_factor_add * distributor_profit_rate
        end_user_sales_price = purchase_price * cost_factor_add * end_user_profit_rate
        

    elif currency == 'USD':
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute("SELECT exchange_rate,end_user_profit_rate,distributor_profit_rate FROM setting WHERE id =1")
        
        result = cur.fetchone()
        result = [dict(zip([column[0] for column in cur.description], result)) if result else None]

        #print("result: ",result)

        end_user_profit_rate = result[0]['end_user_profit_rate']
        distributor_profit_rate  = result[0]['distributor_profit_rate']
        exchange_rate  = result[0]['exchange_rate']

        cost_price = purchase_price * cost_factor_add * exchange_rate
        cost_price_uae = purchase_price * cost_factor_add_uae 
        cost_price_turkey = purchase_price * cost_factor_add_turkey 
        
        distributor_sales_price = cost_price * distributor_profit_rate
        end_user_sales_price = cost_price * end_user_profit_rate
        
        distributor_sales_price_uae = cost_price_uae * distributor_profit_rate
        end_user_sales_price_uae = cost_price_uae * end_user_profit_rate

        distributor_sales_price_turkey = cost_price_turkey * distributor_profit_rate
        end_user_sales_price_turkey = cost_price_turkey * end_user_profit_rate
        
      
    
    elif currency == 'EUR':
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute("SELECT exchange_rate,end_user_profit_rate,distributor_profit_rate FROM setting WHERE id =2")
        
        result = cur.fetchone()
        result = [dict(zip([column[0] for column in cur.description], result)) if result else None]

        #print("result: ",result)

        end_user_profit_rate = result[0]['end_user_profit_rate']
        distributor_profit_rate  = result[0]['distributor_profit_rate']
        exchange_rate  = result[0]['exchange_rate']

        cost_price = purchase_price * cost_factor_add * exchange_rate
        cost_price_uae = purchase_price * cost_factor_add_uae 
        cost_price_turkey = purchase_price * cost_factor_add_turkey 

        distributor_sales_price = purchase_price * cost_factor_add * distributor_profit_rate * exchange_rate
        end_user_sales_price = purchase_price * cost_factor_add * end_user_profit_rate * exchange_rate
        
        distributor_sales_price_uae = purchase_price * cost_factor_add_uae * distributor_profit_rate 
        end_user_sales_price_uae = purchase_price * cost_factor_add_uae * end_user_profit_rate 
        
        distributor_sales_price_turkey = purchase_price * cost_factor_add_turkey * distributor_profit_rate
        end_user_sales_price_turkey = purchase_price * cost_factor_add_turkey * end_user_profit_rate 
       
      
    
    return distributor_sales_price_egypt,end_user_sales_price_egypt, distributor_sales_price_uae,end_user_sales_price_uae, distributor_sales_price_turkey,end_user_sales_price_turkey, cost_price_egypt,cost_price_uae,cost_price_turkey


def calculate_product_price(currency, purchase_price, cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey):
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()

    if currency == 'EGP':
        cur.execute("SELECT end_user_profit_rate, distributor_profit_rate FROM setting WHERE country = 'Egypt'")
    elif currency == 'USD':
        cur.execute("SELECT exchange_rate_usd, end_user_profit_rate, distributor_profit_rate FROM setting WHERE country = 'Egypt'")
    elif currency == 'EUR':
        cur.execute("SELECT exchange_rate_eur, end_user_profit_rate, distributor_profit_rate FROM setting WHERE country = 'Turkey'")

    result = cur.fetchone()
    end_user_profit_rate = result[1]
    distributor_profit_rate = result[2]

    if currency == 'USD':
        exchange_rate = result[0]
        cost_price = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add)) * Decimal(str(exchange_rate))
        cost_price_uae = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add_uae))
        cost_price_turkey = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add_turkey))

        distributor_sales_price = Decimal(str(cost_price)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price = Decimal(str(cost_price)) * Decimal(str(end_user_profit_rate))

        distributor_sales_price_uae = Decimal(str(cost_price_uae)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price_uae = Decimal(str(cost_price_uae)) * Decimal(str(end_user_profit_rate))

        distributor_sales_price_turkey = Decimal(str(cost_price_turkey)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price_turkey = Decimal(str(cost_price_turkey)) * Decimal(str(end_user_profit_rate))

    elif currency == 'EUR':
        exchange_rate = result[0]
        cost_price = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add)) * Decimal(str(exchange_rate))
        cost_price_uae = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add_uae))
        cost_price_turkey = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add_turkey))

        distributor_sales_price = Decimal(str(cost_price)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price = Decimal(str(cost_price)) * Decimal(str(end_user_profit_rate))

        distributor_sales_price_uae = Decimal(str(cost_price_uae)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price_uae = Decimal(str(cost_price_uae)) * Decimal(str(end_user_profit_rate))

        distributor_sales_price_turkey = Decimal(str(cost_price_turkey)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price_turkey = Decimal(str(cost_price_turkey)) * Decimal(str(end_user_profit_rate))

    else:  # EGP
        distributor_sales_price = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add)) * Decimal(str(distributor_profit_rate))
        end_user_sales_price = Decimal(str(purchase_price)) * Decimal(str(cost_factor_add)) * Decimal(str(end_user_profit_rate))
        distributor_sales_price_uae = end_user_sales_price_uae = distributor_sales_price_turkey = end_user_sales_price_turkey = cost_price = cost_price_uae = cost_price_turkey = Decimal('0')

    return distributor_sales_price_egypt, end_user_sales_price_egypt, distributor_sales_price_uae, end_user_sales_price_uae, distributor_sales_price_turkey, end_user_sales_price_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey
"""
#----------------------------------------------------------------------------------------------
@app.route('/add_customer', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def add_customer():
       
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
        customer_name = data.get('customer_name')
        #tin_vat = int(data.get('tin_vat'))
        tin_vat = data.get('tin_vat')

        if (tin_vat == ''):
            tin_vat = 0
        else:
            tin_vat = tin_vat

        contact_packet = data.get('contacts')  
        #print("customer name: ",customer_name)
        #print("tin vat: ",tin_vat)
        #print("contact packet: ",contact_packet)
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute('''
            INSERT INTO customers (customer_name, tin_vat)
            VALUES (%s, %s)
        ''', (customer_name, tin_vat))
        conn.commit()
        
        cur.execute("SELECT LAST_INSERT_ID()")
        customer_id = cur.fetchone()[0]

        # Insert customers_contacts into customers_contacts table
        for contact in contact_packet:
            cur.execute('''
                INSERT INTO customers_contacts (
                    contact_name,
                    contact_job,
                    contact_phone,
                    contact_email,
                    customer_id
                )
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                contact['contact_name'],
                contact['contact_job'],
                contact['contact_phone'],
                contact['contact_email'],
                customer_id  # Assuming customer_id is associated with the current customer
            ))
        conn.commit()
       
        #print("sql send success ")
       

    return render_template('add_customer.html')
         
#-----------------------------------------------------------------------------------------------


@app.route('/view_customers', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def view_customers():


    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM customers')
    columns = [column[0] for column in cur.description]
    customers = [dict(zip(columns, row)) for row in cur.fetchall()]
       
    return render_template('view_customers.html',customers = customers)


#--------------------------------------------------------------------------------------------
@app.route('/customer_details', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def customer_details():

    customer_id = request.args.get('customer_id')
   
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        customer_id = int(data.get('customerID'))
        customer_name = data.get('customer_name')
        #tin_vat = int(data.get('tin_vat')) 
        tin_vat = data.get('tin_vat')
        #print("tin vat: ",tin_vat)
        contact_packet = data.get('contacts')  
        #print("customer name: ",customer_id)
        #print("customer name: ",customer_name)
        #print("tin vat: ",tin_vat)
        #print("contact packet: ",contact_packet)
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
 


        cur.execute('''
            UPDATE customers 
            SET customer_name=%s, tin_vat=%s
            WHERE id=%s
        ''', (customer_name, tin_vat, customer_id))
        conn.commit()
        
        cur.execute('DELETE FROM customers_contacts WHERE customer_id = %s', (customer_id,))
        conn.commit()

        # Insert customers_contacts into customers_contacts table
        for contact in contact_packet:
            cur.execute('''
                INSERT INTO customers_contacts (
                    contact_name,
                    contact_job,
                    contact_phone,
                    contact_email,
                    customer_id
                )
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                contact['contact_name'],
                contact['contact_job'],
                contact['contact_phone'],
                contact['contact_email'],
                customer_id  # Assuming customer_id is associated with the current customer
            ))
        conn.commit()
       
        #print("sql send success ")
        return redirect(url_for('view_customers'))


    if customer_id:


        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
       
        cur.execute('SELECT * FROM customers WHERE id = %s', (customer_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        customer = dict(zip(columns, row)) if row else None
        #print("customer:",customer)




        cur.execute('SELECT * FROM customers_contacts WHERE customer_id = %s', (customer_id,))
        columns = [column[0] for column in cur.description]
        customer_contacts = [dict(zip(columns, row)) for row in cur.fetchall()]
        #print("customer_contacts:",customer_contacts)


        return render_template('customer_details.html',customer_info = customer, customer_contacts = customer_contacts)


#--------------------------------------------------------------------------------------------
@app.route('/delete_customer', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_customer():
    customer_id = request.form.get('customer_id')


    if customer_id:
       
        cur.execute('DELETE FROM customers WHERE id = %s', (customer_id,))
        conn.commit()


        cur.execute('DELETE FROM customers_contacts WHERE customer_id = %s', (customer_id,))
        conn.commit()



    return redirect(url_for('view_customers'))



#-----------------------



@app.route('/add_estimate', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def add_estimate():
       
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        estimatename = data.get('estimateName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        customer_name = data.get('customer_name')
        contact_name = data.get('contact_name')
        contact_job = data.get('contact_job')
        contact_phone = data.get('contact_phone')
        contact_email = data.get('contact_email')
        product_packet = data.get('products')
        fees_packet = data.get('fees')

        #print("sol name: ",estimatename)
        #print("sol dec: ",description)
        #print("sol price: ",total_price)
        #print("estimate_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
 
        cur.execute('''
        INSERT INTO estimates (
                estimate_name, 
                estimate_description, 
                estimate_total_price, 
                estimate_total_fees, 
                customer_name, 
                contact_name, 
                contact_job, 
                contact_phone, 
                contact_email
            )            
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (estimatename, description, total_price, total_fees, customer_name, contact_name, contact_job, contact_phone, contact_email))
        conn.commit()
       
        # Get the ID of the last inserted estimate (assuming it's an identity column)
        cur.execute("SELECT LAST_INSERT_ID()")
        estimate_id = cur.fetchone()[0]

        # Insert estimates_products into estimates_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO estimates_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    estimate_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                estimate_id
            ))
        conn.commit()


        for fee in fees_packet:
            cur.execute('''
                INSERT INTO estimates_fees (
                    estimate_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                estimate_id,
                fee['fee_name'],
                fee['fee_amount']
            ))
        conn.commit()
       
        #print("sql send success ")
    return render_template('add_estimate.html')
         
#-----------------------------------------------------------------------------------------------


@app.route('/view_estimates', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def view_estimates():


    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM estimates')
    #estimates = cur.fetchall()
    columns = [column[0] for column in cur.description]
    estimates = [dict(zip(columns, row)) for row in cur.fetchall()]
       
    return render_template('view_estimates.html',estimates = estimates)


#--------------------------------------------------------------------------------------------
@app.route('/estimate_details', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def estimate_details():
   
    estimate_id = request.args.get('estimate_id')
   
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        estimateid = int(data.get('estimateID'))
        estimatename = data.get('estimateName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        customer_name = data.get('customer_name')
        contact_name = data.get('contact_name')
        contact_job = data.get('contact_job')
        contact_phone = data.get('contact_phone')
        contact_email = data.get('contact_email')
        product_packet = data.get('products')
        fees_packet = data.get('fees')


        #print("sol id: ",estimateid)
        #print("sol name: ",estimatename)
        #print("sol dec: ",description)
        #print("sol price: ",total_price)
        #print("estimate_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)


        #print("estimate_id: ",estimate_id)
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        cur.execute('''
            UPDATE estimates
            SET estimate_name=%s, estimate_description=%s, estimate_total_price=%s, estimate_total_fees=%s,
                customer_name=%s, contact_name=%s, contact_job=%s, contact_phone=%s,  contact_email=%s
            WHERE id=%s
        ''', (estimatename, description, total_price, total_fees, customer_name, contact_name, contact_job, contact_phone, contact_email, estimateid))
        conn.commit()

        cur.execute('DELETE FROM estimates_products WHERE estimate_id = %s', (estimateid,))
        conn.commit()

        cur.execute('DELETE FROM estimates_fees WHERE estimate_id = %s', (estimateid,))
        conn.commit()

        # No need to fetch the last inserted ID since we're updating an existing row

        # Insert estimates_products into estimates_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO estimates_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    estimate_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                estimateid  # Assuming estimate_id is associated with the current estimate
            ))
        conn.commit()

        # Insert fees_packet into estimates_fees table
        for fee in fees_packet:
            cur.execute('''
                INSERT INTO estimates_fees (
                    estimate_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                estimateid,
                fee['fee_name'],
                fee['fee_amount']
                # Assuming estimate_id is associated with the current estimate
            ))
        conn.commit()
       
        #print("sql send success ")
       
        
        return redirect(url_for('view_estimates'))


    if estimate_id:


        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
       
        cur.execute('SELECT * FROM estimates WHERE id = %s', (estimate_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        estimate = dict(zip(columns, row)) if row else None

        cur.execute('SELECT * FROM estimates_products WHERE estimate_id = %s', (estimate_id,))
        columns = [column[0] for column in cur.description]
        estimate_products = [dict(zip(columns, row)) for row in cur.fetchall()]


        cur.execute('SELECT * FROM estimates_fees WHERE estimate_id = %s', (estimate_id,))
        columns = [column[0] for column in cur.description]
        estimate_fees = [dict(zip(columns, row)) for row in cur.fetchall()]


        return render_template('estimate_details.html',estimate = estimate, estimate_info = estimate, estimate_products = estimate_products, estimate_fees = estimate_fees)



#--------------------------------------------------------------------------------------------
@app.route('/delete_estimate', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_estimate():
    estimate_id = request.form.get('estimate_id')


    if estimate_id:
       
        cur.execute('DELETE FROM estimates WHERE id = %s', (estimate_id,))
        conn.commit()


        cur.execute('DELETE FROM estimates_products WHERE estimate_id = %s', (estimate_id,))
        conn.commit()


        cur.execute('DELETE FROM estimates_fees WHERE estimate_id = %s', (estimate_id,))
        conn.commit()
        #conn.close()


    return redirect(url_for('view_estimates'))


#-----------------------




@app.route('/add_invoice', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def add_invoice():
       
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        invoicename = data.get('invoiceName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        customer_name = data.get('customer_name')
        contact_name = data.get('contact_name')
        contact_job = data.get('contact_job')
        contact_phone = data.get('contact_phone')
        contact_email = data.get('contact_email')
        product_packet = data.get('products')
        fees_packet = data.get('fees')


        #print("sol name: ",invoicename)
        #print("sol dec: ",description)
        #print("sol price: ",total_price)
        #print("invoice_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)


        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
 
        cur.execute('''
        INSERT INTO invoices (
                invoice_name,
                invoice_description,
                invoice_total_price,
                invoice_total_fees,
                customer_name,
                contact_name,
                contact_job,
                contact_phone,
                contact_email
            )            
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (invoicename, description, total_price, total_fees, customer_name, contact_name, contact_job, contact_phone, contact_email))
        conn.commit()
       
        # Get the ID of the last inserted invoice (assuming it's an identity column)
        cur.execute("SELECT LAST_INSERT_ID()")
        invoice_id = cur.fetchone()[0]


        # Insert invoices_products into invoices_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO invoices_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    invoice_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                invoice_id
            ))
        conn.commit()




        for fee in fees_packet:
            cur.execute('''
                INSERT INTO invoices_fees (
                    invoice_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                invoice_id,
                fee['fee_name'],
                fee['fee_amount']
            ))
        conn.commit()

        
       
        #print("sql send success ")
    return render_template('add_invoice.html')
         
#-----------------------------------------------------------------------------------------------




@app.route('/view_invoices', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def view_invoices():




    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM invoices')
    #invoices = cur.fetchall()
    columns = [column[0] for column in cur.description]
    invoices = [dict(zip(columns, row)) for row in cur.fetchall()]
       
    return render_template('view_invoices.html',invoices = invoices)




#--------------------------------------------------------------------------------------------
@app.route('/invoice_details', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def invoice_details():
   
    invoice_id = request.args.get('invoice_id')
   
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        invoiceid = int(data.get('invoiceID'))
        invoicename = data.get('invoiceName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        customer_name = data.get('customer_name')
        contact_name = data.get('contact_name')
        contact_job = data.get('contact_job')
        contact_phone = data.get('contact_phone')
        contact_email = data.get('contact_email')
        product_packet = data.get('products')
        fees_packet = data.get('fees')




        #print("sol id: ",invoiceid)
        #print("sol name: ",invoicename)
        #print("sol dec: ",description)
        #print("sol price: ",total_price)
        #print("invoice_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)




        #print("invoice_id: ",invoice_id)
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()


        cur.execute('''
            UPDATE invoices
            SET invoice_name=%s, invoice_description=%s, invoice_total_price=%s, invoice_total_fees=%s,
                customer_name=%s, contact_name=%s, contact_job=%s, contact_phone=%s,  contact_email=%s
            WHERE id=%s
        ''', (invoicename, description, total_price, total_fees, customer_name, contact_name, contact_job, contact_phone, contact_email, invoiceid))
        conn.commit()


        cur.execute('DELETE FROM invoices_products WHERE invoice_id = %s', (invoiceid,))
        conn.commit()


        cur.execute('DELETE FROM invoices_fees WHERE invoice_id = %s', (invoiceid,))
        conn.commit()


        # No need to fetch the last inserted ID since we're updating an existing row


        # Insert invoices_products into invoices_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO invoices_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    invoice_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                invoiceid  # Assuming invoice_id is associated with the current invoice
            ))
        conn.commit()


        # Insert fees_packet into invoices_fees table
        for fee in fees_packet:
            cur.execute('''
                INSERT INTO invoices_fees (
                    invoice_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                invoiceid,
                fee['fee_name'],
                fee['fee_amount']
                # Assuming invoice_id is associated with the current invoice
            ))
        conn.commit()
       
        #print("sql send success ")
       
       
        return redirect(url_for('view_invoices'))




    if invoice_id:




        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
       
        cur.execute('SELECT * FROM invoices WHERE id = %s', (invoice_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        invoice = dict(zip(columns, row)) if row else None


        cur.execute('SELECT * FROM invoices_products WHERE invoice_id = %s', (invoice_id,))
        columns = [column[0] for column in cur.description]
        invoice_products = [dict(zip(columns, row)) for row in cur.fetchall()]




        cur.execute('SELECT * FROM invoices_fees WHERE invoice_id = %s', (invoice_id,))
        columns = [column[0] for column in cur.description]
        invoice_fees = [dict(zip(columns, row)) for row in cur.fetchall()]




        return render_template('invoice_details.html',invoice = invoice, invoice_info = invoice, invoice_products = invoice_products, invoice_fees = invoice_fees)






#--------------------------------------------------------------------------------------------
@app.route('/delete_invoice', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_invoice():
    invoice_id = request.form.get('invoice_id')




    if invoice_id:
       
        cur.execute('DELETE FROM invoices WHERE id = %s', (invoice_id,))
        conn.commit()




        cur.execute('DELETE FROM invoices_products WHERE invoice_id = %s', (invoice_id,))
        conn.commit()




        cur.execute('DELETE FROM invoices_fees WHERE invoice_id = %s', (invoice_id,))
        conn.commit()
        #conn.close()




    return redirect(url_for('view_invoices'))




#-----------------------








def model_check(cur, model):
    check = False
    
    # Your comment block was placed here. If needed, move it to an appropriate authority.
    
    for category in categories:

        cur.execute(f'SELECT model FROM {category} WHERE model = %s', (model,))
        model_check = cur.fetchall()
        #print("model_check: ", model_check)
        
        if model_check:
            check = True
            break

    return check
#================================================================
 
@app.route('/search_customers', methods=['POST'])
def search_customers():
    search_customer = request.form.get('search_customer')

    # Assuming you have a 'customers' table
    cur.execute("SELECT * FROM customers WHERE customer_name LIKE %s", ('%' + search_customer + '%',))
    customers = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]

    return jsonify(customers)

@app.route('/search_contacts', methods=['POST'])
def search_contacts():
    search_contact = request.form.get('search_contact')

    # Assuming you have a 'contacts' table
    cur.execute("SELECT * FROM customers_contacts WHERE contact_name LIKE %s", ('%' + search_contact + '%',))
    contacts = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]

    return jsonify(contacts)



@app.route('/search_suppliers', methods=['POST'])
def search_suppliers():
    search_supplier = request.form.get('search_supplier')


    # Assuming you have a 'suppliers' table
    cur.execute("SELECT * FROM suppliers WHERE supplier_name LIKE %s", ('%' + search_supplier + '%',))
    suppliers = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return jsonify(suppliers)


@app.route('/suppliers_contacts', methods=['POST'])
def suppliers_contacts():
    search_contact = request.form.get('search_contact')


    # Assuming you have a 'contacts' table
    cur.execute("SELECT * FROM suppliers_contacts WHERE contact_name LIKE %s", ('%' + search_contact + '%',))
    contacts = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return jsonify(contacts)
















@app.route('/add_supplier', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def add_supplier():
       
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
        supplier_name = data.get('supplier_name')
        #tin_vat = int(data.get('tin_vat'))
        tin_vat = data.get('tin_vat')


        if (tin_vat == ''):
            tin_vat = 0
        else:
            tin_vat = tin_vat


        contact_packet = data.get('contacts')  
        #print("supplier name: ",supplier_name)
        #print("tin vat: ",tin_vat)
        #print("contact packet: ",contact_packet)
       
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()


        cur.execute('''
            INSERT INTO suppliers (supplier_name, tin_vat)
            VALUES (%s, %s)
        ''', (supplier_name, tin_vat))
        conn.commit()
       
        cur.execute("SELECT LAST_INSERT_ID()")
        supplier_id = cur.fetchone()[0]


        # Insert suppliers_contacts into suppliers_contacts table
        for contact in contact_packet:
            cur.execute('''
                INSERT INTO suppliers_contacts (
                    contact_name,
                    contact_job,
                    contact_phone,
                    contact_email,
                    supplier_id
                )
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                contact['contact_name'],
                contact['contact_job'],
                contact['contact_phone'],
                contact['contact_email'],
                supplier_id  # Assuming supplier_id is associated with the current supplier
            ))
        conn.commit()
       
        #print("sql send success ")
       


    return render_template('add_supplier.html')
         
#-----------------------------------------------------------------------------------------------




@app.route('/view_suppliers', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def view_suppliers():




    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM suppliers')
    columns = [column[0] for column in cur.description]
    suppliers = [dict(zip(columns, row)) for row in cur.fetchall()]
       
    return render_template('view_suppliers.html',suppliers = suppliers)




#--------------------------------------------------------------------------------------------
@app.route('/supplier_details', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def supplier_details():


    supplier_id = request.args.get('supplier_id')
   
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        supplier_id = int(data.get('supplierID'))
        supplier_name = data.get('supplier_name')
        #tin_vat = int(data.get('tin_vat'))
        tin_vat = data.get('tin_vat')
        #print("tin vat: ",tin_vat)
        contact_packet = data.get('contacts')  
        #print("supplier name: ",supplier_id)
        #print("supplier name: ",supplier_name)
        #print("tin vat: ",tin_vat)
        #print("contact packet: ",contact_packet)
       
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
 




        cur.execute('''
            UPDATE suppliers
            SET supplier_name=%s, tin_vat=%s
            WHERE id=%s
        ''', (supplier_name, tin_vat, supplier_id))
        conn.commit()
       
        cur.execute('DELETE FROM suppliers_contacts WHERE supplier_id = %s', (supplier_id,))
        conn.commit()


        # Insert suppliers_contacts into suppliers_contacts table
        for contact in contact_packet:
            cur.execute('''
                INSERT INTO suppliers_contacts (
                    contact_name,
                    contact_job,
                    contact_phone,
                    contact_email,
                    supplier_id
                )
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                contact['contact_name'],
                contact['contact_job'],
                contact['contact_phone'],
                contact['contact_email'],
                supplier_id  # Assuming supplier_id is associated with the current supplier
            ))
        conn.commit()
       
        #print("sql send success ")
        return redirect(url_for('view_suppliers'))




    if supplier_id:




        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
       
        cur.execute('SELECT * FROM suppliers WHERE id = %s', (supplier_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        supplier = dict(zip(columns, row)) if row else None
        #print("supplier:",supplier)








        cur.execute('SELECT * FROM suppliers_contacts WHERE supplier_id = %s', (supplier_id,))
        columns = [column[0] for column in cur.description]
        supplier_contacts = [dict(zip(columns, row)) for row in cur.fetchall()]
        #print("supplier_contacts:",supplier_contacts)




        return render_template('supplier_details.html',supplier_info = supplier, supplier_contacts = supplier_contacts)




#--------------------------------------------------------------------------------------------
@app.route('/delete_supplier', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_supplier():
    supplier_id = request.form.get('supplier_id')




    if supplier_id:
       
        cur.execute('DELETE FROM suppliers WHERE id = %s', (supplier_id,))
        conn.commit()




        cur.execute('DELETE FROM suppliers_contacts WHERE supplier_id = %s', (supplier_id,))
        conn.commit()






    return redirect(url_for('view_suppliers'))






#-----------------------






@app.route('/add_order', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def add_order():
       
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        ordername = data.get('orderName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        supplier_name = data.get('supplier_name')
        contact_name = data.get('contact_name')
        contact_job = data.get('contact_job')
        contact_phone = data.get('contact_phone')
        contact_email = data.get('contact_email')
        product_packet = data.get('products')
        fees_packet = data.get('fees')


        #print("order name: ",ordername)
        #print("order dec: ",description)
        #print("order price: ",total_price)
        #print("order_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)


        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
 
        cur.execute('''
        INSERT INTO orders (
                order_name,
                order_description,
                order_total_price,
                order_total_fees,
                supplier_name,
                contact_name,
                contact_job,
                contact_phone,
                contact_email
            )            
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (ordername, description, total_price, total_fees, supplier_name, contact_name, contact_job, contact_phone, contact_email))
        conn.commit()
       
        # Get the ID of the last inserted order (assuming it's an identity column)
        cur.execute("SELECT LAST_INSERT_ID()")
        order_id = cur.fetchone()[0]


        # Insert orders_products into orders_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO orders_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    order_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                order_id
            ))
        conn.commit()




        for fee in fees_packet:
            cur.execute('''
                INSERT INTO orders_fees (
                    order_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                order_id,
                fee['fee_name'],
                fee['fee_amount']
            ))
        conn.commit()
       
        #print("sql send success ")
    return render_template('add_order.html')
         
#-----------------------------------------------------------------------------------------------




@app.route('/view_orders', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def view_orders():




    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute('SELECT * FROM orders')
    #orders = cur.fetchall()
    columns = [column[0] for column in cur.description]
    orders = [dict(zip(columns, row)) for row in cur.fetchall()]
       
    return render_template('view_orders.html',orders = orders)




#--------------------------------------------------------------------------------------------
@app.route('/order_details', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def order_details():
   
    order_id = request.args.get('order_id')
   
    if request.method == 'POST':
        data = request.get_json()
        #print("Received data:", data)
       
        orderid = int(data.get('orderID'))
        ordername = data.get('orderName')
        description = data.get('description')
        total_price = float(data.get('totalPrice')) if data.get('totalPrice') is not None else 0.0
        total_fees = float(data.get('total_fees')) if data.get('total_fees') is not None else 0.0
        supplier_name = data.get('supplier_name')
        contact_name = data.get('contact_name')
        contact_job = data.get('contact_job')
        contact_phone = data.get('contact_phone')
        contact_email = data.get('contact_email')
        product_packet = data.get('products')
        fees_packet = data.get('fees')




        #print("sol id: ",orderid)
        #print("order name: ",ordername)
        #print("order dec: ",description)
        #print("order price: ",total_price)
        #print("order_total_fees: ",total_fees)
        #print("product_packet: ",product_packet)
        #print("fees_packet: ",fees_packet)




        #print("order_id: ",order_id)
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()


        cur.execute('''
            UPDATE orders
            SET order_name=%s, order_description=%s, order_total_price=%s, order_total_fees=%s,
                supplier_name=%s, contact_name=%s, contact_job=%s, contact_phone=%s,  contact_email=%s
            WHERE id=%s
        ''', (ordername, description, total_price, total_fees, supplier_name, contact_name, contact_job, contact_phone, contact_email, orderid))
        conn.commit()


        cur.execute('DELETE FROM orders_products WHERE order_id = %s', (orderid,))
        conn.commit()


        cur.execute('DELETE FROM orders_fees WHERE order_id = %s', (orderid,))
        conn.commit()


        # No need to fetch the last inserted ID since we're updating an existing row


        # Insert orders_products into orders_products table
        for product in product_packet:
            cur.execute('''
                INSERT INTO orders_products (
                    product_name,
                    product_description,
                    product_quantity,
                    product_price,
                    product_discount,
                    product_total,
                    order_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                product['productName'],
                product['productDescription'],
                product['quantity'],
                product['price'],
                product['discount'],
                product['total'],
                orderid  # Assuming order_id is associated with the current order
            ))
        conn.commit()


        # Insert fees_packet into orders_fees table
        for fee in fees_packet:
            cur.execute('''
                INSERT INTO orders_fees (
                    order_id,
                    fee_name,
                    fee_price
                )
                VALUES (%s, %s, %s)
            ''', (
                orderid,
                fee['fee_name'],
                fee['fee_amount']
                # Assuming order_id is associated with the current order
            ))
        conn.commit()
       
        #print("sql send success ")
       
       
        return redirect(url_for('view_orders'))




    if order_id:




        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
       
        cur.execute('SELECT * FROM orders WHERE id = %s', (order_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        order = dict(zip(columns, row)) if row else None


        cur.execute('SELECT * FROM orders_products WHERE order_id = %s', (order_id,))
        columns = [column[0] for column in cur.description]
        order_products = [dict(zip(columns, row)) for row in cur.fetchall()]




        cur.execute('SELECT * FROM orders_fees WHERE order_id = %s', (order_id,))
        columns = [column[0] for column in cur.description]
        order_fees = [dict(zip(columns, row)) for row in cur.fetchall()]




        return render_template('order_details.html',order = order, order_info = order, order_products = order_products, order_fees = order_fees)






#--------------------------------------------------------------------------------------------
@app.route('/delete_order', methods=['POST'])
@login_required
@role_required(['Admin','Moderator'])
def delete_order():
    order_id = request.form.get('order_id')




    if order_id:
       
        cur.execute('DELETE FROM orders WHERE id = %s', (order_id,))
        conn.commit()




        cur.execute('DELETE FROM orders_products WHERE order_id = %s', (order_id,))
        conn.commit()




        cur.execute('DELETE FROM orders_fees WHERE order_id = %s', (order_id,))
        conn.commit()
        #conn.close()




    return redirect(url_for('view_orders'))











#================================================================
#add product section
#================================================================
# Route for adding a product, accessible only by logged-in users with 'Admin' or 'Moderator' role
@app.route('/add_product', methods=['GET', 'POST'])
@login_required  # Ensure that the user is logged in before accessing this route
@role_required(['Admin', 'Moderator'])  # Ensure that the user has 'Admin' or 'Moderator' role before accessing this route
def add_product():
    product_id = request.args.get('product_id')
    filename = None  # Initialize filename for product image
    
    # If it's a POST request, handle form submission
    if request.method == 'POST':
        create_upload_folder()  # Create an upload folder if it doesn't exist
        
        # Handle file upload for the product image
        if 'product_image' in request.files:
            file = request.files['product_image']  # Get the uploaded file
            # Check if file is uploaded and is allowed
            if file.filename != '' and allowed_file(file.filename):
                # Rename the file using the model name and save it to the upload folder
                filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                # Set default filename if no image is uploaded
                filename = "No image uploaded"
  
        # Extract form data for the product
        brand = request.form['brand']
        series = request.form['series']
        category = request.form['category']
        origin = request.form['origin']
        model = request.form['model']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_add']
        cost_factor_add_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_add_uae = float(request.form['cost_factor_uae'])
        cost_factor_add_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
      
        # Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_add_egypt, 
                                    'uae': cost_factor_add_uae, 
                                    'turkey': cost_factor_add_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)

        # Establish a connection to the database
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

        # Check if the model already exists in the database
        if model_check(cur, model):
            # If model already exists, show a flash message and redirect back to add_product page
            flash('ADD Failed. You used a registered model.', 'danger')
            return redirect(url_for('add_product'))
        else:
            # If model does not exist, insert the product into the appropriate table based on its category
            if category == "plc":  # If category is plc
                # Extract additional plc-specific form data
                digital_input = int(request.form['digital_input'])
                digital_output = int(request.form['digital_output'])
                analog_input = int(request.form['analog_input'])
                analog_output = int(request.form['analog_output'])
                selected_checkboxes = request.form.getlist('communication_port_plc')
                communication = '-'.join(selected_checkboxes)
                input_voltage = request.form['power_supply_plc']
                
                # Insert product into the plc table
                cur.execute('''
                    INSERT INTO plc (
                        brand, series, model, description, purchase_price, currency, 
                        end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                        distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                        cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                        cost_price_egypt, cost_price_uae, cost_price_turkey, 
                        quantity_egypt, quantity_uae, quantity_turkey, 
                        digitalinput, digitaloutput, analoginput,
                        analogoutput, communication, inputvoltage, origin, product_image
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                ''', (
                    brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey,
                    cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    digital_input, digital_output, analog_input, analog_output, communication, input_voltage, origin, filename
                ))
                conn.commit()
                flash('ADD Success.', 'success')
                return redirect(url_for('plc'))
            
            elif category == "HMI":  # If category is HMI
                # Extract additional HMI-specific form data
                size = request.form['size']
                selected_checkboxes = request.form.getlist('hmi_communication_port')
                communication = '-'.join(selected_checkboxes)
                input_voltage = request.form['hmi_power_supply']

                # Insert product into the HMI table
                cur.execute('''
                   INSERT INTO hmi (brand, series, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                        distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                        cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                        cost_price_egypt, cost_price_uae, cost_price_turkey, 
                        quantity_egypt, quantity_uae, quantity_turkey, 
                    size,communication,inputvoltage, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey,
                    cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    size, communication, input_voltage, origin, filename))
                conn.commit()
                flash('ADD Success.', 'success')
                return redirect(url_for('hmi'))
  
            
                #-------------Inverter Input Section------------------------------------------------------------

            elif category == "Inverter":
                outputpower = float(request.form['inverter_output_power'])
                outputcurrent = float(request.form['inverter_output_current'])


                selected_checkboxes = request.form.getlist('inverter_communication_port')
                communication = '-'.join(selected_checkboxes)

                input_voltage = request.form['inverter_power_supply']

                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor()
                cur.execute('''
                   INSERT INTO inverter (brand, series, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                    inputvoltage, outputpower, outputcurrent, communication, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    input_voltage, outputpower, outputcurrent, communication,origin,filename))
                conn.commit()

                return redirect(url_for('inverter'))

                #-------------------Power Supply Section----------------------------------------------------------

            elif category == "Power Supply":
                
                outputcurrent = request.form['ps_output_current']
                outputvoltage = request.form['ps_output_voltage']
        


                
                input_voltage = request.form['ps_power_supply']

                
            
                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor()
                cur.execute('''
                   INSERT INTO power_supply (brand, series, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                     outputcurrent,outputvoltage, inputvoltage, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    outputcurrent,outputvoltage,input_voltage,origin,filename))
                conn.commit()

            
                return redirect(url_for('power_supply'))
                    
                #-------------------Servo Drive Section----------------------------------------------------------

            elif category == "Servo Drive":
                
                series = request.form['series']
                #print ("series = ",series)                
                power = float(request.form['power_servo_drive'])
                inputvoltage = request.form['inputvoltage']
                selected_checkboxes = request.form.getlist('control_type')
                control_type = '-'.join(selected_checkboxes)
                
                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor()
                cur.execute('''
                   INSERT INTO servo_drive (brand, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                    inputvoltage, power, series, control_type, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    inputvoltage, power, series, control_type, origin, filename))
                conn.commit()

            
                return redirect(url_for('servo_drive'))
            
                #-------------------Servo Motor Section----------------------------------------------------------

            elif category == "Servo Motor":
                
                encoder = request.form['encoder']
                series = request.form['series']
                brake = request.form['brake']
                power = float(request.form['power_servo_motor'])
            
                #print ("power = ",power)
                #print ("==========================================")
                
                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor()
                cur.execute('''
                   INSERT INTO servo_motor (brand, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                    series,brake,encoder, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    series,brake,encoder, origin,filename))
                conn.commit()

            
                return redirect(url_for('servo_motor'))
            
                #-------------------Servo Accessory Section----------------------------------------------------------

            elif category == "Servo Accessory":
                
                accessory_type = request.form['servo_accessory_type']
                cable_length = float(request.form['servo_cable_length'])
                
                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor()
                cur.execute('''
                   INSERT INTO servo_accessories (brand, series, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                    accessory_type, cable_length, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    accessory_type, cable_length, origin,filename))
                conn.commit()
                return redirect(url_for('servo_accessories'))


                 #-------------------Photocell Section----------------------------------------------------------

            elif category == "Photocell":
                
                photocell_type = request.form['photocell_type']
                photocell_shape = request.form['photocell_shape']
                photocell_size = request.form['photocell_size']
                photocell_connection = request.form['photocell_connection']
                photocell_distance = float(request.form['photocell_distance'])
                output_type = request.form['output_type']
                inputvoltage = request.form['inputvoltage']

                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor()
                cur.execute('''
                   INSERT INTO photocell (brand, series, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                    photocell_type, photocell_shape, photocell_size, photocell_connection, 
                    photocell_distance, output_type, inputvoltage, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                     photocell_type, photocell_shape, photocell_size, photocell_connection, 
                     photocell_distance, output_type, inputvoltage, origin,filename))
                conn.commit()
                return redirect(url_for('photocell'))
                
                #-------------------Relay Section----------------------------------------------------------

            elif category == "Relay":
                
                coil_voltage = request.form['coil_voltage']
                pins = request.form['pins']
                base = request.form['base']
                current = float(request.form['current_relay'])
                
                conn = mysql.connector.connect(**db_config)
                cur = conn.cursor() 
                cur.execute('''
                   INSERT INTO relay (brand, series, model, description, purchase_price, currency, 
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_egypt, cost_factor_uae, cost_factor_turkey, 
                    cost_price_egypt, cost_price_uae, cost_price_turkey, 
                    quantity_egypt, quantity_uae, quantity_turkey, 
                    coil_voltage,pins,current,base, origin, product_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_add_egypt, cost_factor_add_uae, cost_factor_add_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    coil_voltage,pins,current,base, origin,filename))
                conn.commit()

            
                return redirect(url_for('relay'))
        
    # Pass category and brand options to the template
    category_options = ['plc', 'hmi', 'inverter', 'servo drive', 'servo motor', 'relay', 'servo accessories', 'photocell' 'power supply']
    brand_options = ['Mitsubishi', 'Omron', 'Asem', 'Cumark', 'Vector', 'GMT']

    return render_template('add_product.html', category_options=category_options, brand_options=brand_options)

#================================================================
#view product section
#================================================================
@app.route('/plc', methods=['GET', 'POST'])
def plc():
    
    brand_search = request.form.getlist('brand_search[]')
    series_search = request.form.getlist('series_search[]')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    communication_search = request.form.getlist('communication_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    digital_input_search = request.form.get('digital_input_search')
    digital_output_search = request.form.get('digital_output_search')
    analog_input_search = request.form.get('analog_input_search')
    analog_output_search = request.form.get('analog_output_search')
  
    filtered_products = retrieve_data(brand_search, series_search, input_voltage_search, communication_search, model_search, 
                   digital_input_search, digital_output_search, analog_input_search, 
                   analog_output_search)
    
    return render_template('plc.html', products=filtered_products, selected_brand=selected_dropdown,digital_input_search=digital_input_search)

def retrieve_data(brand_search, series_search, input_voltage_search, communication_search, model_search, 
                   digital_input_search, digital_output_search, analog_input_search, 
                   analog_output_search):
  
    query = "SELECT * FROM plc"
    parameters = []
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)

    if series_search:
        if brand_search:
             query += " AND series IN ({})".format(', '.join(['%s'] * len(series_search)))
        else:
             query += " WHERE series IN ({})".format(', '.join(['%s'] * len(series_search)))
        parameters.extend(series_search)

    if input_voltage_search:
        if brand_search or series_search:
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    if communication_search:
        if brand_search or series_search or input_voltage_search :
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " AND (" + " AND ".join(communication_conditions) + ")"
            query += communication_query
        else:
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " WHERE (" + " AND ".join(communication_conditions) + ")"
            query += communication_query

    if model_search:
        if brand_search or series_search or input_voltage_search or communication_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
  
    if digital_input_search:
        digital_input_search_int = int(digital_input_search)
        if brand_search or series_search or model_search or input_voltage_search or communication_search:
            query += " AND digitalinput >= %s"
        else:
            query += " WHERE digitalinput >= %s"

        parameters.extend([digital_input_search_int])

    if digital_output_search:
        digital_output_search_int = int(digital_output_search)
        if brand_search or series_search or model_search or digital_input_search or input_voltage_search or communication_search:
            query += " AND digitaloutput >= %s"
        else:
            query += " WHERE digitaloutput >= %s"

        parameters.extend([digital_output_search_int])

    if analog_input_search:
        analog_input_search_int = int(analog_input_search)
        if brand_search or series_search or model_search or digital_input_search or digital_output_search or input_voltage_search or communication_search:
            query += " AND analoginput >= %s"
        else:
            query += " WHERE analoginput >= %s"

        parameters.extend([analog_input_search_int])

    if analog_output_search:
        analog_output_search_int = int(analog_output_search)
        if brand_search or series_search or  model_search or digital_input_search or digital_output_search or analog_input_search or input_voltage_search or communication_search:
            query += " AND analogoutput >= %s"
        else:
            query += " WHERE analogoutput >= %s"
    
        parameters.extend([analog_output_search_int])

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute(query, parameters)

    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
  
    return products_search

#-----------------------------------------------------------------------

@app.route('/hmi', methods=['GET', 'POST'])
def hmi():

    brand_search = request.form.getlist('brand_search_hmi[]')
    
    size_search = request.form.getlist('size_search_hmi[]')
    input_voltage_search = request.form.getlist('input_voltage_search_hmi[]')
    communication_search = request.form.getlist('communication_search_hmi[]')

    model_search = request.form.get('model_search_hmi')

    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("size_search: ",size_search)
    #print("input_voltage_search: ",input_voltage_search)
    #print("communication_search: ",communication_search)

    filtered_products = retrieve_hmi_products(brand_search, model_search, size_search, input_voltage_search, communication_search)
    
    #print("products:", filtered_products)

    return render_template('hmi.html', products=filtered_products)

def retrieve_hmi_products(brand_search, model_search, size_search, input_voltage_search, communication_search):
    
    # Initialize an empty list to store the results
    rows = []

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM hmi"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    # Add more conditions for other filters (communication, model, etc.)
    if communication_search:
        if brand_search or input_voltage_search :
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " AND (" + " AND ".join(communication_conditions) + ")"
            query += communication_query
        else:
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " WHERE (" + " AND ".join(communication_conditions) + ")"
            query += communication_query

    if model_search:
        # Adjust this condition based on your actual model storage and comparison logic
        if brand_search or input_voltage_search or communication_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
        #parameters.extend([model_search])

    if size_search:
        if brand_search or model_search or input_voltage_search or communication_search :
            query += " AND size IN ({})".format(', '.join(['%s'] * len(size_search)))
        else:
            query += " WHERE size IN ({})".format(', '.join(['%s'] * len(size_search)))

        parameters.extend(size_search)
    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return products_search

#----------------------------------------------------------------------------------------------------

@app.route('/inverter',methods=['GET', 'POST'])
def inverter():
    # Get form data
    brand_search = request.form.getlist('brand_search[]')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    communication_search = request.form.getlist('communication_search[]')
    model_search = request.form.get('model_search')
    out_current_search = request.form.get('out_current_search')
    out_power_search = request.form.get('out_power_search')
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("out_current_search: ",out_current_search)
    #print("out_power_search: ",out_power_search)
    
    #print("input_voltage_search: ",input_voltage_search)
    #print("communication_search: ",communication_search)
    filtered_products = retrieve_inverter_products(brand_search, input_voltage_search, communication_search, model_search, 
                   out_current_search, out_power_search)
    
    #print("products:", filtered_products)

    return render_template('inverter.html', products=filtered_products)

def retrieve_inverter_products(brand_search, input_voltage_search, communication_search, model_search, 
                   out_current_search, out_power_search):
    # Initialize an empty list to store the results
    rows = []

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM inverter"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    # Add more conditions for other filters (communication, model, etc.)
    if communication_search:
        if brand_search or input_voltage_search :
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " AND (" + " AND ".join(communication_conditions) + ")"
            query += communication_query
        else:
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " WHERE (" + " AND ".join(communication_conditions) + ")"
            query += communication_query

    """
    if communication_search:
        if brand_search or input_voltage_search :
            query += " AND CAST(communication AS NVARCHAR(MAX)) LIKE ({})".format(', '.join(['%s'] * len(communication_search)))
        else:
            query += " WHERE CAST(communication AS NVARCHAR(MAX)) LIKE ({})".format(', '.join(['%s'] * len(communication_search)))

        parameters.extend(communication_search)
    """
    if model_search:
        # Adjust this condition based on your actual model storage and comparison logic
        if brand_search or input_voltage_search or communication_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
        #parameters.extend([model_search])

    if out_current_search:
        if brand_search or model_search or input_voltage_search or communication_search:
            query += " AND outputcurrent = %s"
        else:
            query += " WHERE outputcurrent = %s"

        parameters.extend([out_current_search])

    if out_power_search:
        if brand_search or model_search or out_current_search or input_voltage_search or communication_search:
            query += " AND outputpower = %s"
        else:
            query += " WHERE outputpower = %s"

        parameters.extend([out_power_search])

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return products_search

#----------------------------------------------------------------------------------------------------

@app.route('/power_supply',methods=['GET', 'POST'])
def power_supply():
    # Get form data
    brand_search = request.form.getlist('brand_search[]')
    model_search = request.form.get('model_search')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    out_voltage_search = request.form.getlist('out_voltage_search[]')
    out_current_search = request.form.getlist('out_current_search[]')
    
    filtered_products = retrieve_power_supply(brand_search, input_voltage_search, model_search, out_current_search, out_voltage_search)
    
    return render_template('power_supply.html', products=filtered_products)

def retrieve_power_supply(brand_search, input_voltage_search, model_search, out_current_search, out_voltage_search):
    # Initialize an empty list to store the results
    rows = []

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM power_supply"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    
    # Build the WHERE clause based on the selected input voltage values    
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)


    if model_search:
        # Adjust this condition based on your actual model storage and comparison logic
        if brand_search or input_voltage_search :
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
        #parameters.extend([model_search])

    

    if out_current_search:
        if brand_search or model_search or input_voltage_search:
            query += " AND outputcurrent IN ({})".format(', '.join(['%s'] * len(out_current_search)))
        else:
            query += " WHERE outputcurrent IN ({})".format(', '.join(['%s'] * len(out_current_search)))

        parameters.extend(out_current_search)

    if out_voltage_search:
        if brand_search or model_search or out_current_search or input_voltage_search:
            query += " AND outputvoltage IN ({})".format(', '.join(['%s'] * len(out_voltage_search)))
        else:
            query += " WHERE outputvoltage IN ({})".format(', '.join(['%s'] * len(out_voltage_search)))

        parameters.extend(out_voltage_search)

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return products_search

#----------------------------------------------------------------------------------------------------

@app.route('/servo_drive',methods=['GET', 'POST'])
def servo_drive():
    brand_search = request.form.getlist('brand_search[]')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    control_type_search = request.form.getlist('control_type_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    series_search = request.form.get('series_search')
    power_search = request.form.get('power_search')
  
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("series_search: ",series_search)
    #print("power_search: ",power_search)
    #print("input_voltage_search: ",input_voltage_search)
    #print("control_type_search: ",control_type_search)

    filtered_products = retrieve_servo_drive(brand_search, input_voltage_search, control_type_search, model_search, 
                   series_search, power_search )
    
    #print("products:", filtered_products)

    return render_template('servo_drive.html', products=filtered_products, selected_brand=selected_dropdown,series_search=series_search)

def retrieve_servo_drive(brand_search, input_voltage_search, control_type_search, model_search, 
                   series_search, power_search):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM servo_drive"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    # Add more conditions for other filters (communication, model, etc.)
    if control_type_search:
        if brand_search or input_voltage_search :
            control_type_conditions = []
            for control_type_value in control_type_search:
                control_conditions = [f"control_type LIKE %s"] * len(control_type_value.split('-'))
                control_type_conditions.append("(" + " AND ".join(control_conditions) + ")")

                for control_choice in control_type_value.split('-'):
                    parameters.extend([f'%{control_choice}%'])

            control_type_query = " AND (" + " AND ".join(control_type_conditions) + ")"
            query += control_type_query
        else:
            control_type_conditions = []
            for control_type_value in control_type_search:
                control_conditions = [f"control_type LIKE %s"] * len(control_type_value.split('-'))
                control_type_conditions.append("(" + " AND ".join(control_conditions) + ")")

                for control_choice in control_type_value.split('-'):
                    parameters.extend([f'%{control_choice}%'])

            control_type_query = " WHERE (" + " AND ".join(control_type_conditions) + ")"
            query += control_type_query

    if model_search:
        if brand_search or input_voltage_search or control_type_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    if series_search:
        if brand_search or model_search or input_voltage_search or control_type_search:
            query += " AND series LIKE '%" + series_search + "%'"
        else:
            query += " WHERE series LIKE '%" + series_search + "%'"


    if power_search:
        power_search_int = int(power_search)
        if brand_search or model_search or series_search or input_voltage_search or control_type_search:
            query += " AND power >= %s"
        else:
            query += " WHERE power >= %s"

        parameters.extend([power_search_int])

    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search


#----------------------------------------------------------------------------------------------------

@app.route('/servo_accessories', methods=['GET', 'POST'])
def servo_accessories():
    brand_search = request.form.getlist('brand_search[]')
    accessory_type_search = request.form.getlist('accessory_type_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    cable_length_search = request.form.get('cable_length_search')

    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("cable_length_search: ",cable_length_search)
    #print("accessory_type_search: ",accessory_type_search)

    filtered_products = retrieve_servo_accessories(brand_search, cable_length_search, accessory_type_search, model_search)
    
    #print("products:", filtered_products)

    return render_template('servo_accessories.html', products=filtered_products, selected_brand=selected_dropdown)

def retrieve_servo_accessories(brand_search, cable_length_search, accessory_type_search, model_search):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM servo_accessories"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:
        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if cable_length_search:
        if brand_search:
            query += " AND cable_length LIKE '%" + cable_length_search + "%'"
        else:
            query += " WHERE cable_length LIKE '%" + cable_length_search + "%'"

    # Add more conditions for other filters (communication, model, etc.)
    if accessory_type_search:
        if brand_search or cable_length_search :
            accessories_type_conditions = []
            for accessories_type_value in accessory_type_search:
                accessories_conditions = [f"accessory_type LIKE %s"] * len(accessories_type_value.split('-'))
                accessories_type_conditions.append("(" + " AND ".join(accessories_conditions) + ")")

                for accessories_choice in accessories_type_value.split('-'):
                    parameters.extend([f'%{accessories_choice}%'])

            accessories_type_query = " AND (" + " AND ".join(accessories_type_conditions) + ")"
            query += accessories_type_query
        else:
            accessories_type_conditions = []
            for accessories_type_value in accessory_type_search:
                accessories_conditions = [f"accessory_type LIKE %s"] * len(accessories_type_value.split('-'))
                accessories_type_conditions.append("(" + " AND ".join(accessories_conditions) + ")")

                for accessories_choice in accessories_type_value.split('-'):
                    parameters.extend([f'%{accessories_choice}%'])

            accessories_type_query = " WHERE (" + " AND ".join(accessories_type_conditions) + ")"
            query += accessories_type_query

    if model_search:
        if brand_search or cable_length_search or accessory_type_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search

#----------------------------------------------------------------------------------------------------


@app.route('/photocell', methods=['GET', 'POST'])
def photocell():

    brand_search = request.form.getlist('brand_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    sensing_distance_search = request.form.get('sensing_distance_search')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    output_type_search = request.form.getlist('output_type_search[]')
    shape_search = request.form.getlist('shape_search[]')
    connection_search = request.form.getlist('connection_search[]')
    type_search = request.form.getlist('type_search[]')
 
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("sensing_distance_search: ",sensing_distance_search)
    #print("input_voltage_search: ",input_voltage_search)
    #print("output_type_search: ",output_type_search)
    #print("shape_search: ",shape_search)
    #print("connection_search: ",connection_search)
    #print("type_search: ",type_search)

   

    filtered_products = retrieve_photocell(brand_search, model_search, sensing_distance_search, input_voltage_search, output_type_search, shape_search, connection_search, type_search)
    
    #print("products:", filtered_products)

    return render_template('photocell.html', products=filtered_products)

def retrieve_photocell(brand_search, model_search, sensing_distance_search, input_voltage_search, output_type_search, shape_search, connection_search, type_search):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM photocell"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand

    #1
    if brand_search:
        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    
    #2
    if model_search:
        if brand_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    #3
    if sensing_distance_search:
        photocell_distance_int = float(sensing_distance_search)
        if brand_search or model_search:
            query += " AND photocell_distance >= %s"
        else:
            query += " WHERE photocell_distance >= %s"
        parameters.extend([photocell_distance_int])


    #4
    if input_voltage_search:
        if brand_search or model_search or sensing_distance_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)


    

    #5
    if output_type_search:
        if brand_search or model_search or sensing_distance_search or input_voltage_search :
            query += " AND output_type IN ({})".format(', '.join(['%s'] * len(output_type_search)))
        else:
            query += " WHERE output_type IN ({})".format(', '.join(['%s'] * len(output_type_search)))
        parameters.extend(output_type_search)

    #6   
    if shape_search:
        if brand_search or model_search or sensing_distance_search or output_type_search or output_type_search :
            query += " AND photocell_shape IN ({})".format(', '.join(['%s'] * len(shape_search)))
        else:
            query += " WHERE photocell_shape IN ({})".format(', '.join(['%s'] * len(shape_search)))
        parameters.extend(shape_search)

    
    
    #7
    if connection_search:
        if brand_search or model_search or sensing_distance_search or output_type_search or output_type_search or shape_search:
            query += " AND photocell_connection IN ({})".format(', '.join(['%s'] * len(connection_search)))
        else:
            query += " WHERE photocell_connection IN ({})".format(', '.join(['%s'] * len(connection_search)))

        parameters.extend(connection_search)
    #8
        
    if type_search:
        if brand_search or model_search or sensing_distance_search or output_type_search or output_type_search or shape_search or connection_search:
            query += " AND photocell_type IN ({})".format(', '.join(['%s'] * len(type_search)))
        else:
            query += " WHERE photocell_type IN ({})".format(', '.join(['%s'] * len(type_search)))
        parameters.extend(type_search)
    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search
#----------------------------------------------------------------------------------------------------
@app.route('/relay',methods=['GET', 'POST'])
def relay():

    brand_search = request.form.getlist('brand_search[]')
    coil_voltage_search = request.form.getlist('coil_voltage_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    pins_search = request.form.get('pins_search')
    current_search = request.form.get('current_search')
  
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("pins_search: ",pins_search)
    #print("current_search: ",current_search)
    #print("coil_voltage_search: ",coil_voltage_search)

    filtered_products = retrieve_relay(brand_search, coil_voltage_search, model_search, pins_search, current_search )
    
    #print("products:", filtered_products)

    return render_template('relay.html', products=filtered_products, selected_brand=selected_dropdown)

def retrieve_relay(brand_search, coil_voltage_search, model_search, pins_search, current_search):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM relay"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if coil_voltage_search:
        if brand_search :
            query += " AND coil_voltage IN ({})".format(', '.join(['%s'] * len(coil_voltage_search)))
        else:
            query += " WHERE coil_voltage IN ({})".format(', '.join(['%s'] * len(coil_voltage_search)))

        parameters.extend(coil_voltage_search)

    if model_search:
        if brand_search or coil_voltage_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    if pins_search:
        if brand_search or model_search or coil_voltage_search:
            query += " AND pins LIKE '%" + pins_search + "%'"
        else:
            query += " WHERE pins LIKE '%" + pins_search + "%'"


    if current_search:
        current_search_float = float(current_search)
        if brand_search or model_search or pins_search or coil_voltage_search:
            query += " AND current >= %s"
        else:
            query += " WHERE current >= %s"

        parameters.extend([current_search_float])

    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search

#----------------------------------------------------------------------------------------------------

@app.route('/servo_motor',methods=['GET', 'POST'])
def servo_motor():
    brand_search = request.form.getlist('brand_search[]')
    brake_search = request.form.getlist('brake_search[]')
    encoder_search = request.form.getlist('encoder_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    series_search = request.form.get('series_search')
    power_search = request.form.get('power_search')
  
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("series_search: ",series_search)
    #print("power_search: ",power_search)
    #print("brake_search: ",brake_search)
    #print("encoder_search: ",encoder_search)

    filtered_products = retrieve_servo_motor( brake_search, encoder_search, brand_search, 
       model_search, series_search, power_search )
    
    #print("products:", filtered_products)

    return render_template('servo_motor.html', products=filtered_products, selected_brand=selected_dropdown,series_search=series_search)

def retrieve_servo_motor( brake_search, encoder_search, brand_search, 
       model_search, series_search, power_search ):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM servo_motor"
    parameters = []
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)

    if encoder_search:
        if brand_search :
            query += " AND encoder IN ({})".format(', '.join(['%s'] * len(encoder_search)))
        else:
            query += " WHERE encoder IN ({})".format(', '.join(['%s'] * len(encoder_search)))

        parameters.extend(encoder_search)


    if brake_search:
        if brand_search or encoder_search:

            query += " AND brake IN ({})".format(', '.join(['%s'] * len(brake_search)))
        else:
            query += " WHERE brake IN ({})".format(', '.join(['%s'] * len(brake_search)))
        parameters.extend(brake_search)

    if model_search:
        if brand_search or brake_search or encoder_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    if series_search:
        if brand_search or brake_search or encoder_search or model_search:
            query += " AND series LIKE '%" + series_search + "%'"
        else:
            query += " WHERE series LIKE '%" + series_search + "%'"


    if power_search:
        power_search_int = int(power_search)
        if brand_search or brake_search or encoder_search or model_search or series_search:
            query += " AND power >= %s"
        else:
            query += " WHERE power >= %s"

        parameters.extend([power_search_int])

    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search



#================================================================
#product details section
#================================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def create_upload_folder():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


#================================================================

        
def get_product_details(product_type):
    endpoint_name = f"{product_type}_details"

    @app.route(f'/{product_type}_details', methods=['GET', 'POST'], endpoint=endpoint_name)
    def product_details():
        product_id = request.args.get('product_id')
        
        if product_id: 
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            
            cur.execute(f"SELECT * FROM {product_type} WHERE id = %s", (product_id,))
            columns = [column[0] for column in cur.description]
            row = cur.fetchone()
            product = dict(zip(columns, row)) if row else None
            

            if product:
                # Query the settings table to fetch exchange rates for Egypt, Turkey, and UAE
                cur.execute("SELECT country, exchange_rate_usd, exchange_rate_eur FROM setting WHERE country IN ('egypt', 'turkey', 'uae')")
                settings = cur.fetchall()
                exchange_rates = {country: (exchange_rate_usd, exchange_rate_eur) for country, exchange_rate_usd, exchange_rate_eur in settings}


                template_name = f'{product_type}_details.html'
                return render_template(template_name, product=product, exchange_rates=exchange_rates)

    return product_details

product_types = ['plc', 'hmi', 'inverter', 'servo_drive', 'power_supply', 'servo_motor', 'photocell', 'relay', 'servo_accessories']

for product_type in product_types:
    get_product_details(product_type)


#================================================================
#delete product section
#================================================================
def delete_product(table_name):
    endpoint_function_name = f"delete_{table_name}_route"

    @app.route(f'/delete_{table_name}', methods=['POST'], endpoint=endpoint_function_name)
    @login_required
    @role_required(['Admin', 'Moderator'])
    def delete_product_route():
        product_id = request.form.get('product_id')

        if product_id:
            # Retrieve the image filename from the database
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute(f'SELECT product_image FROM {table_name} WHERE id = %s', (product_id,))
            filename = cur.fetchone()[0]

            # Delete the product from the database
            cur.execute(f'DELETE FROM {table_name} WHERE id = %s', (product_id,))
            conn.commit()
            conn.close()

            # Delete the associated image file
            if filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    os.remove(file_path)

        return redirect(url_for(table_name))

delete_product('plc')
delete_product('hmi')
delete_product('inverter')
delete_product('power_supply')
delete_product('servo_drive')
delete_product('servo_motor')
delete_product('relay')
delete_product('photocell')
delete_product('servo_accessories')



#================================================================
#edit product section 
#================================================================
@app.route('/plc_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def plc_edit():
    product_id = request.args.get('product_id')
    filename = None

    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM plc WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        origin = request.form['origin']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        digital_input = int(request.form['digital_input'])
        digital_output = int(request.form['digital_output'])
        analog_input = int(request.form['analog_input'])
        analog_output = int(request.form['analog_output']) 
        selected_checkboxes = request.form.getlist('communication_port_plc')
        communication = '-'.join(selected_checkboxes)
        input_voltage = request.form['power_supply_plc']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)




        cur.execute('''
            UPDATE plc 
            SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    digitalinput=%s,  digitaloutput=%s,  analoginput=%s, 
                    analogoutput=%s,  communication=%s,  inputvoltage=%s,  origin=%s,  product_image=%s
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey, digital_input, digital_output, analog_input, analog_output, communication,input_voltage,origin,filename, product_id))
        conn.commit()

        update_solution_prices(model, end_user_sales_price_egypt)  
        return redirect(url_for('plc'))

    if product_id:
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM plc WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('plc_edit.html', product=product)

        return redirect(url_for('plc'))


#----------------------------------------------------------------------------------------------------------
@app.route('/hmi_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def hmi_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM hmi WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        description = request.form['description']
        size = request.form['size']
        selected_checkboxes = request.form.getlist('communication_port')
        communication = '-'.join(selected_checkboxes)
        input_voltage = request.form['hmi_power_supply']
        origin = request.form['origin']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
           
        

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()

# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)




        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE hmi 
                    
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    size=%s, communication=%s, inputvoltage=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    size,communication,input_voltage,origin,filename, product_id))
        conn.commit()
 
        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('hmi'))
   
    if product_id:
     
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM hmi WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('hmi_edit.html', product=product)

        return redirect(url_for('hmi'))
 
#----------------------------------------------------------------------------------------------------------
@app.route('/inverter_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def inverter_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM inverter WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        description = request.form['description']
        input_voltage = request.form['inverter_power_supply']
        origin = request.form['origin']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        outputpower = float(request.form['inverter_output_power'])
        outputcurrent = float(request.form['inverter_output_current'])
        selected_checkboxes = request.form.getlist('inverter_communication_port')
        communication = '-'.join(selected_checkboxes)
        input_voltage = request.form['inverter_power_supply']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
           
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



        

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE inverter 
                     SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    outputcurrent=%s, outputpower=%s, communication=%s, inputvoltage=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    outputcurrent, outputpower, communication, input_voltage, origin,filename, product_id))  

        conn.commit()
 
        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('inverter'))
   
    if product_id:
     
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM inverter WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('inverter_edit.html', product=product)

        return redirect(url_for('inverter'))
    
#----------------------------------------------------------------------------------------------------------
@app.route('/power_supply_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def power_supply_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM power_supply WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        origin = request.form['origin']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        outputvoltage = request.form['ps_output_voltage']
        outputcurrent = request.form['ps_output_current']
        input_voltage = request.form['ps_power_supply']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
           
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE power_supply 
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                     outputvoltage=%s, outputcurrent=%s, inputvoltage=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    outputvoltage,outputcurrent,input_voltage, origin,filename, product_id))  
        conn.commit()

        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('power_supply'))
   
    if product_id:
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM power_supply WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('power_supply_edit.html', product=product)

        return redirect(url_for('power_supply.html'))

#---------------------------------------------------------------------------------------------------------- 
@app.route('/servo_drive_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def servo_drive_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM servo_drive WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        origin = request.form['origin']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
        
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



       
        #print ("series = ",series)        
        power = float(request.form['power_servo_drive'])
        inputvoltage = request.form['inputvoltage']
        selected_checkboxes = request.form.getlist('control_type')
        control_type = '-'.join(selected_checkboxes)


        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE servo_drive 
                    
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    power=%s, series=%s, inputvoltage=%s, control_type=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    power,series,inputvoltage,control_type, origin,filename, product_id))
           
        conn.commit()
 
        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('servo_drive'))
   
    if product_id:
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM servo_drive WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('servo_drive_edit.html', product=product)

        return redirect(url_for('servo_drive.html'))

#----------------------------------------------------------------------------------------------------------
@app.route('/servo_motor_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def servo_motor_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM servo_motor WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        origin = request.form['origin']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
        
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



        
        
        
        encoder = request.form['encoder']
        brake = request.form['brake']
        power_servo_motor = float(request.form['power_servo_motor'])
   

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE servo_motor 
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    power=%s, series=%s, brake=%s, encoder=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    power_servo_motor,series,brake,encoder, origin,filename, product_id))
        
           
        conn.commit()

        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('servo_motor'))
   
    if product_id:
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM servo_motor WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('servo_motor_edit.html', product=product)

        return redirect(url_for('servo_motor.html'))
     
#---------------------------------------------------------------------------------------------------------- 
@app.route('/relay_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def relay_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM relay WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        origin = request.form['origin']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
        
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



       
        coil_voltage = request.form['coil_voltage']
        pins = request.form['pins']
        base = request.form['base']
        current = float(request.form['current_relay'])
   

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE relay 
                    
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                     coil_voltage=%s, `current`=%s, base=%s, pins=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    coil_voltage,current,base,pins, origin,filename, product_id))
        
           
        conn.commit()
           
 

        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('relay'))
   
    if product_id:
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM relay WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('relay_edit.html', product=product)

        return redirect(url_for('relay.html'))
    


@app.route('/photocell_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def photocell_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM photocell WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        origin = request.form['origin']
        description = request.form['description']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
        
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



        
        photocell_type = request.form['photocell_type']
        photocell_shape = request.form['photocell_shape']
        photocell_size = request.form['photocell_size']
        photocell_connection = request.form['photocell_connection']
        photocell_distance = float(request.form['photocell_distance'])
        output_type = request.form['output_type']
        inputvoltage = request.form['inputvoltage']
   

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE photocell 
                    
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    photocell_type=%s, photocell_shape=%s, photocell_size=%s, photocell_connection=%s, 
                    photocell_distance=%s, output_type=%s, inputvoltage=%s, 
                    origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    photocell_type,photocell_shape,photocell_size,photocell_connection,
                    photocell_distance,output_type,inputvoltage,
                    origin, filename, product_id))
        
           
        conn.commit()
           
 

        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('photocell'))
   
    if product_id:
        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM photocell WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('photocell_edit.html', product=product)

        return redirect(url_for('photocell.html'))
#----------------------------------------------------------------------------------------------------------
@app.route('/servo_accessories_edit', methods=['GET', 'POST'])
@login_required
@role_required(['Admin','Moderator'])
def servo_accessories_edit():
    product_id = request.args.get('product_id')
    
    if request.method == 'POST':
        create_upload_folder()

        # Check which image option is selected
        image_option = request.form.get('image_option')

        if image_option == 'existing':
            # Load existing product data
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute('SELECT * FROM servo_accessories WHERE id = %s', (product_id,))
            product = cur.fetchone()

            # Check if product is not None and has data
            if product:
                # Get the index of the 'product_image' column
                filename_index = None
                for i, column_info in enumerate(cur.description):
                    column_name = column_info[0]
                    if column_name == 'product_image':
                        filename_index = i
                        break

                # Use existing image filename from the database if available
                if filename_index is not None:
                    filename = product[filename_index]
                else:
                    # Handle the case when the 'product_image' column is not found
                    # This could be due to a change in the database schema
                    filename = None

        else:
            # Handle file upload for new image
            if 'product_image' in request.files:
                file = request.files['product_image']
                if file.filename != '' and allowed_file(file.filename):
                    # Rename the file as the model
                    filename = secure_filename(request.form['model'] + os.path.splitext(file.filename)[1])
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
            else:
                # Handle case where no file is uploaded
                filename = None

        brand = request.form['brand']
        series = request.form['series']
        model = request.form['model']
        description = request.form['description']
        accessory_type = request.form['servo_accessory_type']
        cable_length = float(request.form['servo_cable_length'])
        origin = request.form['origin']
        purchase_price = float(request.form['purchase_price'])
        currency = request.form['currency_edit']
        cost_factor_edit_egypt = float(request.form['cost_factor_egypt'])
        cost_factor_edit_uae = float(request.form['cost_factor_uae'])
        cost_factor_edit_turkey = float(request.form['cost_factor_turkey'])
        quantity_egypt = request.form['quantity_egypt']
        quantity_uae = request.form['quantity_uae']
        quantity_turkey = request.form['quantity_turkey']
           
# Calculate sales prices for the product
        (
            cost_price_egypt, cost_price_uae, cost_price_turkey,
            distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
            end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
        ) = calculate_product_price(db_config, currency, purchase_price, 
                                    {'egypt': cost_factor_edit_egypt, 
                                    'uae': cost_factor_edit_uae, 
                                    'turkey': cost_factor_edit_turkey})
       #            #print the calculated values
        #print("Cost Prices:")
        #print("Egypt:", cost_price_egypt)
        #print("UAE:", cost_price_uae)
        #print("Turkey:", cost_price_turkey)

        #print("\nDistributor Sales Prices:")
        #print("Egypt:", distributor_sales_price_egypt)
        #print("UAE:", distributor_sales_price_uae)
        #print("Turkey:", distributor_sales_price_turkey)

        #print("\nEnd User Sales Prices:")
        #print("Egypt:", end_user_sales_price_egypt)
        #print("UAE:", end_user_sales_price_uae)
        #print("Turkey:", end_user_sales_price_turkey)



        
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
    
        cur.execute('''
            UPDATE servo_accessories 
                    
                    SET brand=%s, series=%s,  model=%s,  description=%s,  purchase_price=%s,  currency=%s, 
                    end_user_sales_price_egypt=%s,  end_user_sales_price_uae=%s,  end_user_sales_price_turkey=%s, 
                    distributor_sales_price_egypt=%s,  distributor_sales_price_uae=%s,  distributor_sales_price_turkey=%s, 
                    cost_factor_egypt=%s,  cost_factor_uae=%s,  cost_factor_turkey=%s, 
                    cost_price_egypt=%s,  cost_price_uae=%s,  cost_price_turkey=%s, 
                    quantity_egypt=%s,  quantity_uae=%s,  quantity_turkey=%s, 
                    accessory_type=%s, cable_length=%s, origin=%s , product_image=%s 
 
            WHERE id=%s
        ''', (brand, series, model, description, purchase_price, currency,
                    end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey, 
                    distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey, 
                    cost_factor_edit_egypt, cost_factor_edit_uae, cost_factor_edit_turkey, cost_price_egypt, cost_price_uae, cost_price_turkey,
                    quantity_egypt, quantity_uae, quantity_turkey,
                    accessory_type, cable_length, origin,filename, product_id))
                   
        conn.commit()

        update_solution_prices(model, end_user_sales_price_egypt) 
        return redirect(url_for('servo_accessories'))
   
    if product_id:
     
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM servo_accessories WHERE id = %s', (product_id,))
        columns = [column[0] for column in cur.description]
        row = cur.fetchone()
        product = dict(zip(columns, row)) if row else None

        if product:
            return render_template('servo_accessories_edit.html', product=product)

        return redirect(url_for('servo_accessories'))

#================================================================
#setting section
#================================================================
 

# Define db_config dictionary
db_config = {
    'host': 'localhost',
    'user': 'emtecheg_emroot',
    'password': 'Ms~l-IahD5kq',
    'database': 'emtecheg_emtech_products',
}

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@role_required(['Admin', 'Moderator'])
def settings():
    # If it's a POST request, update settings based on form data
    if request.method == 'POST':
        update_settings(request.form, db_config)
        update_all_categories()  
# Call update_all_categories instead    # Retrieve settings for specific countries from the database
    settings = get_settings(['Egypt', 'UAE', 'Turkey'], db_config)
    # Render the 'settings.html' template with the retrieved settings
    return render_template('settings.html', settings=settings)

# Function to retrieve settings for specific countries from the database
def get_settings(countries, db_config):
    settings = {}
     # Establish a connection to the database
    with mysql.connector.connect(**db_config) as conn:
            cur = conn.cursor(dictionary=True)
            # Iterate over each country
            for country in countries:
                cur.execute("SELECT exchange_rate_usd, exchange_rate_eur, end_user_profit_rate, distributor_profit_rate FROM setting WHERE country = %s", (country,))
                result = cur.fetchone()
                settings[country] = result if result else {'exchange_rate_usd': None, 'exchange_rate_eur': None, 'end_user_profit_rate': None, 'distributor_profit_rate': None}
    return settings

# Function to update settings in the database based on form data
def update_settings(form_data, db_config):
    with mysql.connector.connect(**db_config) as conn:
            cur = conn.cursor()
            for country in ['Egypt', 'UAE', 'Turkey']:
                exchange_rate_usd = float(form_data[f'exchange_rate_usd_{country.lower()}'])
                exchange_rate_eur = float(form_data[f'exchange_rate_eur_{country.lower()}'])
                end_user_profit_rate = float(form_data[f'end_user_profit_rate_{country.lower()}'])
                distributor_profit_rate = float(form_data[f'distributor_profit_rate_{country.lower()}'])

                cur.execute('''
                    UPDATE setting 
                    SET exchange_rate_usd=%s, exchange_rate_eur=%s, end_user_profit_rate=%s, distributor_profit_rate=%s
                    WHERE country=%s
                ''', (exchange_rate_usd, exchange_rate_eur, end_user_profit_rate, distributor_profit_rate, country))
                conn.commit()

# Function to retrieve exchange rates for specific currencies and countries from the database
def get_exchange_rates(currency, db_config):
    with mysql.connector.connect(**db_config) as conn:
            cur = conn.cursor()
            # Modify the SQL query to fetch all rows without filtering by currency
            cur.execute("SELECT country, exchange_rate_usd, exchange_rate_eur, end_user_profit_rate, distributor_profit_rate FROM setting")
            results = cur.fetchall()
            #print("Query executed successfully.")
            #print("Results:", results)
        # Construct a dictionary of exchange rates using country as the key
    exchange_rates = {}
    for row in results:
        country, exchange_rate_usd, exchange_rate_eur, end_user_profit_rate, distributor_profit_rate = row
        exchange_rates[country] = (exchange_rate_usd, exchange_rate_eur, end_user_profit_rate, distributor_profit_rate)
    #print("Exchange rates:", exchange_rates)
    return exchange_rates
  
    
# Function to calculate sales prices based on purchase price, cost factor, and exchange rates
def calculate_sales_prices(purchase_price, cost_factor, exchange_rate_usd, exchange_rate_eur, distributor_profit_rate, end_user_profit_rate):
    cost_price = Decimal(str(purchase_price)) * Decimal(str(cost_factor)) * Decimal(str(exchange_rate_usd))
    distributor_sales_price = cost_price * Decimal(str(distributor_profit_rate))
    end_user_sales_price = cost_price * Decimal(str(end_user_profit_rate))
    return distributor_sales_price, end_user_sales_price, cost_price


def calculate_product_price(db_config, currency, purchase_price, cost_factors):
    exchange_rates = get_exchange_rates(currency, db_config)
    
    distributor_sales_prices = {}
    end_user_sales_prices = {}
    cost_prices = {}

    for country, rates in exchange_rates.items():
        if rates is None:
            distributor_sales_prices[country.lower()] = 0
            end_user_sales_prices[country.lower()] = 0
            cost_prices[country.lower()] = 0
            continue
        
        exchange_rate_usd, exchange_rate_eur, end_user_profit_rate, distributor_profit_rate = rates
        
        cost_factor = cost_factors.get(country.lower(), None)
        if cost_factor is None:
            raise ValueError(f"Cost factor not provided for country: {country}")

        if currency.lower() == 'usd':
            exchange_rate = exchange_rate_usd
        elif currency.lower() == 'eur':
            exchange_rate = exchange_rate_eur
        else:
            raise ValueError("Invalid currency selected")

        distributor_sales_price, end_user_sales_price, cost_price = calculate_sales_prices(
            purchase_price, cost_factor, exchange_rate, exchange_rate, distributor_profit_rate, end_user_profit_rate)
        
        distributor_sales_prices[country.lower()] = distributor_sales_price
        end_user_sales_prices[country.lower()] = end_user_sales_price
        cost_prices[country.lower()] = cost_price

    return (
        cost_prices.get('egypt', 0), cost_prices.get('uae', 0), cost_prices.get('turkey', 0),
        distributor_sales_prices.get('egypt', 0), distributor_sales_prices.get('uae', 0), distributor_sales_prices.get('turkey', 0),
        end_user_sales_prices.get('egypt', 0), end_user_sales_prices.get('uae', 0), end_user_sales_prices.get('turkey', 0)
    )


def update_all_categories():
    categories = ['hmi' , 'plc', 'inverter', 'power_supply', 'photocell', 'relay', 'servo_accessories', 'servo_drive', 'servo_motor']

    for category in categories:
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM {category}")
        products = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
        update_product_price(category, products)
        cur.close()
        conn.close()
#-----------------------------------------------------------------------
        
def update_product_price(table_name, products):
    # Update sale prices for each product
    #print("products = ", products)

    for product in products:
        purchase_price = product.get('purchase_price')
        currency = product.get('currency')
        
        # Retrieve cost factors for each country
        cost_factor_egypt = product.get('cost_factor_egypt')
        cost_factor_uae = product.get('cost_factor_uae')
        cost_factor_turkey = product.get('cost_factor_turkey')

        # Check if essential keys exist in the product dictionary
        if None in [purchase_price, currency, cost_factor_egypt, cost_factor_uae, cost_factor_turkey]:
            #print("Skipping product update. Essential data missing.")
            continue
        
        db_config = {
            'host': 'localhost',
            'user': 'emtecheg_emroot',
            'password': 'Ms~l-IahD5kq',
            'database': 'emtecheg_emtech_products',
        }


        (
                cost_price_egypt, cost_price_uae, cost_price_turkey,
                distributor_sales_price_egypt, distributor_sales_price_uae, distributor_sales_price_turkey,
                end_user_sales_price_egypt, end_user_sales_price_uae, end_user_sales_price_turkey
            ) = calculate_product_price(db_config, currency, purchase_price, {
                'egypt': cost_factor_egypt,
                'uae': cost_factor_uae,
                'turkey': cost_factor_turkey
            })

            # Update the sales price in the database
        cur.execute(f'''
                UPDATE {table_name}
                SET end_user_sales_price_egypt=%s, distributor_sales_price_egypt=%s, cost_price_egypt=%s,
                    end_user_sales_price_uae=%s, distributor_sales_price_uae=%s, cost_price_uae=%s,
                    end_user_sales_price_turkey=%s, distributor_sales_price_turkey=%s, cost_price_turkey=%s
                WHERE id=%s
            ''', (end_user_sales_price_egypt, distributor_sales_price_egypt, cost_price_egypt,
                  end_user_sales_price_uae, distributor_sales_price_uae, cost_price_uae,
                  end_user_sales_price_turkey, distributor_sales_price_turkey, cost_price_turkey,
                  product['id']))
        conn.commit()

            # Check if model in solutions_products and update it
        model = product.get('model')
        if model:
            update_solution_prices(model, end_user_sales_price_egypt)  # For simplicity, using Egypt's sales price


#-----------------------------------------------------------------------
@app.route("/products.html")
def products():
    return render_template("products.html",title="Products")
#----------------------------------------------------------------------------------------------------
@app.route("/contact.html")
def contact():
    return render_template("contact.html",title="contact")
#-----------------------------------------------------------------------
@app.route("/automation_system.html")
def automation_system():
    return render_template("automation_system.html",title="Automation System")
#================================================================
@app.route("/plc_product.html")
def plc_product():
    return render_template("plc_product.html",title="PLC Product")
#================================================


@app.route('/plc_table.html', methods=['GET', 'POST'])
def plc_table():
    
    brand_search = request.form.getlist('brand_search[]')
    series_search = request.form.getlist('series_search[]')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    communication_search = request.form.getlist('communication_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    digital_input_search = request.form.get('digital_input_search')
    digital_output_search = request.form.get('digital_output_search')
    analog_input_search = request.form.get('analog_input_search')
    analog_output_search = request.form.get('analog_output_search')
  
    filtered_products = retrieve_dataplc_table(brand_search, series_search, input_voltage_search, communication_search, model_search, 
                   digital_input_search, digital_output_search, analog_input_search, 
                   analog_output_search)
    
    return render_template('plc_table.html', products=filtered_products, selected_brand=selected_dropdown,digital_input_search=digital_input_search,product=product)

def retrieve_dataplc_table(brand_search, series_search, input_voltage_search, communication_search, model_search, 
                   digital_input_search, digital_output_search, analog_input_search, 
                   analog_output_search):
  
    query = "SELECT * FROM plc"
    parameters = []
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)

    if series_search:
        if brand_search:
             query += " AND series IN ({})".format(', '.join(['%s'] * len(series_search)))
        else:
             query += " WHERE series IN ({})".format(', '.join(['%s'] * len(series_search)))
        parameters.extend(series_search)

    if input_voltage_search:
        if brand_search or series_search:
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    if communication_search:
        if brand_search or series_search or input_voltage_search :
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " AND (" + " AND ".join(communication_conditions) + ")"
            query += communication_query
        else:
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " WHERE (" + " AND ".join(communication_conditions) + ")"
            query += communication_query

    if model_search:
        if brand_search or series_search or input_voltage_search or communication_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
  
    if digital_input_search:
        digital_input_search_int = int(digital_input_search)
        if brand_search or series_search or model_search or input_voltage_search or communication_search:
            query += " AND digitalinput >= %s"
        else:
            query += " WHERE digitalinput >= %s"

        parameters.extend([digital_input_search_int])

    if digital_output_search:
        digital_output_search_int = int(digital_output_search)
        if brand_search or series_search or model_search or digital_input_search or input_voltage_search or communication_search:
            query += " AND digitaloutput >= %s"
        else:
            query += " WHERE digitaloutput >= %s"

        parameters.extend([digital_output_search_int])

    if analog_input_search:
        analog_input_search_int = int(analog_input_search)
        if brand_search or series_search or model_search or digital_input_search or digital_output_search or input_voltage_search or communication_search:
            query += " AND analoginput >= %s"
        else:
            query += " WHERE analoginput >= %s"

        parameters.extend([analog_input_search_int])

    if analog_output_search:
        analog_output_search_int = int(analog_output_search)
        if brand_search or series_search or  model_search or digital_input_search or digital_output_search or analog_input_search or input_voltage_search or communication_search:
            query += " AND analogoutput >= %s"
        else:
            query += " WHERE analogoutput >= %s"
    
        parameters.extend([analog_output_search_int])

    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute(query, parameters)

    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
  
    return products_search
# -----------------------------------
@app.route('/hmi_table.html', methods=['GET', 'POST'])
def hmi_table():
    
   
    brand_search = request.form.getlist('brand_search_hmi[]')
    
    size_search = request.form.getlist('size_search_hmi[]')
    input_voltage_search = request.form.getlist('input_voltage_search_hmi[]')
    communication_search = request.form.getlist('communication_search_hmi[]')

    model_search = request.form.get('model_search_hmi')

    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("size_search: ",size_search)
    #print("input_voltage_search: ",input_voltage_search)
    #print("communication_search: ",communication_search)

    filtered_products = retrieve_hmi_productsz(brand_search, model_search, size_search, input_voltage_search, communication_search)
    
    #print("products:", filtered_products)

    return render_template('hmi_table.html', products=filtered_products)

def retrieve_hmi_productsz(brand_search, model_search, size_search, input_voltage_search, communication_search):
    
    # Initialize an empty list to store the results
    rows = []

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM hmi"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    # Add more conditions for other filters (communication, model, etc.)
    if communication_search:
        if brand_search or input_voltage_search :
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " AND (" + " AND ".join(communication_conditions) + ")"
            query += communication_query
        else:
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " WHERE (" + " AND ".join(communication_conditions) + ")"
            query += communication_query

    if model_search:
        # Adjust this condition based on your actual model storage and comparison logic
        if brand_search or input_voltage_search or communication_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
        #parameters.extend([model_search])

    if size_search:
        if brand_search or model_search or input_voltage_search or communication_search :
            query += " AND size IN ({})".format(', '.join(['%s'] * len(size_search)))
        else:
            query += " WHERE size IN ({})".format(', '.join(['%s'] * len(size_search)))

        parameters.extend(size_search)
    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return products_search
# ----------------------------------
@app.route('/Inverter_table.html', methods=['GET', 'POST'])
def Inverter_table():
    
    # Get form data
    brand_search = request.form.getlist('brand_search[]')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    communication_search = request.form.getlist('communication_search[]')
    model_search = request.form.get('model_search')
    out_current_search = request.form.get('out_current_search')
    out_power_search = request.form.get('out_power_search')
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("out_current_search: ",out_current_search)
    #print("out_power_search: ",out_power_search)
    
    #print("input_voltage_search: ",input_voltage_search)
    #print("communication_search: ",communication_search)
    filtered_products = retrieve_inverter_productsz(brand_search, input_voltage_search, communication_search, model_search, 
                   out_current_search, out_power_search)
    
    #print("products:", filtered_products)

    return render_template('Inverter_table.html', products=filtered_products)

def retrieve_inverter_productsz(brand_search, input_voltage_search, communication_search, model_search, 
                   out_current_search, out_power_search):
    # Initialize an empty list to store the results
    rows = []

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM inverter"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)

    # Add more conditions for other filters (communication, model, etc.)
    if communication_search:
        if brand_search or input_voltage_search :
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " AND (" + " AND ".join(communication_conditions) + ")"
            query += communication_query
        else:
            communication_conditions = []
            for comm_value in communication_search:
                comm_conditions = [f"communication LIKE %s"] * len(comm_value.split('-'))
                communication_conditions.append("(" + " AND ".join(comm_conditions) + ")")

                for comm_part in comm_value.split('-'):
                    parameters.extend([f'%{comm_part}%'])

            communication_query = " WHERE (" + " AND ".join(communication_conditions) + ")"
            query += communication_query

    """
    if communication_search:
        if brand_search or input_voltage_search :
            query += " AND CAST(communication AS NVARCHAR(MAX)) LIKE ({})".format(', '.join(['%s'] * len(communication_search)))
        else:
            query += " WHERE CAST(communication AS NVARCHAR(MAX)) LIKE ({})".format(', '.join(['%s'] * len(communication_search)))

        parameters.extend(communication_search)
    """
    if model_search:
        # Adjust this condition based on your actual model storage and comparison logic
        if brand_search or input_voltage_search or communication_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
        #parameters.extend([model_search])

    if out_current_search:
        if brand_search or model_search or input_voltage_search or communication_search:
            query += " AND outputcurrent = %s"
        else:
            query += " WHERE outputcurrent = %s"

        parameters.extend([out_current_search])

    if out_power_search:
        if brand_search or model_search or out_current_search or input_voltage_search or communication_search:
            query += " AND outputpower = %s"
        else:
            query += " WHERE outputpower = %s"

        parameters.extend([out_power_search])

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return products_search
# ------------------------------------------
@app.route('/power_supply_table.html', methods=['GET', 'POST'])
def power_supply_table():
    
   # Get form data
    brand_search = request.form.getlist('brand_search[]')
    model_search = request.form.get('model_search')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    out_voltage_search = request.form.getlist('out_voltage_search[]')
    out_current_search = request.form.getlist('out_current_search[]')
    
    filtered_products = retrieve_power_supplyz(brand_search, input_voltage_search, model_search, out_current_search, out_voltage_search)
    
    return render_template('power_supply_table.html', products=filtered_products)

def retrieve_power_supplyz(brand_search, input_voltage_search, model_search, out_current_search, out_voltage_search):
    # Initialize an empty list to store the results
    rows = []

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM power_supply"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    
    # Build the WHERE clause based on the selected input voltage values    
    if input_voltage_search:
        if brand_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)


    if model_search:
        # Adjust this condition based on your actual model storage and comparison logic
        if brand_search or input_voltage_search :
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"
        #parameters.extend([model_search])

    

    if out_current_search:
        if brand_search or model_search or input_voltage_search:
            query += " AND outputcurrent IN ({})".format(', '.join(['%s'] * len(out_current_search)))
        else:
            query += " WHERE outputcurrent IN ({})".format(', '.join(['%s'] * len(out_current_search)))

        parameters.extend(out_current_search)

    if out_voltage_search:
        if brand_search or model_search or out_current_search or input_voltage_search:
            query += " AND outputvoltage IN ({})".format(', '.join(['%s'] * len(out_voltage_search)))
        else:
            query += " WHERE outputvoltage IN ({})".format(', '.join(['%s'] * len(out_voltage_search)))

        parameters.extend(out_voltage_search)

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]


    return products_search
# ------------------------------------------
@app.route('/relay_table.html', methods=['GET', 'POST'])
def relay_table():
     
    brand_search = request.form.getlist('brand_search[]')
    coil_voltage_search = request.form.getlist('coil_voltage_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    pins_search = request.form.get('pins_search')
    current_search = request.form.get('current_search')
  
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("pins_search: ",pins_search)
    #print("current_search: ",current_search)
    #print("coil_voltage_search: ",coil_voltage_search)

    filtered_products = retrieve_relayz(brand_search, coil_voltage_search, model_search, pins_search, current_search )
    
    #print("products:", filtered_products)

    return render_template('relay_table.html', products=filtered_products, selected_brand=selected_dropdown)

def retrieve_relayz(brand_search, coil_voltage_search, model_search, pins_search, current_search):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM relay"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand
    if brand_search:

        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    # Build the WHERE clause based on the selected input voltage values
    if coil_voltage_search:
        if brand_search :
            query += " AND coil_voltage IN ({})".format(', '.join(['%s'] * len(coil_voltage_search)))
        else:
            query += " WHERE coil_voltage IN ({})".format(', '.join(['%s'] * len(coil_voltage_search)))

        parameters.extend(coil_voltage_search)

    if model_search:
        if brand_search or coil_voltage_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    if pins_search:
        if brand_search or model_search or coil_voltage_search:
            query += " AND pins LIKE '%" + pins_search + "%'"
        else:
            query += " WHERE pins LIKE '%" + pins_search + "%'"


    if current_search:
        current_search_float = float(current_search)
        if brand_search or model_search or pins_search or coil_voltage_search:
            query += " AND current >= %s"
        else:
            query += " WHERE current >= %s"

        parameters.extend([current_search_float])

    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search
# ------------------------------------------
@app.route('/photocell_table.html', methods=['GET', 'POST'])
def photocell_table():

    brand_search = request.form.getlist('brand_search[]')
    selected_dropdown = request.form.get('selected_dropdown')
    model_search = request.form.get('model_search')
    sensing_distance_search = request.form.get('sensing_distance_search')
    input_voltage_search = request.form.getlist('input_voltage_search[]')
    output_type_search = request.form.getlist('output_type_search[]')
    shape_search = request.form.getlist('shape_search[]')
    connection_search = request.form.getlist('connection_search[]')
    type_search = request.form.getlist('type_search[]')
 
    #print("brand_search: ",brand_search)
    #print("model_search: ",model_search)
    #print("sensing_distance_search: ",sensing_distance_search)
    #print("input_voltage_search: ",input_voltage_search)
    #print("output_type_search: ",output_type_search)
    #print("shape_search: ",shape_search)
    #print("connection_search: ",connection_search)
    #print("type_search: ",type_search)

   

    filtered_products = retrieve_photocellz(brand_search, model_search, sensing_distance_search, input_voltage_search, output_type_search, shape_search, connection_search, type_search)
    
    #print("products:", filtered_products)

    return render_template('photocell_table.html', products=filtered_products)

def retrieve_photocellz(brand_search, model_search, sensing_distance_search, input_voltage_search, output_type_search, shape_search, connection_search, type_search):

    # Build the SQL query with a parameterized WHERE clause
    query = "SELECT * FROM photocell"
    parameters = []
    # Build the WHERE clause based on the selected checkboxes for brand

    #1
    if brand_search:
        query += " WHERE brand IN ({})".format(', '.join(['%s'] * len(brand_search)))
        parameters.extend(brand_search)
    
    #2
    if model_search:
        if brand_search:
            query += " AND model LIKE '%" + model_search + "%'"
        else:
            query += " WHERE model LIKE '%" + model_search + "%'"

    #3
    if sensing_distance_search:
        photocell_distance_int = float(sensing_distance_search)
        if brand_search or model_search:
            query += " AND photocell_distance >= %s"
        else:
            query += " WHERE photocell_distance >= %s"
        parameters.extend([photocell_distance_int])


    #4
    if input_voltage_search:
        if brand_search or model_search or sensing_distance_search :
            query += " AND inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))
        else:
            query += " WHERE inputvoltage IN ({})".format(', '.join(['%s'] * len(input_voltage_search)))

        parameters.extend(input_voltage_search)


    

    #5
    if output_type_search:
        if brand_search or model_search or sensing_distance_search or input_voltage_search :
            query += " AND output_type IN ({})".format(', '.join(['%s'] * len(output_type_search)))
        else:
            query += " WHERE output_type IN ({})".format(', '.join(['%s'] * len(output_type_search)))
        parameters.extend(output_type_search)

    #6   
    if shape_search:
        if brand_search or model_search or sensing_distance_search or output_type_search or output_type_search :
            query += " AND photocell_shape IN ({})".format(', '.join(['%s'] * len(shape_search)))
        else:
            query += " WHERE photocell_shape IN ({})".format(', '.join(['%s'] * len(shape_search)))
        parameters.extend(shape_search)

    
    
    #7
    if connection_search:
        if brand_search or model_search or sensing_distance_search or output_type_search or output_type_search or shape_search:
            query += " AND photocell_connection IN ({})".format(', '.join(['%s'] * len(connection_search)))
        else:
            query += " WHERE photocell_connection IN ({})".format(', '.join(['%s'] * len(connection_search)))

        parameters.extend(connection_search)
    #8
        
    if type_search:
        if brand_search or model_search or sensing_distance_search or output_type_search or output_type_search or shape_search or connection_search:
            query += " AND photocell_type IN ({})".format(', '.join(['%s'] * len(type_search)))
        else:
            query += " WHERE photocell_type IN ({})".format(', '.join(['%s'] * len(type_search)))
        parameters.extend(type_search)
    

    # Execute the query with the list of parameters
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    #print("Generated SQL query:", query)
    #print("query type:", type(query))
    #print("Provided parameters:", parameters)
    cur.execute(query, parameters)

    #rows = cur.fetchall()
    products_search = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    #print("searched_productes:", products_search)

    return products_search
   
   

"""
@app.route("/plc_table.html")
def table_plc():
    return render_template("plc_table.html",title="PLC Details",product=product)
"""
#================================================
@app.route("/hmi_product.html")
def hmi_product():
    return render_template("hmi_product.html",title="HMI Product")
#=====================================================
@app.route("/servo_system.html")
def servo_system():
    return render_template("servo_system.html",title="Servo System")
#=====================================================
@app.route("/servo_drives.html")
def servo_drives():
    return render_template("servo_drives.html",title="Servo Drives")
#=====================================================
@app.route("/servo_motors.html")
def servo_motors():
    return render_template("servo_motors.html",title="Servo Motors")
#=====================================================
@app.route("/accessories.html")
def accessories():
    return render_template("accessories.html",title="Servo Accessories")
#=====================================================
@app.route("/external.html")
def external():
    return render_template("external.html",title="External")
#=====================================================
@app.route("/motion_controllers.html")
def motion_controllers():
    return render_template("motion_controllers.html",title="Motion Controllers")
#=====================================================
@app.route("/motionanddrives.html")
def motionanddrives():
    return render_template("motionanddrives.html",title="Motion & Drives")
#=====================================================
@app.route("/sensing.html")
def sensing():
    return render_template("sensing.html",title="Sensing")
#=====================================================
@app.route("/controlcomponents.html")
def controlcomponents():
    return render_template("controlcomponents.html",title="Control Components")
#=====================================================
@app.route("/inverters.html")
def inverters():
    return render_template("inverters.html",title="Inverters")
#=====================================================
@app.route("/power_supplies.html")
def power_supplies():
    return render_template("power_supplies.html",title="Power Supply")
#=====================================================
@app.route("/CP2E-S60DT1-D.html")
def CP2E_S60DT1_D():
    return render_template("CP2E-S60DT1-D.html", title="CP2E-S60DT1-D")
#================================================================================
@app.route("/solid_state_relay.html")
def solid_state_relay():
    return render_template("solid_state_relay.html" , title="Solid State Relay")
#================================================================================
@app.route("/phottocell.html")
def phottocell():
    return render_template("phottocell.html" , title="Photocell")
#================================================================================
@app.route("/rellay.html")
def rellay():
    return render_template("rellay.html" , title="Relay")
#===================================================================================
# @app.route("/hmi_table.html")
# def hmi_table():
#     return render_template("hmi_table.html" , title="hmi Table")
#===================================================================================
@app.route("/CP2E-S40DT1-D.html")
def CP2E_S40DT1_D():
    return render_template("CP2E-S40DT1-D.html", title="CP2E-S40DT1-D")
#================================================================================
@app.route("/CP2E-S60DT-D.html")
def CP2E_S60DT_D():
    return render_template("CP2E-S60DT-D.html", title="CP2E-S60DT-D")
#================================================================================
@app.route("/CP2E-S40DR-A.html")
def CP2E_S40DR_A():
    return render_template("CP2E-S40DR-A.html", title="CP2E-S40DR-A")
#================================================================================
@app.route("/CP2E-N40DR-A.html")
def CP2E_N40DR_A():
    return render_template("CP2E-N40DR-A.html", title="CP2E-N40DR-A")
#================================================================================
@app.route("/CP2E-N40DT1-D.html")
def CP2E_N40DT1_D():
    return render_template("CP2E-N40DT1-D.html", title="CP2E-N40DT1-D")
#===============================================================================
@app.route("/CP2E-N20DRA.html")
def CP2E_N20DRA():
    return render_template("CP2E-N20DRA.html", title="CP2E-N20DRA")
#==============================================================================
@app.route("/CP2E-S30DT1-D.html")
def CP2E_S30DT1_D():
    return render_template("CP2E-S30DT1-D.html", title="CP2E-S30DT1-D")
#=============================================================================
@app.route("/CP2E-S30DR-A.html")
def CP2E_S30DR_A():
    return render_template("CP2E-S30DR-A.html", title="CP2E-S30DR-A")
#============================================================================
@app.route("/CP2E-S60DRA.html")
def CP2E_S60DRA():
    return render_template("CP2E-S60DRA.html", title="CP2E-S60DRA")
#===========================================================================
@app.route("/GMT_1518T.html")
def GMT_1518T():
    return render_template("GMT_1518T.html", title="GMT_1518T")
#=========================================================================
@app.route("/NB7W-TW01B.html")
def NB7W_TW01B():
    return render_template("NB7W-TW01B.html", title="NB7W-TW01B")
#========================================================================
@app.route("/NB10W-TW01B.html")
def NB10W_TW01B():
    return render_template("NB10W-TW01B.html", title="NB10W-TW01B")
#=======================================================================
@app.route("/NB7W-TW00B.html")
def NB7W_TW00B():
    return render_template("NB7W-TW00B.html", title="NB7W-TW00B")
#======================================================================
@app.route("/GS2110-WTBD-N.html")
def GS2110_WTBD_N():
    return render_template("GS2110-WTBD-N.html", title="GS2110-WTBD-N")
#===========================================================================
@app.route("/GS2107-WTBD-N.html")
def GS2107_WTBD_N():
    return render_template("GS2107-WTBD-N.html", title="GS2107-WTBD-N")
#============================================================================
@app.route("/G3NA-250B-UTU DC5-24 BY OMZ.html")
def G3NA_250B_UTU_DC5_24_BY_OMZ():
    return render_template("G3NA-250B-UTU DC5-24 BY OMZ.html", title="G3NA-250B-UTU DC5-24 BY OMZ")
#=====================================================================================================
@app.route("/G3NA-225B-UTU DC5-24 BY OMZ.html")
def G3NA_225B_UTU_DC5_24_BY_OMZ():
    return render_template("G3NA-225B-UTU DC5-24 BY OMZ.html", title="G3NA-225B-UTU DC5-24 BY OMZ")
#====================================================================================================
@app.route("/G3PA-240B-VD 5-24VDC.html")
def G3PA_240B_VD_5_24VDC():
    return render_template("G3PA-240B-VD 5-24VDC.html", title="G3PA-240B-VD 5-24VDC")
#====================================================================================================
@app.route("/G3NA-220B-UTU 100-240VAC.html")
def G3NA_220B_UTU_100_240VAC():
    return render_template("G3NA-220B-UTU 100-240VAC.html", title="G3NA-220B-UTU 100-240VAC")
#===================================================================================================
@app.route("/S8VK-C06024.html")
def S8VK_C06024():
    return render_template("S8VK-C06024.html", title="S8VK-C06024")
#==================================================================================================
@app.route("/S8VK-C12024.html")
def S8VK_C12024():
    return render_template("S8VK-C12024.html", title="S8VK-C12024")
#=================================================================================================
@app.route("/S8VK-C24024.html")
def S8VK_C24024():
    return render_template("S8VK-C24024.html", title="S8VK-C24024")
#================================================================================================
@app.route("/S8VK-C48024.html")
def S8VK_C48024():
    return render_template("S8VK-C48024.html", title="S8VK-C48024")
#================================================================================================
@app.route("/EPS60.html")
def EPS60():
    return render_template("EPS60.html", title="EPS60")
#===============================================================================================	
@app.route("/S8VK-T24024.html")
def S8VK_T24024():
    return render_template("S8VK-T24024.html", title="S8VK-T24024")
#===============================================================================================
@app.route("/S8VK-T48024.html")
def S8VK_T48024():
    return render_template("S8VK-T48024.html", title="S8VK-T48024")
#==============================================================================================
@app.route("/CP1W-20EDR1.html")
def CP1W_20EDR1():
    return render_template("CP1W-20EDR1.html", title="CP1W-20EDR1")
#=============================================================================================
@app.route("/CP1W-20EDT1.html")
def CP1W_20EDT1():
    return render_template("CP1W-20EDT1.html", title="CP1W-20EDT1")
#=========================================================================================
@app.route("/CP1W-TS003.html")
def CP1W_TS003():
    return render_template("CP1W-TS003.html", title="CP1W-TS003")
#====================================================================================
@app.route("/CP1W-40EDR.html")
def CP1W_40EDR():
    return render_template("CP1W-40EDR.html", title="CP1W-40EDR")
#==============================================================================
@app.route("/CP1W-40EDT1.html")
def CP1W_40EDT1():
    return render_template("CP1W-40EDT1.html", title="CP1W-40EDT1")
#=======================================================================
@app.route("/CP1W-8ED.html")
def CP1W_8ED():
    return render_template("CP1W-8ED.html", title="CP1W-8ED")
#=====================================================================
@app.route("/CP1W-8ER.html")
def CP1W_8ER():
    return render_template("CP1W-8ER.html", title="CP1W-8ER")
#=================================================================
@app.route("/CP1W-8ET1.html")
def CP1W_8ET1():
    return render_template("CP1W-8ET1.html", title="CP1W-8ET1")
#==================================================================
@app.route("/CP1W-DA042.html")
def CP1W_DA042():
    return render_template("CP1W-DA042.html", title="CP1W-DA042")
#===================================================================
@app.route("/CP1W-AD042.html")
def CP1W_AD042():
    return render_template("CP1W-AD042.html", title="CP1W-AD042")
#==================================================================
@app.route("/details_estimate.html")
def details_estimate():
   
    cur.execute('SELECT * FROM estimates')
    columns = [column[0] for column in cur.description]
    estimates = [dict(zip(columns, row)) for row in cur.fetchall()]
     
    return render_template("details_estimate.html", title="details_estimate" ,estimates = estimates)
#==================================================================
#app run section
#================================================================

if __name__ == '__main__':
    app.run(host=IPAddr, port=8888, debug=True, threaded=True)

    

try:
    #print("code")
    fwef = True

except KeyboardInterrupt:
    #print("Script terminated by user")
    sdf = False

finally:
    

    #Disconnect from SQL Server
    cur.close()
    conn.close()