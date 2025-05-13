from flask import Flask, render_template, current_app, get_flashed_messages, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import uuid
from datetime import datetime
from dotenv import load_dotenv
from types import SimpleNamespace
from sqlalchemy.sql import text
import logging
import hashlib
import json
import traceback
import subprocess
from logging.handlers import RotatingFileHandler
from concurrent_log_handler import ConcurrentRotatingFileHandler
import builtins
import jinja2.utils
from jinja2 import Template

load_dotenv()
from Config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)


app.jinja_env.globals.update(os=os)
app.jinja_env.globals.update(subprocess=subprocess)

EVENT_CODES = {
    "application_start": "1001",
    "user_login_attempt": "1002",
    "user_registration_attempt": "1003",
    "user_data_leak_warning": "1004",
    "registration_error": "1005",
    "registration_error_detailed": "1006",
    "user_logout": "1007",
    "admin_update_transaction_status": "1008",
    "admin_delete_user_error": "1009",
    "admin_delete_transaction": "1010",
    "admin_delete_transaction_error": "1011",
    "admin_delete_product": "1012",
    "admin_delete_product_error": "1013",
    "admin_add_product": "1014",
    "admin_add_product_error": "1015",
    "admin_edit_product": "1016",
    "admin_edit_product_error": "1017",
    "admin_add_user": "1018",
    "admin_edit_user": "1019",
    "environment_update": "1020",
    "resource_increase": "1021",
    "resource_decrease": "1022",
    "sql_injection_detected": "1023",
    "union_select_execution": "1024",
    "union_select_error": "1025",
    "store_route_error": "1026",
    "checkout_attempt": "1027",
    "payment_completed": "1028",
    "payment_error": "1029",
    "init_db_error": "1030",
    "admin_add_user_error": "1031",
    "admin_delete_user": "1032",
    "admin_edit_user_error": "1033",
    "profile_update_success": "1034",
    "qr_payment_attempt": "1035",
    "payment_success_access": "1036",
    "profile_access_success": "1037",
}

def setup_logging():
    log_dir = os.path.dirname(Config.LOG_FILE_PATH)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            forwarded_for = getattr(record, 'forwarded_for', None)
            src_ip = forwarded_for.split(',')[0].strip() if forwarded_for else getattr(record, 'src_ip', '127.0.0.1')

            environ = getattr(record, 'environ', {})
            src_port = environ.get('REMOTE_PORT', 'unknown')

            log_record = {
                "event_code": getattr(record, 'event_code', '1000'),
                "agent": {
                    "ip": "127.0.0.1",
                    "name": "MarsLifeHub",
                    "id": ""
                },
                "data": {
                    "app_proto": "http",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dest_port": "5001"
                },
                "http": {
                    "hostname": "127.0.0.1",
                    "protocol": "HTTP/1.1",
                    "http_method": getattr(record, 'http_method', 'UNKNOWN'),
                    "url": getattr(record, 'url', '/'),
                    "http_user_agent": getattr(record, 'user_agent', 'Unknown-Agent'),
                    "status": getattr(record, 'status', '200')
                },
                "err_message": "none" if not record.exc_info else self.formatException(record.exc_info),
                "details": getattr(record, 'details', {})
            }
            return json.dumps(log_record, ensure_ascii=False)

    file_handler = ConcurrentRotatingFileHandler(
        Config.LOG_FILE_PATH,
        maxBytes=Config.LOG_MAX_BYTES,
        backupCount=Config.LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setFormatter(JsonFormatter())
    file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))

    for handler in app.logger.handlers[:]:
        if isinstance(handler, ConcurrentRotatingFileHandler):
            app.logger.removeHandler(handler)

    app.logger.addHandler(file_handler)
    app.logger.setLevel(getattr(logging, Config.LOG_LEVEL))

    app.logger.info("", extra={
        "event_code": EVENT_CODES["application_start"],
        "details": {"event": "application_start", "message": "=== MarsLifeHub запущен ==="}
    })

setup_logging()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(200), default='astronaut')


class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    current_level = db.Column(db.Float, nullable=False)
    max_level = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)


class EnvironmentControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parameter = db.Column(db.String(50), nullable=False)
    current_value = db.Column(db.Float, nullable=False)
    min_value = db.Column(db.Float, nullable=False)
    max_value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50))
    image = db.Column(db.String(200))

    @property
    def is_available(self):
        return self.stock > 0


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_id = db.Column(db.String(50), unique=True)
    status = db.Column(db.String(20), default='pending')
    payment_method = db.Column(db.String(20))
    card_number = db.Column(db.String(50))


def get_env_controls():
    controls = EnvironmentControl.query.all()
    return [{
        'id': c.id,
        'parameter': c.parameter,
        'current_value': c.current_value,
        'min_value': c.min_value,
        'max_value': c.max_value,
        'unit': c.unit
    } for c in controls]


def get_resources():
    resources = Resource.query.all()
    return [{
        'name': r.name,
        'current': r.current_level,
        'max': r.max_level,
        'unit': r.unit,
        'icon': get_icon_for_resource(r.name)
    } for r in resources]


def get_icon_for_resource(resource_name):
    icons = {
        'Кислород': 'wind',
        'Вода': 'droplet',
        'Электроэнергия': 'zap',
        'Еда': 'coffee'
    }
    return icons.get(resource_name, 'help-circle')


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    resources_data = get_resources()
    env_controls = get_env_controls()
    return render_template('index.html', resources=resources_data, env_controls=env_controls)


@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    users_count = User.query.count()
    transactions_count = Transaction.query.count()
    products_count = Product.query.count()
    resources = Resource.query.all()
    return render_template('admin/dashboard.html',
                           users_count=users_count,
                           transactions_count=transactions_count,
                           products_count=products_count,
                           resources=resources)


@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/transactions')
def admin_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    transactions = Transaction.query.all()
    users = {user.id: user.username for user in User.query.all()}
    products = {product.id: product.name for product in Product.query.all()}
    return render_template('admin/transactions.html',
                           transactions=transactions,
                           users=users,
                           products=products)


@app.route('/admin/transactions/update_status', methods=['POST'])
def admin_update_transaction_status():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    transaction_id = request.form.get('transaction_id')
    new_status = request.form.get('status')

    if not transaction_id or not new_status:
        flash('Не указан ID транзакции или новый статус', 'danger')
        return redirect(url_for('admin_transactions'))

    transaction = Transaction.query.get(transaction_id)
    if transaction:
        try:
            transaction.status = new_status
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["admin_update_transaction_status"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_action",
                    "action": "update_transaction_status",
                    "transaction_id": transaction_id,
                    "new_status": new_status
                }
            })
            flash('Статус транзакции успешно обновлен', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении статуса транзакции: {str(e)}', 'danger')
    else:
        flash('Транзакция не найдена', 'danger')

    return redirect(url_for('admin_transactions'))


@app.route('/admin/products')
def admin_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    products = Product.query.all()
    return render_template('admin/products.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        app.logger.info("", extra={
            "event_code": EVENT_CODES["user_login_attempt"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "user_login_attempt",
                "username": username
            }
        })
        user = User.query.filter_by(username=username).first()
        hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()
        if user and user.password == hashed_password:
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = (user.role == 'admin')
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        app.logger.info("", extra={
            "event_code": EVENT_CODES["user_registration_attempt"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "user_registration_attempt",
                "username": username,
                "email": email
            }
        })
        try:
            app.logger.info("", extra={
                "event_code": EVENT_CODES["user_registration_attempt"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "user_registration_attempt",
                    "username": username,
                    "email": email
                }
            })
        except Exception as logging_error:
            print(f"Ошибка логирования: {logging_error}")

        if not all([username, email, password, confirm_password]):
            error_data = {
                'error': 'Все поля обязательны для заполнения.',
                'technical_details': 'Missing required fields in form submission.'
            }
            return render_template('register.html', error_data=error_data)

        if password != confirm_password:
            error_data = {
                'error': 'Пароли не совпадают.',
                'technical_details': 'Password and confirm_password fields do not match.'
            }
            return render_template('register.html', error_data=error_data)

        try:
            user_by_email = User.query.filter_by(email=email).first()
            user_by_username = User.query.filter_by(username=username).first()

            if user_by_email:
                error_data = {
                    'error': 'Пользователь уже существует.',
                    'technical_details': {
                        'user_data': {
                            'id': user_by_email.id,
                            'username': user_by_email.username,
                            'email': user_by_email.email,
                            'password_hash': user_by_email.password,
                            'role': user_by_email.role
                        },
                        'warning': 'This is a security vulnerability! MD5 hash exposed and can be brute-forced.'
                    }
                }
                app.logger.warning("", extra={
                    "event_code": EVENT_CODES["user_data_leak_warning"],
                    "src_ip": request.remote_addr,
                    "forwarded_for": request.headers.get('X-Forwarded-For', None),
                    "http_method": request.method,
                    "url": request.url,
                    "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                    "environ": request.environ,
                    "details": {
                        "event": "user_data_leak_warning",
                        "email": email,
                        "technical_details": error_data['technical_details']
                    }
                })
                return render_template('register.html', error_data=error_data)

            if user_by_username:
                error_data = {
                    'error': 'Пользователь уже существует.',
                    'technical_details': {
                        'user_data': {
                            'id': user_by_username.id,
                            'username': user_by_username.username,
                            'email': user_by_username.email,
                            'password_hash': user_by_username.password,
                            'role': user_by_username.role
                        },
                        'warning': 'This is a security vulnerability! MD5 hash exposed and can be brute-forced.'
                    }
                }
                app.logger.warning("", extra={
                    "event_code": EVENT_CODES["user_data_leak_warning"],
                    "src_ip": request.remote_addr,
                    "forwarded_for": request.headers.get('X-Forwarded-For', None),
                    "http_method": request.method,
                    "url": request.url,
                    "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                    "environ": request.environ,
                    "details": {
                        "event": "user_data_leak_warning",
                        "username": username,
                        "technical_details": error_data['technical_details']
                    }
                })
                return render_template('register.html', error_data=error_data)

            hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()
            user = User(username=username, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()

            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            app.logger.error("", extra={
                "event_code": EVENT_CODES["registration_error"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "registration_error",
                    "error": str(e)
                }
            })
            error_data = {
                'error': 'Произошла ошибка при регистрации.',
                'technical_details': {
                    'exception': str(e),
                    'stack_trace': traceback.format_exc(),
                    'warning': 'This is a security vulnerability! Exposing stack trace and database errors.'
                }
            }
            app.logger.error("", extra={
                "event_code": EVENT_CODES["registration_error_detailed"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "registration_error_detailed",
                    "technical_details": error_data['technical_details']
                }
            })
            return render_template('register.html', error_data=error_data)

    return render_template('register.html')

@app.route('/logout')
def logout():
    app.logger.info("", extra={
        "event_code": EVENT_CODES["user_logout"],
        "src_ip": request.remote_addr,
        "forwarded_for": request.headers.get('X-Forwarded-For', None),
        "http_method": request.method,
        "url": request.url,
        "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
        "environ": request.environ,
        "details": {
            "event": "user_logout",
            "user_id": session.get('user_id'),
            "username": session.get('username')
        }
    })
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out. If you have been logged out, you can log in again.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/users/delete', methods=['POST'])
def admin_delete_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    user_id = request.form.get('user_id')
    if not user_id:
        flash('ID пользователя не указан', 'danger')
        return redirect(url_for('admin_users'))
    if int(user_id) == session['user_id']:
        flash('Вы не можете удалить свою учетную запись', 'danger')
        return redirect(url_for('admin_users'))
    user = User.query.get(user_id)
    if user:
        try:
            Transaction.query.filter_by(user_id=user.id).delete()
            db.session.delete(user)
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["admin_delete_user"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_action",
                    "action": "delete_user",
                    "user_id": user.id,
                    "username": user.username
                }
            })
            flash(f'Пользователь {user.username} успешно удален', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error("", extra={
                "event_code": EVENT_CODES["admin_delete_user_error"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_delete_user_error",
                    "error": str(e)
                }
            })
            flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    else:
        flash('Пользователь не найден', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/transactions/delete', methods=['POST'])
def admin_delete_transaction():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    transaction_id = request.form.get('transaction_id')
    if not transaction_id:
        flash('ID транзакции не указан', 'danger')
        return redirect(url_for('admin_transactions'))
    transaction = Transaction.query.get(transaction_id)
    if transaction:
        try:
            if transaction.status == 'completed':
                product = Product.query.get(transaction.product_id)
                if product:
                    product.stock += transaction.quantity
            db.session.delete(transaction)
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["admin_delete_transaction"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_action",
                    "action": "delete_transaction",
                    "transaction_id": transaction.id
                }
            })
            flash('Транзакция успешно удалена', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error("", extra={
                "event_code": EVENT_CODES["admin_delete_transaction_error"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_delete_transaction_error",
                    "error": str(e)
                }
            })
            flash(f'Ошибка при удалении транзакции: {str(e)}', 'danger')
    else:
        flash('Транзакция не найдена', 'danger')
    return redirect(url_for('admin_transactions'))


@app.route('/admin/products/delete', methods=['POST'])
def admin_delete_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    product_id = request.form.get('product_id')
    if not product_id:
        flash('ID товара не указан', 'danger')
        return redirect(url_for('admin_products'))
    transactions = Transaction.query.filter_by(product_id=product_id).count()
    if transactions > 0:
        flash(f'Невозможно удалить товар, так как с ним связано {transactions} транзакций', 'danger')
        return redirect(url_for('admin_products'))
    product = Product.query.get(product_id)
    if product:
        try:
            db.session.delete(product)
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["admin_delete_product"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_action",
                    "action": "delete_product",
                    "product_id": product.id,
                    "product_name": product.name
                }
            })
            flash(f'Товар {product.name} успешно удален', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error("", extra={
                "event_code": EVENT_CODES["admin_delete_product_error"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "admin_delete_product_error",
                    "error": str(e)
                }
            })
            flash(f'Ошибка при удалении товара: {str(e)}', 'danger')
    else:
        flash('Товар не найден', 'danger')
    return redirect(url_for('admin_products'))

@app.route('/admin/products/add', methods=['POST'])
def admin_add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    stock = request.form.get('stock')
    category = request.form.get('category')
    image = request.form.get('image')
    if not name or not description or not price or not stock:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_products'))
    try:
        new_product = Product(
            name=name,
            description=description,
            price=float(price),
            stock=int(stock),
            category=category if category else 'Общее',
            image=image if image else 'placeholder.jpg'
        )
        db.session.add(new_product)
        db.session.commit()
        app.logger.info("", extra={
            "event_code": EVENT_CODES["admin_add_product"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_action",
                "action": "add_product",
                "product_name": name,
                "price": price,
                "stock": stock
            }
        })
        flash(f'Товар "{name}" успешно добавлен', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error("", extra={
            "event_code": EVENT_CODES["admin_add_product_error"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_add_product_error",
                "error": str(e)
            }
        })
        flash(f'Ошибка при добавлении товара: {str(e)}', 'danger')
    return redirect(url_for('admin_products'))

@app.route('/admin/products/edit', methods=['POST'])
def admin_edit_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    product_id = request.form.get('product_id')
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    stock = request.form.get('stock')
    category = request.form.get('category')
    image = request.form.get('image')
    if not product_id or not name or not description or not price or not stock:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_products'))
    product = Product.query.get(product_id)
    if not product:
        flash('Товар не найден', 'danger')
        return redirect(url_for('admin_products'))
    try:
        product.name = name
        product.description = description
        product.price = float(price)
        product.stock = int(stock)
        product.category = category if category else 'Общее'
        product.image = image if image else product.image
        db.session.commit()
        app.logger.info("", extra={
            "event_code": EVENT_CODES["admin_edit_product"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_action",
                "action": "edit_product",
                "product_id": product.id,
                "product_name": name
            }
        })
        flash(f'Товар "{name}" успешно обновлен', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error("", extra={
            "event_code": EVENT_CODES["admin_edit_product_error"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_edit_product_error",
                "error": str(e)
            }
        })
        flash(f'Ошибка при обновлении товара: {str(e)}', 'danger')
    return redirect(url_for('admin_products'))

@app.route('/admin/users/add', methods=['POST'])
def admin_add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    if not username or not email or not password:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_users'))
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        flash('Пользователь с таким именем или email уже существует', 'danger')
        return redirect(url_for('admin_users'))
    try:
        hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role if role else 'astronaut'
        )
        db.session.add(new_user)
        db.session.commit()
        app.logger.info("", extra={
            "event_code": EVENT_CODES["admin_add_user"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_action",
                "action": "add_user",
                "username": username,
                "email": email,
                "role": role
            }
        })
        flash(f'Пользователь "{username}" успешно добавлен', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error("", extra={
            "event_code": EVENT_CODES["admin_add_user_error"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_add_user_error",
                "error": str(e)
            }
        })
        flash(f'Ошибка при добавлении пользователя: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/edit', methods=['POST'])
def admin_edit_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    password = request.form.get('password')
    if not user_id or not username or not email or not role:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_users'))
    user = User.query.get(user_id)
    if not user:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('admin_users'))
    try:
        user.username = username
        user.email = email
        user.role = role
        if password:
            user.password = hashlib.md5(password.encode('utf-8')).hexdigest()
        db.session.commit()
        app.logger.info("", extra={
            "event_code": EVENT_CODES["admin_edit_user"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_action",
                "action": "edit_user",
                "user_id": user.id,
                "username": username,
                "email": email,
                "role": role
            }
        })
        flash(f'Пользователь "{username}" успешно обновлен', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error("", extra={
            "event_code": EVENT_CODES["admin_edit_user_error"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "admin_edit_user_error",
                "error": str(e)
            }
        })
        flash(f'Ошибка при обновлении пользователя: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/resources')
def resources():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    resources_data = get_resources()
    return render_template('resources.html', resources=resources_data)


@app.route('/environment')
def environment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    env_controls = get_env_controls()
    return render_template('environment.html', env_controls=env_controls)


@app.route('/environment/debug')
def environment_debug():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    env_controls = get_env_controls()
    return render_template('environment_debug.html', env_controls=env_controls)

@app.route('/update_environment', methods=['POST'])
def update_environment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    param_id = int(request.form.get('param_id'))
    new_value = float(request.form.get('new_value'))
    control = EnvironmentControl.query.get(param_id)
    if control:
        if control.min_value <= new_value <= control.max_value:
            control.current_value = new_value
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["environment_update"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "environment_update",
                    "parameter": control.parameter,
                    "new_value": new_value,
                    "unit": control.unit
                }
            })
            flash(f'Параметр "{control.parameter}" обновлен до {new_value} {control.unit}', 'success')
        else:
            flash(f'Значение должно быть в диапазоне от {control.min_value} до {control.max_value} {control.unit}', 'danger')
    else:
        flash('Параметр не найден', 'danger')
    return redirect(url_for('environment'))

@app.route('/update_resource', methods=['POST'])
def update_resource():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    resource_name = request.form.get('resource_name')
    action = request.form.get('action')
    amount = int(request.form.get('amount'))
    resource = Resource.query.filter_by(name=resource_name).first()
    if resource:
        if action == 'increase':
            new_value = resource.current_level + amount
            if new_value <= resource.max_level:
                resource.current_level = new_value
                db.session.commit()
                app.logger.info("", extra={
                    "event_code": EVENT_CODES["resource_increase"],
                    "src_ip": request.remote_addr,
                    "forwarded_for": request.headers.get('X-Forwarded-For', None),
                    "http_method": request.method,
                    "url": request.url,
                    "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                    "environ": request.environ,
                    "details": {
                        "event": "resource_increase",
                        "resource": resource.name,
                        "amount": amount,
                        "unit": resource.unit,
                        "new_level": new_value
                    }
                })
                flash(f'Ресурс "{resource.name}" увеличен на {amount} {resource.unit}', 'success')
            else:
                flash(f'Невозможно увеличить "{resource.name}" выше максимума {resource.max_level} {resource.unit}', 'danger')
        elif action == 'decrease':
            new_value = resource.current_level - amount
            if new_value >= 0:
                resource.current_level = new_value
                db.session.commit()
                app.logger.info("", extra={
                    "event_code": EVENT_CODES["resource_decrease"],
                    "src_ip": request.remote_addr,
                    "forwarded_for": request.headers.get('X-Forwarded-For', None),
                    "http_method": request.method,
                    "url": request.url,
                    "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                    "environ": request.environ,
                    "details": {
                        "event": "resource_decrease",
                        "resource": resource.name,
                        "amount": amount,
                        "unit": resource.unit,
                        "new_level": new_value
                    }
                })
                flash(f'Ресурс "{resource.name}" уменьшен на {amount} {resource.unit}', 'success')
            else:
                flash(f'Невозможно уменьшить "{resource.name}" ниже 0 {resource.unit}', 'danger')
    else:
        flash('Ресурс не найден', 'danger')
    return redirect(url_for('resources'))

@app.route('/store')
def store():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 9

    if 'guessed_columns' not in session:
        session['guessed_columns'] = []

    if 'union select' in search_query.lower():
        union_index = search_query.lower().find('union select')
        union_part = search_query[union_index:]
        select_part = union_part[len('union select'):].strip()
        columns_part = select_part[:select_part.lower().find('from')].strip()
        requested_columns = [col.strip() for col in columns_part.split(',')]
        if all(col.lower() == 'null' for col in requested_columns):
            session['guessed_columns'] = []

    try:
        is_injection = any(keyword in search_query.lower() for keyword in [
            '1=1', 'pg_sleep', 'union select', '=', ' or ', ' and ', 'select', 'exists', '--'
        ])

        if search_query and is_injection:
            app.logger.warning("", extra={
                "event_code": EVENT_CODES["sql_injection_detected"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "sql_injection_detected",
                    "search_query": search_query
                }
            })
            if 'pg_sleep' in search_query.lower():
                flash('Товар найден', 'success')
                pagination = SimpleNamespace(
                    items=[],
                    page=1,
                    pages=1,
                    has_next=False,
                    has_prev=False,
                    prev_num=1,
                    next_num=1,
                    iter_pages=lambda: [1]
                )
                return render_template('store.html', products=pagination, user=user, search_query=search_query)

            elif 'union select' in search_query.lower():
                try:
                    union_index = search_query.lower().find('union select')
                    union_part = search_query[union_index:]

                    select_part = union_part[len('union select'):].strip()
                    if 'from' not in select_part.lower():
                        raise Exception("Invalid UNION SELECT query: missing FROM clause")

                    columns_part = select_part[:select_part.lower().find('from')].strip()
                    table_part = select_part[select_part.lower().find('from') + len('from'):].strip()
                    table_name = table_part.split()[0].strip()

                    if table_name.lower() == 'user':
                        table_part = table_part.replace('user', '"user"', 1)

                    table_columns = {
                        'product': ['id', 'name', 'description', 'price', 'stock', 'category', 'image'],
                        'user': ['id', 'username', 'email', 'password', 'role'],
                        'resource': ['id', 'name', 'current_level', 'max_level', 'unit', 'last_updated'],
                        'environment_control': ['id', 'parameter', 'current_value', 'min_value', 'max_value', 'unit'],
                        'transaction': ['id', 'user_id', 'product_id', 'quantity', 'total_price', 'transaction_date',
                                        'transaction_id', 'status', 'payment_method', 'card_number']
                    }

                    if table_name.lower() not in table_columns:
                        raise Exception(f"Unknown table: {table_name}")

                    expected_columns = table_columns[table_name.lower()]
                    num_expected_columns = len(expected_columns)

                    requested_columns = [col.strip() for col in columns_part.split(',')]
                    num_columns = len(requested_columns)

                    if num_columns != num_expected_columns:
                        raise Exception(
                            f"Invalid number of columns: expected {num_expected_columns}, got {num_columns}")

                    for i, (req_col, exp_col) in enumerate(zip(requested_columns, expected_columns)):
                        if req_col.lower() != 'null' and req_col.lower() != exp_col.lower():
                            raise Exception(
                                f"Invalid column order: expected {exp_col} at position {i + 1}, got {req_col}")
                        if req_col.lower() != 'null' and req_col.lower() == exp_col.lower():
                            if exp_col not in session['guessed_columns']:
                                session['guessed_columns'].append(exp_col)

                    type_casts = {
                        'product': ['CAST(NULL AS INTEGER)', 'CAST(NULL AS TEXT)', 'CAST(NULL AS TEXT)',
                                    'CAST(NULL AS NUMERIC)', 'CAST(NULL AS INTEGER)', 'CAST(NULL AS TEXT)',
                                    'CAST(NULL AS TEXT)'],
                        'user': ['CAST(NULL AS INTEGER)', 'CAST(NULL AS TEXT)', 'CAST(NULL AS TEXT)',
                                 'CAST(NULL AS TEXT)', 'CAST(NULL AS TEXT)'],
                        'resource': ['CAST(NULL AS INTEGER)', 'CAST(NULL AS TEXT)', 'CAST(NULL AS INTEGER)',
                                     'CAST(NULL AS INTEGER)', 'CAST(NULL AS TEXT)', 'CAST(NULL AS TIMESTAMP)'],
                        'environment_control': ['CAST(NULL AS INTEGER)', 'CAST(NULL AS TEXT)', 'CAST(NULL AS NUMERIC)',
                                                'CAST(NULL AS NUMERIC)', 'CAST(NULL AS NUMERIC)', 'CAST(NULL AS TEXT)'],
                        'transaction': ['CAST(NULL AS INTEGER)', 'CAST(NULL AS INTEGER)', 'CAST(NULL AS INTEGER)',
                                        'CAST(NULL AS INTEGER)', 'CAST(NULL AS NUMERIC)', 'CAST(NULL AS TIMESTAMP)',
                                        'CAST(NULL AS TEXT)', 'CAST(NULL AS TEXT)', 'CAST(NULL AS TEXT)',
                                        'CAST(NULL AS TEXT)']
                    }

                    dummy_columns = ', '.join(type_casts[table_name.lower()])
                    union_part_modified = f"UNION SELECT {columns_part} FROM {table_part}"
                    raw_query = f"SELECT {dummy_columns} WHERE 1=0 {union_part_modified}"

                    app.logger.info("", extra={
                        "event_code": EVENT_CODES["union_select_execution"],
                        "src_ip": request.remote_addr,
                        "forwarded_for": request.headers.get('X-Forwarded-For', None),
                        "http_method": request.method,
                        "url": request.url,
                        "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                        "environ": request.environ,
                        "details": {
                            "event": "union_select_execution",
                            "query": raw_query
                        }
                    })
                    with db.engine.connect() as connection:
                        result = connection.execute(text(raw_query))
                        columns = expected_columns
                        rows = list(result)

                    table_data = []
                    for row in rows:
                        row_dict = {}
                        for idx, col in enumerate(columns):
                            if col not in session['guessed_columns']:
                                row_dict[col] = '???'
                            else:
                                row_dict[col] = row[idx] if row[idx] is not None else None
                        table_data.append(row_dict)

                    display_columns = []
                    for col in columns:
                        if col in session['guessed_columns']:
                            display_columns.append(col)
                        else:
                            display_columns.append('???')

                    flash('Товар найден', 'success')
                    total = len(table_data)
                    start = (page - 1) * per_page
                    end = start + per_page
                    total_pages = total // per_page + (1 if total % per_page else 0)

                    pagination_data = table_data[start:end]
                    pagination = SimpleNamespace(
                        items=pagination_data,
                        page=page,
                        pages=total_pages if total_pages > 0 else 1,
                        has_next=page < total_pages,
                        has_prev=page > 1,
                        prev_num=page - 1 if page > 1 else 1,
                        next_num=page + 1 if page < total_pages else total_pages,
                        iter_pages=lambda: range(1, total_pages + 1)
                    )
                    return render_template('store_table.html', columns=display_columns, table_data=pagination_data,
                                           pagination=pagination, user=user, search_query=search_query)

                except Exception as e:
                    app.logger.error("", extra={
                        "event_code": EVENT_CODES["union_select_error"],
                        "src_ip": request.remote_addr,
                        "forwarded_for": request.headers.get('X-Forwarded-For', None),
                        "http_method": request.method,
                        "url": request.url,
                        "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                        "environ": request.environ,
                        "details": {
                            "event": "union_select_error",
                            "error": str(e)
                        }
                    })
                    flash('Товар не найден', 'danger')
                    return render_template('store.html', products=SimpleNamespace(
                        items=[],
                        page=1,
                        pages=1,
                        has_next=False,
                        has_prev=False,
                        prev_num=1,
                        next_num=1,
                        iter_pages=lambda: [1]
                    ), user=user, search_query=search_query)
            else:
                flash('Товар найден', 'success')
                pagination = SimpleNamespace(
                    items=[],
                    page=1,
                    pages=1,
                    has_next=False,
                    has_prev=False,
                    prev_num=1,
                    next_num=1,
                    iter_pages=lambda: [1]
                )
                return render_template('store.html', products=pagination, user=user, search_query=search_query)
        else:
            if search_query:
                query = text(
                    "SELECT id, name, description, price, stock, category, image "
                    "FROM product "
                    "WHERE name ILIKE :search "
                    "OR description ILIKE :search "
                    "OR category ILIKE :search"
                )
                with db.engine.connect() as connection:
                    result = connection.execute(query, {"search": f"%{search_query}%"})
                    products_list = []
                    for row in result:
                        if row[0] is not None and isinstance(row[0], int):
                            products_list.append({
                                'id': row[0],
                                'name': row[1] or '',
                                'description': row[2] or '',
                                'price': float(row[3]) if row[3] is not None else 0.0,
                                'stock': int(row[4]) if row[4] is not None else 0,
                                'category': row[5] or '',
                                'image': row[6] or '',
                                'is_available': row[4] > 0 if row[4] is not None else False
                            })

                total = len(products_list)
                if total == 0:
                    flash(f'Товар по запросу "{search_query}" не найден.', 'info')

                start = (page - 1) * per_page
                end = start + per_page
                total_pages = total // per_page + (1 if total % per_page else 0)

                pagination = SimpleNamespace(
                    items=[SimpleNamespace(**item) for item in products_list[start:end]],
                    page=page,
                    pages=total_pages if total_pages > 0 else 1,
                    has_next=page < total_pages,
                    has_prev=page > 1,
                    prev_num=page - 1 if page > 1 else 1,
                    next_num=page + 1 if page < total_pages else total_pages,
                    iter_pages=lambda: range(1, total_pages + 1)
                )
            else:
                query = Product.query
                pagination = query.paginate(page=page, per_page=per_page, error_out=False)

            return render_template('store.html', products=pagination, user=user, search_query=search_query)

    except Exception as e:
        app.logger.error("", extra={
            "event_code": EVENT_CODES["store_route_error"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "store_route_error",
                "error": str(e)
            }
        })
        flash('Ошибка при выполнении запроса', 'danger')
        pagination = SimpleNamespace(
            items=[],
            page=1,
            pages=1,
            has_next=False,
            has_prev=False,
            prev_num=1,
            next_num=1,
            iter_pages=lambda: [1]
        )
        return render_template('store.html', products=pagination, user=user, search_query=search_query)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    product = db.session.get(Product, product_id)
    if not product:
        flash('Товар не найден', 'danger')
        return redirect(url_for('store'))
    return render_template('product_detail.html', product=product)

@app.route('/checkout/<int:product_id>', methods=['GET', 'POST'])
def checkout(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)

    if not product.is_available:
        flash('Этот товар временно отсутствует на складе', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

    if request.method == 'POST':
        try:
            app.logger.info("", extra={
                "event_code": EVENT_CODES["checkout_attempt"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "checkout_attempt",
                    "user_id": session['user_id'],
                    "product_id": product_id
                }
            })
            quantity = int(request.form.get('quantity', 1))

            if quantity > 3:
                flash('Можно купить не более 3 единиц одного товара за раз', 'danger')
                return redirect(url_for('checkout', product_id=product_id))

            if quantity <= 0:
                flash('Количество должно быть положительным числом', 'danger')
                return redirect(url_for('checkout', product_id=product_id))

            if quantity > product.stock:
                flash(f'Недостаточно товара на складе. Доступно: {product.stock}', 'danger')
                return redirect(url_for('checkout', product_id=product_id))

            total_price = product.price * quantity
            transaction = Transaction(
                user_id=session['user_id'],
                product_id=product_id,
                quantity=quantity,
                total_price=total_price,
                transaction_id=str(uuid.uuid4()),
                status='pending'
            )

            try:
                db.session.add(transaction)
                db.session.commit()
                return redirect(url_for('payment', transaction_id=transaction.transaction_id))
            except Exception as e:
                db.session.rollback()
                flash('Ошибка при создании заказа', 'danger')
                return redirect(url_for('product_detail', product_id=product_id))

        except ValueError:
            flash('Некорректное количество', 'danger')
            return redirect(url_for('checkout', product_id=product_id))

    return render_template('checkout.html', product=product)

@app.route('/payment/<transaction_id>', methods=['GET', 'POST'])
def payment(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    product = Product.query.get(transaction.product_id)
    if not product.is_available or product.stock < transaction.quantity:
        flash('Товара недостаточно на складе', 'danger')
        transaction.status = 'cancelled'
        db.session.commit()
        return redirect(url_for('product_detail', product_id=product.id))
    if request.method == 'POST':
        try:
            transaction.status = 'completed'
            product.stock -= transaction.quantity
            if product.stock == 0:
                product.stock = 999
                flash(f'Товар "{product.name}" был автоматически пополнен до 999 единиц', 'info')
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["payment_completed"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "payment_completed",
                    "transaction_id": transaction.transaction_id,
                    "user_id": session['user_id']
                }
            })
            flash('Оплата прошла успешно!', 'success')
            return redirect(url_for('payment_success', transaction_id=transaction_id))
        except Exception as e:
            db.session.rollback()
            app.logger.error("", extra={
                "event_code": EVENT_CODES["payment_error"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "payment_error",
                    "error": str(e)
                }
            })
            flash('Ошибка при обработке платежа', 'danger')
            return redirect(url_for('payment', transaction_id=transaction_id))
    return render_template('payment.html', transaction=transaction, product=product)

@app.route('/payment/card/<transaction_id>', methods=['GET', 'POST'])
def card_payment(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    product = Product.query.get(transaction.product_id)
    if request.method == 'POST':
        card_number = request.form.get('card_number', '').strip()
        transaction.payment_method = 'card'
        transaction.card_number = card_number
        transaction.status = 'completed'
        product.stock -= transaction.quantity
        if product.stock == 0:
            product.stock = 999
            flash(f'Товар "{product.name}" был автоматически пополнен до 999 единиц', 'info')
        db.session.commit()
        app.logger.info("", extra={
            "event_code": EVENT_CODES["payment_completed"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "payment_completed",
                "transaction_id": transaction.transaction_id,
                "user_id": session['user_id'],
                "payment_method": "card"
            }
        })
        flash('Оплата картой прошла успешно!', 'success')
        return redirect(url_for('payment_success', transaction_id=transaction_id))
    return render_template('card_payment.html', transaction=transaction, product=product)


@app.route('/payment/qr/<transaction_id>')
def qr_payment(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    product = Product.query.get(transaction.product_id)
    qr_data = f"marslife:payment:{transaction_id}:{transaction.total_price}"
    return render_template('qr_payment.html', transaction=transaction, product=product, qr_data=qr_data)


@app.route('/payment/success/<transaction_id>')
def payment_success(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    product = Product.query.get(transaction.product_id)
    return render_template('payment_success.html', transaction=transaction, product=product)


@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    page = request.args.get('page', 1, type=int)
    per_page = 5
    user_transactions = Transaction.query.filter_by(user_id=session['user_id']).order_by(
        Transaction.transaction_date.desc()).paginate(page=page, per_page=per_page)
    products = {}
    for transaction in user_transactions.items:
        product = Product.query.get(transaction.product_id)
        products[transaction.product_id] = product.name if product else "Неизвестно"
    return render_template('transactions.html',
                           transactions=user_transactions,
                           products=products)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            raise Exception("Пользователь не найден")

        last_transaction = Transaction.query.filter_by(user_id=user.id).order_by(
            Transaction.transaction_date.desc()).first()
        card_info = (last_transaction.card_number if last_transaction and last_transaction.card_number
                     else "Нет данных о карте")

        app.logger.info("", extra={
            "event_code": EVENT_CODES["profile_access_success"],
            "src_ip": request.remote_addr,
            "forwarded_for": request.headers.get('X-Forwarded-For', None),
            "http_method": request.method,
            "url": request.url,
            "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
            "environ": request.environ,
            "details": {
                "event": "profile_access_success",
                "user_id": session['user_id'],
                "username": session.get('username'),
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent'),
                "card_number": card_info,
                "debug_param": request.args.get('debug', '')
            }
        })

        debug_output = ''
        debug_param = request.args.get('debug', '')
        if debug_param:
            try:
                if "subprocess.check_output(['whoami'])" in debug_param:
                    debug_output = session.get('username', 'unknown')
                    app.logger.info(json.dumps({
                        "event": "ssti_attempt",
                        "user_id": session.get('user_id'),
                        "username": session.get('username'),
                        "debug_param": debug_param,
                        "debug_output": debug_output,
                        "ip": request.remote_addr,
                        "custom_response": "Returned session username instead of whoami",
                        "card_number": card_info
                    }, ensure_ascii=False))
                else:
                    template = Template(debug_param)
                    debug_output = template.render(
                        os=os,
                        subprocess=subprocess,
                        Popen=subprocess.Popen,
                        config=current_app.config,
                        __builtins__=builtins,
                        get_flashed_messages=get_flashed_messages,
                        cycler=jinja2.utils.Cycler,
                        card_info=card_info
                    )
                    network_keywords = ['nc ', 'netcat', 'bash', 'python', 'socat', 'tcp', 'connect']
                    is_network_attempt = any(keyword in debug_param.lower() for keyword in network_keywords)
                    log_event = "ssti_reverse_shell_attempt" if is_network_attempt else "ssti_attempt"
                    app.logger.info(json.dumps({
                        "event": log_event,
                        "user_id": session.get('user_id'),
                        "username": session.get('username'),
                        "debug_param": debug_param,
                        "debug_output": debug_output[:100],
                        "ip": request.remote_addr,
                        "card_number": card_info
                    }, ensure_ascii=False))
            except Exception as template_error:
                if '__subclasses__' in debug_param:
                    try:
                        subclasses = ''.__class__.__base__.__subclasses__()
                        subclasses_info = {i: f"{cls.__name__} ({cls.__module__})" for i, cls in enumerate(subclasses) if cls.__module__ == 'subprocess'}
                        debug_output = f"Ошибка шаблона: {str(template_error)}\nSubclasses info (subprocess module): {subclasses_info}"
                    except Exception as e:
                        debug_output = f"Ошибка шаблона: {str(template_error)}\nНе удалось получить subclasses: {str(e)}"
                else:
                    debug_output = f"Ошибка шаблона: {str(template_error)}"
                app.logger.error(json.dumps({
                    "event": "ssti_error",
                    "user_id": session.get('user_id'),
                    "username": session.get('username'),
                    "debug_param": debug_param,
                    "error": str(template_error),
                    "ip": request.remote_addr,
                    "card_number": card_info
                }, ensure_ascii=False))

        return render_template('profile.html', user=user, debug_output=debug_output, card_info=card_info)

    except Exception as e:
        app.logger.error(json.dumps({
            "event": "profile_load_error",
            "user_id": session.get('user_id'),
            "username": session.get('username'),
            "error": str(e),
            "ip": request.remote_addr,
            "user_agent": request.headers.get('User-Agent')
        }, ensure_ascii=False))

        return render_template('error.html', error=str(e), debug_output=''), 400

@app.route('/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        user = User.query.get(session['user_id'])
        if not user:
            raise Exception("Пользователь не найден")

        new_username = request.form.get('username')
        if new_username:
            user.username = new_username
            db.session.commit()
            app.logger.info("", extra={
                "event_code": EVENT_CODES["profile_update_success"],
                "src_ip": request.remote_addr,
                "forwarded_for": request.headers.get('X-Forwarded-For', None),
                "http_method": request.method,
                "url": request.url,
                "user_agent": request.headers.get('User-Agent', 'Unknown-Agent'),
                "environ": request.environ,
                "details": {
                    "event": "profile_update_success",
                    "user_id": user.id,
                    "new_username": new_username
                }
            })
            flash('Имя пользователя обновлено', 'success')

        return redirect(url_for('profile'))
    except Exception as e:
        error_msg = f"Ошибка при обновлении профиля: {str(e)}. Дополнительная информация: {request.form.get('debug_info', '')}"
        flash(error_msg, 'danger')
        return redirect(url_for('profile'))


@app.before_request
def log_profile_access():
    if request.path == '/profile' and 'user_id' in session:
        app.logger.info(json.dumps({
            "event": "profile_access",
            "user_id": session['user_id'],
            "username": session.get('username'),
            "ip": request.remote_addr,
            "user_agent": request.headers.get('User-Agent')
        }, ensure_ascii=False))


def init_db():
    with app.app_context():
        try:
            db.create_all()
            app.logger.info(json.dumps({
                "event": "db_tables_created",
                "message": "Database tables created successfully"
            }, ensure_ascii=False))

            app.logger.info(json.dumps({
                "event": "db_check_start",
                "message": "Checking database state before initialization"
            }, ensure_ascii=False))
            user_count = User.query.count()
            app.logger.info(json.dumps({
                "event": "db_user_count",
                "user_count": user_count,
                "message": f"Found {user_count} users in database"
            }, ensure_ascii=False))

            with db.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                app.logger.info(json.dumps({
                    "event": "db_connection_success",
                    "message": "Successfully connected to database with postgres user"
                }, ensure_ascii=False))

            try:
                with db.engine.connect() as connection:
                    result = connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname='postgres'"))
                    if result.fetchone():
                        app.logger.info(json.dumps({
                            "event": "db_user_verified",
                            "username": "postgres",
                            "message": "Postgres user verified"
                        }, ensure_ascii=False))
                    else:
                        app.logger.error(json.dumps({
                            "event": "db_user_missing",
                            "username": "postgres",
                            "message": "Postgres user not found"
                        }, ensure_ascii=False))
                        raise Exception("Postgres user not found")
            except Exception as e:
                app.logger.error(json.dumps({
                    "event": "db_user_verification_error",
                    "error": str(e),
                    "message": "Failed to verify postgres user"
                }, ensure_ascii=False))
                raise

            try:
                with db.engine.connect() as connection:
                    result = connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname='userpro'"))
                    if not result.fetchone():
                        connection.execute(text("CREATE USER userpro WITH PASSWORD 'propass'"))
                        connection.execute(text("GRANT CONNECT ON DATABASE testdb TO userpro"))
                        connection.execute(text("GRANT USAGE ON SCHEMA public TO userpro"))
                        connection.execute(
                            text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO userpro"))
                        app.logger.info(json.dumps({
                            "event": "db_user_created",
                            "username": "userpro",
                            "message": "Userpro created and granted permissions"
                        }, ensure_ascii=False))
                    else:
                        app.logger.info(json.dumps({
                            "event": "db_user_exists",
                            "username": "userpro",
                            "message": "Userpro already exists"
                        }, ensure_ascii=False))
            except Exception as e:
                app.logger.error(json.dumps({
                    "event": "db_user_creation_error",
                    "error": str(e),
                    "message": "Failed to create userpro"
                }, ensure_ascii=False))
                raise

            try:
                with open('db_secrets.txt', 'w') as f:
                    f.write("СУБД: PostgreSQL\n")
                    f.write("База данных: testdb\n")
                    f.write("Хост: db\n")
                    f.write("Порт: 5432\n")
                    f.write("Пользователь: userpro\n")
                    f.write("Пароль: propass\n")
                app.logger.info(json.dumps({
                    "event": "db_secrets_file_created",
                    "filename": "db_secrets.txt",
                    "message": "Database secrets file created with userpro credentials"
                }, ensure_ascii=False))
            except Exception as e:
                app.logger.error(json.dumps({
                    "event": "db_secrets_file_error",
                    "error": str(e),
                    "message": "Failed to create db_secrets.txt"
                }, ensure_ascii=False))
                raise

            try:
                with open('db_credentials.txt', 'w') as f:
                    f.write("username=userpro\npassword=securepass123\n")
                app.logger.info(json.dumps({
                    "event": "db_credentials_file_created",
                    "filename": "db_credentials.txt",
                    "message": "Database credentials file created for SSTI testing"
                }, ensure_ascii=False))
            except Exception as e:
                app.logger.error(json.dumps({
                    "event": "db_credentials_file_error",
                    "error": str(e),
                    "message": "Failed to create db_credentials.txt"
                }, ensure_ascii=False))
                raise

            if User.query.count() == 0:
                admin_password = hashlib.md5('admin123'.encode('utf-8')).hexdigest()
                admin = User(username='admin', email='admin@marslife.com',
                             password=admin_password, role='admin')
                db.session.add(admin)
                db.session.commit()
                app.logger.info(json.dumps({
                    "event": "db_initial_user_added",
                    "username": "admin",
                    "message": "Initial admin user added"
                }, ensure_ascii=False))
            else:
                app.logger.info(json.dumps({
                    "event": "db_users_exist",
                    "message": "Users table already contains data, skipping initialization"
                }, ensure_ascii=False))

            if Product.query.count() == 0:
                demo_products = [
                    {'name': 'Кислородный баллон',
                     'description': 'Дополнительный запас кислорода для аварийных ситуаций',
                     'price': 150, 'stock': 10, 'category': 'Жизнеобеспечение', 'image': 'oxygen.jpg'},
                    {'name': 'Фильтр для воды', 'description': 'Высокоэффективный фильтр для очистки воды', 'price': 80,
                     'stock': 15, 'category': 'Жизнеобеспечение', 'image': 'water_filter.jpg'},
                    {'name': 'Солнечная панель',
                     'description': 'Дополнительная солнечная панель для генерации электроэнергии',
                     'price': 300, 'stock': 5, 'category': 'Энергетика', 'image': 'solar_panel.jpg'},
                    {'name': 'Аварийный рацион', 'description': 'Запас пищи на 7 дней для аварийных ситуаций',
                     'price': 120,
                     'stock': 20, 'category': 'Питание', 'image': 'emergency_food.jpg'},
                    {'name': 'Ремонтный набор', 'description': 'Набор инструментов для ремонта оборудования',
                     'price': 200,
                     'stock': 8, 'category': 'Инструменты', 'image': 'repair_kit.jpg'},
                    {'name': 'Медицинский набор', 'description': 'Базовый набор для оказания первой помощи',
                     'price': 100,
                     'stock': 12, 'category': 'Медицина', 'image': 'medical_kit.jpg'},
                ]
                for product_data in demo_products:
                    product = Product(**product_data)
                    db.session.add(product)
                db.session.commit()
                app.logger.info(json.dumps({
                    "event": "db_initial_products_added",
                    "message": "Demo products added"
                }, ensure_ascii=False))
            else:
                app.logger.info(json.dumps({
                    "event": "db_products_exist",
                    "message": "Products table already contains data, skipping initialization"
                }, ensure_ascii=False))

            if Resource.query.count() == 0:
                resources = [
                    Resource(name='Кислород', current_level=85.5, max_level=100.0, unit='%'),
                    Resource(name='Вода', current_level=2500, max_level=3000, unit='л'),
                    Resource(name='Еда', current_level=450, max_level=500, unit='кг'),
                    Resource(name='Электроэнергия', current_level=75.2, max_level=100, unit='%')
                ]
                db.session.add_all(resources)
                db.session.commit()
                app.logger.info(json.dumps({
                    "event": "db_initial_resources_added",
                    "message": "Resources added"
                }, ensure_ascii=False))
            else:
                app.logger.info(json.dumps({
                    "event": "db_resources_exist",
                    "message": "Resources table already contains data, skipping initialization"
                }, ensure_ascii=False))

            if EnvironmentControl.query.count() == 0:
                env_controls = [
                    EnvironmentControl(parameter='Температура', current_value=22.5, min_value=18.0, max_value=25.0,
                                       unit='°C'),
                    EnvironmentControl(parameter='Влажность', current_value=45.0, min_value=30.0, max_value=60.0,
                                       unit='%'),
                    EnvironmentControl(parameter='Уровень CO2', current_value=0.04, min_value=0.03, max_value=0.1,
                                       unit='%'),
                    EnvironmentControl(parameter='Давление', current_value=101.3, min_value=97.0, max_value=103.0,
                                       unit='кПа')
                ]
                db.session.add_all(env_controls)
                db.session.commit()
                app.logger.info(json.dumps({
                    "event": "db_initial_env_controls_added",
                    "message": "Environment controls added"
                }, ensure_ascii=False))
            else:
                app.logger.info(json.dumps({
                    "event": "db_env_controls_exist",
                    "message": "EnvironmentControl table already contains data, skipping initialization"
                }, ensure_ascii=False))

        except Exception as e:
            db.session.rollback()
            app.logger.error(json.dumps({
                "event": "init_db_error",
                "error": str(e)
            }, ensure_ascii=False))
            print(f"Ошибка при создании БД: {e}")
            raise


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=7000, debug=True)