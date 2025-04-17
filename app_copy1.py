from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'marslifehub-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:987654@localhost/testdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

with app.app_context():
    db.create_all()


# Database Models
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
    payment_method = db.Column(db.String(20))  # 'card' или 'qr'
    card_number = db.Column(db.String(50))     # Полный ID карты


# Маршруты
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Используем те же данные, что и в resources.html
    resources_data = get_resources()
    env_controls = get_env_controls()

    return render_template('index.html', resources=resources_data, env_controls=env_controls)


# Маршруты админом

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    # Получаем статистику для дашборда
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

    # Проверяем, является ли пользователь администратором
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

    # Проверяем, является ли пользователь администратором
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    transactions = Transaction.query.all()

    # Получаем информацию о пользователях и продуктах
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

    # Проверяем, является ли пользователь администратором
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

    # Проверяем, является ли пользователь администратором
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

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = (user.role == 'admin')  # Добавляем информацию о роли в сессию
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Данный пользователь уже зарегистрирован', 'danger')
        elif existing_email:
            flash('Почта уже зарегистрирована', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно! Войти', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


# Добавьте эти маршруты в app.py

@app.route('/admin/users/delete', methods=['POST'])
def admin_delete_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    user_id = request.form.get('user_id')
    if not user_id:
        flash('ID пользователя не указан', 'danger')
        return redirect(url_for('admin_users'))

    # Проверяем, не пытается ли админ удалить самого себя
    if int(user_id) == session['user_id']:
        flash('Вы не можете удалить свою учетную запись', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get(user_id)
    if user:
        try:
            # Удаляем все транзакции пользователя
            Transaction.query.filter_by(user_id=user.id).delete()

            # Удаляем пользователя
            db.session.delete(user)
            db.session.commit()
            flash(f'Пользователь {user.username} успешно удален', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    else:
        flash('Пользователь не найден', 'danger')

    return redirect(url_for('admin_users'))


@app.route('/admin/transactions/delete', methods=['POST'])
def admin_delete_transaction():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
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
            # Возвращаем товар на склад, если транзакция была завершена
            if transaction.status == 'completed':
                product = Product.query.get(transaction.product_id)
                if product:
                    product.stock += transaction.quantity

            # Удаляем транзакцию
            db.session.delete(transaction)
            db.session.commit()
            flash('Транзакция успешно удалена', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при удалении транзакции: {str(e)}', 'danger')
    else:
        flash('Транзакция не найдена', 'danger')

    return redirect(url_for('admin_transactions'))


@app.route('/admin/products/delete', methods=['POST'])
def admin_delete_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    product_id = request.form.get('product_id')
    if not product_id:
        flash('ID товара не указан', 'danger')
        return redirect(url_for('admin_products'))

    # Проверяем, есть ли транзакции с этим товаром
    transactions = Transaction.query.filter_by(product_id=product_id).count()
    if transactions > 0:
        flash(f'Невозможно удалить товар, так как с ним связано {transactions} транзакций', 'danger')
        return redirect(url_for('admin_products'))

    product = Product.query.get(product_id)
    if product:
        try:
            db.session.delete(product)
            db.session.commit()
            flash(f'Товар {product.name} успешно удален', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при удалении товара: {str(e)}', 'danger')
    else:
        flash('Товар не найден', 'danger')

    return redirect(url_for('admin_products'))


@app.route('/admin/products/add', methods=['POST'])
def admin_add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    # Получаем данные из формы
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    stock = request.form.get('stock')
    category = request.form.get('category')
    image = request.form.get('image')

    # Проверяем обязательные поля
    if not name or not description or not price or not stock:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_products'))

    try:
        # Создаем новый товар
        new_product = Product(
            name=name,
            description=description,
            price=float(price),
            stock=int(stock),
            category=category if category else 'Общее',
            image=image if image else 'placeholder.jpg'
        )

        # Добавляем в базу данных
        db.session.add(new_product)
        db.session.commit()

        flash(f'Товар "{name}" успешно добавлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при добавлении товара: {str(e)}', 'danger')

    return redirect(url_for('admin_products'))

@app.route('/admin/products/edit', methods=['POST'])
def admin_edit_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    # Получаем данные из формы
    product_id = request.form.get('product_id')
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    stock = request.form.get('stock')
    category = request.form.get('category')
    image = request.form.get('image')

    # Проверяем обязательные поля
    if not product_id or not name or not description or not price or not stock:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_products'))

    # Находим товар в базе данных
    product = Product.query.get(product_id)
    if not product:
        flash('Товар не найден', 'danger')
        return redirect(url_for('admin_products'))

    try:
        # Обновляем данные товара
        product.name = name
        product.description = description
        product.price = float(price)
        product.stock = int(stock)
        product.category = category if category else 'Общее'
        product.image = image if image else product.image

        # Сохраняем изменения
        db.session.commit()

        flash(f'Товар "{name}" успешно обновлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обновлении товара: {str(e)}', 'danger')

    return redirect(url_for('admin_products'))


@app.route('/admin/users/add', methods=['POST'])
def admin_add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    # Получаем данные из формы
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')

    # Проверяем обязательные поля
    if not username or not email or not password:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_users'))

    # Проверяем, существует ли пользователь с таким именем или email
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        flash('Пользователь с таким именем или email уже существует', 'danger')
        return redirect(url_for('admin_users'))

    try:
        # Создаем нового пользователя без поля credits
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role if role else 'astronaut'
        )

        # Добавляем в базу данных
        db.session.add(new_user)
        db.session.commit()

        flash(f'Пользователь "{username}" успешно добавлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при добавлении пользователя: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))

@app.route('/admin/users/edit', methods=['POST'])
def admin_edit_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.role != 'admin':
        flash('У вас нет доступа к админской панели', 'danger')
        return redirect(url_for('index'))

    # Получаем данные из формы
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    password = request.form.get('password')

    # Проверяем обязательные поля
    if not user_id or not username or not email or not role:
        flash('Пожалуйста, заполните все обязательные поля', 'danger')
        return redirect(url_for('admin_users'))

    # Находим пользователя в базе данных
    user = User.query.get(user_id)
    if not user:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('admin_users'))

    try:
        # Обновляем данные пользователя
        user.username = username
        user.email = email
        user.role = role

        # Обновляем пароль, если он был предоставлен
        if password:
            user.password = generate_password_hash(password)

        # Сохраняем изменения
        db.session.commit()

        flash(f'Пользователь "{username}" успешно обновлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обновлении пользователя: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


def get_env_controls():
    # Если данные уже есть в сессии, используем их
    if 'env_controls' in session:
        return session['env_controls']

    # Иначе используем значения по умолчанию
    default_controls = [
        {'id': 1, 'parameter': 'Температура', 'current_value': 22.5, 'min_value': 18.0, 'max_value': 26.0,
         'unit': '°C'},
        {'id': 2, 'parameter': 'Влажность', 'current_value': 45.0, 'min_value': 30.0, 'max_value': 60.0, 'unit': '%'},
        {'id': 3, 'parameter': 'Давление', 'current_value': 101.3, 'min_value': 98.0, 'max_value': 102.5,
         'unit': 'кПа'},
        {'id': 4, 'parameter': 'Уровень CO2', 'current_value': 0.04, 'min_value': 0.03, 'max_value': 0.06, 'unit': '%'},
    ]

    # Сохраняем в сессию
    session['env_controls'] = default_controls
    return default_controls


# Инициализация данных о ресурсах
def get_resources():
    # Если данные уже есть в сессии, используем их
    if 'resources' in session:
        return session['resources']

    # Иначе используем значения по умолчанию
    default_resources = [
        {'name': 'Кислород', 'current': 85, 'max': 100, 'unit': '%', 'icon': 'wind'},
        {'name': 'Вода', 'current': 2500, 'max': 5000, 'unit': 'л', 'icon': 'droplet'},
        {'name': 'Электроэнергия', 'current': 75, 'max': 100, 'unit': 'кВт', 'icon': 'zap'},
        {'name': 'Еда', 'current': 1200, 'max': 2000, 'unit': 'кг', 'icon': 'coffee'},
    ]

    # Сохраняем в сессию
    session['resources'] = default_resources
    return default_resources


@app.route('/resources')
def resources():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем данные о ресурсах
    resources_data = get_resources()

    return render_template('resources.html', resources=resources_data)


@app.route('/environment')
def environment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем данные о параметрах окружающей среды
    env_controls = get_env_controls()

    return render_template('environment.html', env_controls=env_controls)

# Добавляем маршрут для отладки параметров окружающей среды
@app.route('/environment/debug')
def environment_debug():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем данные о параметрах окружающей среды
    env_controls = get_env_controls()

    return render_template('environment_debug.html', env_controls=env_controls)


@app.route('/update_environment', methods=['POST'])
def update_environment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем данные из формы
    param_id = int(request.form.get('param_id'))
    new_value = float(request.form.get('new_value'))

    # Получаем текущие параметры
    env_controls = get_env_controls()

    # Находим нужный параметр и обновляем его значение
    for control in env_controls:
        if control['id'] == param_id:
            # Проверяем, что новое значение в допустимом диапазоне
            if control['min_value'] <= new_value <= control['max_value']:
                control['current_value'] = new_value
                flash(f'Параметр "{control["parameter"]}" обновлен до {new_value} {control["unit"]}', 'success')
            else:
                flash(
                    f'Значение должно быть в диапазоне от {control["min_value"]} до {control["max_value"]} {control["unit"]}',
                    'danger')
            break

    # Сохраняем обновленные параметры в сессию
    session['env_controls'] = env_controls

    return redirect(url_for('environment'))


@app.route('/update_resource', methods=['POST'])
def update_resource():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем данные из формы
    resource_name = request.form.get('resource_name')
    action = request.form.get('action')
    amount = int(request.form.get('amount'))

    # Получаем текущие ресурсы
    resources_data = get_resources()

    # Находим нужный ресурс и обновляем его значение
    for resource in resources_data:
        if resource['name'] == resource_name:
            if action == 'increase':
                # Проверяем, что не превышаем максимум
                new_value = resource['current'] + amount
                if new_value <= resource['max']:
                    resource['current'] = new_value
                    flash(f'Ресурс "{resource["name"]}" увеличен на {amount} {resource["unit"]}', 'success')
                else:
                    flash(
                        f'Невозможно увеличить "{resource["name"]}" выше максимума {resource["max"]} {resource["unit"]}',
                        'danger')
            elif action == 'decrease':
                # Проверяем, что не уходим в отрицательные значения
                new_value = resource['current'] - amount
                if new_value >= 0:
                    resource['current'] = new_value
                    flash(f'Ресурс "{resource["name"]}" уменьшен на {amount} {resource["unit"]}', 'success')
                else:
                    flash(f'Невозможно уменьшить "{resource["name"]}" ниже 0 {resource["unit"]}', 'danger')
            break

    # Сохраняем обновленные ресурсы в сессию
    session['resources'] = resources_data

    return redirect(url_for('resources'))


@app.route('/store')
def store():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем данные о пользователе
    user = User.query.get(session['user_id'])

    # Получаем данные о товарах
    products = Product.query.all()

    # Если продуктов нет, добавляем демо-данные
    if not products:
        demo_products = [
            {'name': 'Кислородный баллон', 'description': 'Дополнительный запас кислорода для аварийных ситуаций',
             'price': 150, 'stock': 10, 'category': 'Жизнеобеспечение', 'image': 'oxygen.jpg'},
            {'name': 'Фильтр для воды', 'description': 'Высокоэффективный фильтр для очистки воды', 'price': 80,
             'stock': 15, 'category': 'Жизнеобеспечение', 'image': 'water_filter.jpg'},
            {'name': 'Солнечная панель', 'description': 'Дополнительная солнечная панель для генерации электроэнергии',
             'price': 300, 'stock': 5, 'category': 'Энергетика', 'image': 'solar_panel.jpg'},
            {'name': 'Аварийный рацион', 'description': 'Запас пищи на 7 дней для аварийных ситуаций', 'price': 120,
             'stock': 20, 'category': 'Питание', 'image': 'emergency_food.jpg'},
            {'name': 'Ремонтный набор', 'description': 'Набор инструментов для ремонта оборудования', 'price': 200,
             'stock': 8, 'category': 'Инструменты', 'image': 'repair_kit.jpg'},
            {'name': 'Медицинский набор', 'description': 'Базовый набор для оказания первой помощи', 'price': 100,
             'stock': 12, 'category': 'Медицина', 'image': 'medical_kit.jpg'},
        ]

        for product_data in demo_products:
            product = Product(**product_data)
            db.session.add(product)

        db.session.commit()
        products = Product.query.all()

    return render_template('store.html', products=products, user=user)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)




@app.route('/checkout/<int:product_id>', methods=['GET', 'POST'])
def checkout(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)

    # Жесткая проверка наличия товара
    if not product.is_available:
        flash('Этот товар временно отсутствует на складе', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

    if request.method == 'POST':
        try:
            quantity = int(request.form.get('quantity', 1))
        except ValueError:
            flash('Некорректное количество', 'danger')
            return redirect(url_for('checkout', product_id=product_id))

        # Проверка количества
        if quantity <= 0:
            flash('Количество должно быть положительным числом', 'danger')
            return redirect(url_for('checkout', product_id=product_id))

        if quantity > product.stock:
            flash(f'Недостаточно товара на складе. Доступно: {product.stock}', 'danger')
            return redirect(url_for('checkout', product_id=product_id))

        total_price = product.price * quantity

        # Создаем транзакцию
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

    return render_template('checkout.html', product=product)


@app.route('/payment/<transaction_id>', methods=['GET', 'POST'])
def payment(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    product = Product.query.get(transaction.product_id)

    # Финальная проверка перед оплатой
    if not product.is_available or product.stock < transaction.quantity:
        flash('Товара недостаточно на складе', 'danger')
        transaction.status = 'cancelled'
        db.session.commit()
        return redirect(url_for('product_detail', product_id=product.id))

    if request.method == 'POST':
        try:
            transaction.status = 'completed'
            product.stock -= transaction.quantity

            # Автоматическое пополнение, если товар закончился
            if product.stock == 0:
                product.stock = 99  # Устанавливаем базовый уровень пополнения
                flash(f'Товар "{product.name}" был автоматически пополнен до 99 единиц', 'info')

            db.session.commit()
            flash('Оплата прошла успешно!', 'success')
            return redirect(url_for('payment_success', transaction_id=transaction_id))
        except Exception as e:
            db.session.rollback()
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

        # Сохраняем полный ID карты (ТОЛЬКО ДЛЯ ТЕСТОВОГО ПРОЕКТА)
        transaction.payment_method = 'card'
        transaction.card_number = card_number  # Сохраняем полный номер
        transaction.status = 'completed'

        product.stock -= transaction.quantity

        # Автоматическое пополнение, если товар закончился
        if product.stock == 0:
            product.stock = 99  # Устанавливаем базовый уровень пополнения
            flash(f'Товар "{product.name}" был автоматически пополнен до 99 единиц', 'info')

        db.session.commit()

        flash('Оплата картой прошла успешно!', 'success')
        return redirect(url_for('payment_success', transaction_id=transaction_id))

    return render_template('card_payment.html', transaction=transaction, product=product)

@app.route('/payment/qr/<transaction_id>')
def qr_payment(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    product = Product.query.get(transaction.product_id)

    # Generate QR code data (in real app, this would be a proper QR code)
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

    # Получаем номер страницы из запроса (по умолчанию 1)
    page = request.args.get('page', 1, type=int)
    # Устанавливаем количество элементов на странице
    per_page = 5

    # Получаем транзакции с пагинацией
    user_transactions = Transaction.query.filter_by(user_id=session['user_id']).order_by(
        Transaction.transaction_date.desc()).paginate(page=page, per_page=per_page)

    # Get all products for the transactions
    products = {}
    for transaction in user_transactions.items:
        product = Product.query.get(transaction.product_id)
        products[transaction.product_id] = product.name if product else "Неизвестно"

    return render_template('transactions.html',
                         transactions=user_transactions,
                         products=products)


# Initialize the database with sample data
def init_db():
    with (app.app_context()):
        try:
            db.create_all()
            print("Таблицы созданы успешно!")
            # Добавление тестовых данных
            if User.query.count() == 0:
                admin = User(username='admin', email='admin@marslife.com',
                             password=generate_password_hash('admin123'), role='admin')
                db.session.add(admin)
                db.session.commit()
                print("Тестовые данные добавлены.")
        except Exception as e:
            print(f"Ошибка при создании БД: {e}")

            # Create resources
            resources = [
                Resource(name='Кислород', current_level=85.5, max_level=100.0, unit='%'),
                Resource(name='Вода', current_level=2500, max_level=3000, unit='л'),
                Resource(name='Еда', current_level=450, max_level=500, unit='кг'),
                Resource(name='Электроэнергия', current_level=75.2, max_level=100, unit='%')
            ]
            db.session.add_all(resources)

            # Create environment controls
            env_controls = [
                EnvironmentControl(parameter='Температура', current_value=22.5, min_value=18.0, max_value=25.0,
                                   unit='°C'),
                EnvironmentControl(parameter='Влажность', current_value=45.0, min_value=30.0, max_value=60.0, unit='%'),
                EnvironmentControl(parameter='Уровень C02', current_value=0.04, min_value=0.03, max_value=0.1, unit='%'),
                EnvironmentControl(parameter='Давление', current_value=101.3, min_value=97.0, max_value=103.0,
                                   unit='кПа')
            ]
            db.session.add_all(env_controls)



if __name__ == '__main__':
    init_db()
    app.run(port=5001, debug=True)  # Теперь приложение будет запускаться на порту 5001

print("Flask application structure created successfully!")

