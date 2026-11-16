"""
Flask приложение для управления мультимедийным контентом
с парсером FTP-каталога и возможностью сохранения постоянных элементов
С системой авторизации и защиты

Структура проекта:
- app.py: Основной файл приложения (маршруты, контроллеры)
- config/: Конфигурация приложения
    - settings.py: Все настройки и константы приложения
- utils/: Утилиты и вспомогательные функции
    - data_utils.py: Работа с данными (загрузка/сохранение JSON)
    - parser_utils.py: Парсинг FTP-каталога
    - auth_utils.py: Аутентификация и пользователи
    - catalog_utils.py: Работа с каталогом (поиск, обновление, удаление)
"""

import os
import json
import re
import threading
import warnings
import requests
import urllib3
from datetime import datetime, timedelta
from urllib.parse import unquote, urlparse
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash, Response, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Подавление SSL-предупреждений при использовании verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

# Импорт конфигурации из модуля settings
from config.settings import (
    DATA_DIR, CATALOG_FILE, PERMANENT_FILE, USERS_FILE, PARSER_IMAGES_FILE, ERROR_LOG_FILE, SECRET_KEY,
    FTP_BASE_URL, PARSER_MAX_DEPTH, PARSER_TIMEOUT,
    RATELIMIT_STORAGE_URI, RATELIMIT_DEFAULT, RATELIMIT_LOGIN, RATELIMIT_ENABLED,
    LOGIN_VIEW, LOGIN_MESSAGE, SESSION_PROTECTION
)

# Импорт утилит для работы с данными, парсингом, аутентификацией и каталогом
from utils.data_utils import (
    ensure_data_dir, load_json_file, save_json_file, get_current_timestamp, get_full_timestamp,
    load_users, save_users, load_catalog, save_catalog, load_permanent_items, save_permanent_items,
    normalize_url, replace_url_domain
)
from utils.parser_utils import extract_items_from_html, parse_folder
from utils.auth_utils import User, hash_password, verify_password, admin_required_decorator
from utils.catalog_utils import (
    get_item_path, mark_permanent_recursive, merge_with_permanent,
    find_item_by_path, delete_item_by_path, update_item_by_path
)
from utils.audit_utils import (
    audit_error, audit_upload_success, audit_web_resource, audit_filesystem_read,
    audit_catalog_item_open, load_audit_logs, clear_audit_logs, AuditEventType
)
from utils.proxy_utils import configure_proxy_support
from utils.response_utils import add_static_response_headers

# Инициализация Flask приложения
# static_folder='.' указывает, что статические файлы находятся в корневой директории
# static_url_path='' позволяет обращаться к файлам напрямую по имени
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = SECRET_KEY  # Использование секретного ключа из конфига для сессий

# Настройка JSON: сохранять UTF-8 символы без экранирования \uXXXX
app.config['JSON_AS_ASCII'] = False
app.json.ensure_ascii = False

# Глобальная переменная для хранения префикса пути
URL_PREFIX = '/navigator'

# Настройка для работы за reverse proxy и внешним префиксом /navigator
configure_proxy_support(app, URL_PREFIX)

# Настройка CORS заголовков для всех ответов
@app.after_request
def add_cors_headers(response):
    """Добавляет CORS заголовки и MIME-типы для статических файлов"""
    return add_static_response_headers(response, request.path)

# Инициализация расширений Flask
csrf = CSRFProtect(app)  # Защита от CSRF атак

# Отключаем rate limiting для статических файлов
def limiter_enabled():
    """Проверка, включен ли rate limiting для текущего запроса"""
    static_paths = ('/page/', '/static/', '/css/', '/js/')
    if request.path.startswith(static_paths):
        return False
    return RATELIMIT_ENABLED

limiter = Limiter(
    key_func=get_remote_address,  # Ограничение по IP адресу
    app=app,
    default_limits=RATELIMIT_DEFAULT,  # Ограничения по умолчанию из конфига
    storage_uri=RATELIMIT_STORAGE_URI,  # Хранилище счётчиков в памяти
    enabled=limiter_enabled  # Динамическое включение/отключение
)
login_manager = LoginManager()
login_manager.init_app(app)

# -------------------------------------------------------------------
# ИСПРАВЛЕНИЕ 1: Настройка login_manager для работы с префиксом
# -------------------------------------------------------------------
login_manager.login_view = 'login'
login_manager.login_message = LOGIN_MESSAGE
login_manager.session_protection = SESSION_PROTECTION

def custom_login_url(next=None):
    """Возвращает URL страницы входа с учётом префикса (SCRIPT_NAME)."""
    base_url = URL_PREFIX + '/login'
    if next:
        if not next.startswith(URL_PREFIX):
            next = URL_PREFIX + next if next.startswith('/') else URL_PREFIX + '/' + next.lstrip('/')
        return base_url + '?next=' + next
    return base_url

login_manager.login_url = custom_login_url

@login_manager.unauthorized_handler
def unauthorized():
    """Обработчик для неавторизованных пользователей с учётом префикса"""
    from flask import request, redirect
    from urllib.parse import urlparse
    current_path = urlparse(request.url).path
    return redirect(login_manager.login_url(current_path))

# Глобальная переменная для хранения статуса парсера
parser_status = {'running': False, 'last_run': None, 'message': 'Парсер не запущен', 'images': []}

# Глобальный список для хранения логов парсера (для отправки в браузер)
parser_logs = []


@login_manager.user_loader
def load_user(user_id):
    """
    Callback функция для загрузки пользователя по ID (требуется Flask-Login)
    """
    users_data = load_users(USERS_FILE, hash_password)
    for user in users_data.get('users', []):
        if str(user['id']) == str(user_id):
            return User(user['id'], user['username'], user.get('is_admin', False))
    return None


def run_parser_task():
    """
    Фоновая задача парсинга FTP-каталога
    """
    import logging
    import traceback as tb_module
    global parser_status, parser_logs
    try:
        parser_logs.clear()
        
        def log(message, log_type='info', error_details=None):
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            log_entry = {
                'timestamp': timestamp,
                'message': message,
                'type': log_type,
                'error_details': error_details
            }
            parser_logs.append(log_entry)
            print(f"[{timestamp}] {message}")
            if error_details:
                print(f"[{timestamp}] DETAILS: {error_details}")
        
        log("Запуск run_parser_task()")
        log(f"FTP_BASE_URL: {FTP_BASE_URL}")
        log(f"PARSER_MAX_DEPTH: {PARSER_MAX_DEPTH}")
        log(f"PARSER_TIMEOUT: {PARSER_TIMEOUT}")
        
        existing_images_data = load_json_file(PARSER_IMAGES_FILE, {'images': []})
        existing_images = set(existing_images_data.get('images', []))
        log(f"Существующих изображений в файле: {len(existing_images)}")
        
        log("Вызов parse_folder()...")
        items = parse_folder(FTP_BASE_URL, max_depth=PARSER_MAX_DEPTH, timeout=PARSER_TIMEOUT)
        log(f"parse_folder() вернул элементов: {len(items)}")
        if items:
            log(f"Первые 5 элементов: {items[:5]}")
        else:
            log("WARNING: parse_folder() вернул пустой список!")
        
        new_parser_images = []
        def collect_images(items_list):
            for item in items_list:
                if item.get('children') is None:
                    url = item.get('url', '')
                    if url and (url.lower().endswith('.png') or url.lower().endswith('.jpg') or 
                                url.lower().endswith('.jpeg') or url.lower().endswith('.gif') or 
                                url.lower().endswith('.webp')):
                        if url not in new_parser_images:
                            new_parser_images.append(url)
                else:
                    if item.get('children'):
                        collect_images(item['children'])
        
        log("Сбор изображений из элементов...")
        collect_images(items)
        log(f"Найдено новых изображений: {len(new_parser_images)}")
        
        new_parser_images = [normalize_url(replace_url_domain(img)) for img in new_parser_images]
        existing_images_normalized = {normalize_url(img) for img in existing_images}
        
        all_images = list(existing_images)
        for img_url in new_parser_images:
            if img_url not in existing_images_normalized:
                all_images.append(img_url)
        
        log(f"Всего изображений после объединения: {len(all_images)}")
        
        save_json_file(PARSER_IMAGES_FILE, {'images': all_images})
        log(f"Изображения сохранены в {PARSER_IMAGES_FILE}")
        
        parser_status['images'] = all_images
        
        def replace_url_domain_recursive(items_list):
            for item in items_list:
                if 'url' in item and item['url']:
                    item['url'] = replace_url_domain(item['url'])
                if item.get('children') and isinstance(item['children'], list):
                    replace_url_domain_recursive(item['children'])
        
        replace_url_domain_recursive(items)
        
        permanent_items = load_permanent_items(PERMANENT_FILE)
        permanent_paths = set(permanent_items.get('permanent_items', []))
        
        existing_catalog = load_catalog(CATALOG_FILE)
        existing_children = existing_catalog.get('children', [])
        
        merged_children = merge_with_permanent(items, existing_children, permanent_paths)
        
        existing_catalog['children'] = merged_children
        existing_catalog['modified'] = get_current_timestamp()
        save_catalog(CATALOG_FILE, existing_catalog)
        log(f"Каталог сохранён в {CATALOG_FILE}")
        
        audit_upload_success('ftp_parser', object_type='catalog', 
                           description=f'Успешный парсинг FTP: найдено {len(items)} элементов',
                           additional_data={'items_count': len(items), 'images_count': len(all_images)})
        
        parser_status['last_run'] = get_full_timestamp()
        parser_status['message'] = f'Парсинг завершён успешно. Найдено элементов: {len(items)}. Всего изображений: {len(all_images)}'
        log(f"Итоговый статус: {parser_status['message']}")
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        parser_status['message'] = f'Ошибка парсинга: {str(e)}'
        
        error_details = {
            'type': type(e).__name__,
            'message': str(e),
            'url': None,
            'timeout': PARSER_TIMEOUT,
            'http_status': None,
            'response_headers': None,
            'response_body': None,
            'reason': None,
            'traceback': error_traceback
        }
        
        if hasattr(e, 'request') and e.request is not None:
            error_details['url'] = e.request.url
            error_details['method'] = e.request.method
        if hasattr(e, 'response') and e.response is not None:
            error_details['http_status'] = e.response.status_code
            error_details['response_headers'] = dict(e.response.headers)
            error_details['response_body'] = str(e.response.text[:500])
        if hasattr(e, 'reason'):
            error_details['reason'] = str(e.reason)
        
        log(f"ОШИБКА в run_parser_task(): {str(e)}", log_type='error', error_details=error_details)
        
        audit_error('parser_error', 'ftp_parser', 
                   description=f'Ошибка парсинга FTP: {str(e)}',
                   exception=e,
                   additional_data=error_details)
    finally:
        parser_status['running'] = False
        log(f"Завершение run_parser_task(). Статус: running={parser_status['running']}")


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(RATELIMIT_LOGIN)
def login():
    if current_user.is_authenticated:
        return redirect(URL_PREFIX + '/admin')
    
    error = None
    next_page = request.args.get('next')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        user_obj = authenticate_user(username, password)
        
        if user_obj:
            login_user(user_obj, remember=remember)
            flash('Вы успешно вошли в систему', 'success')
            redirect_url = get_safe_redirect_url(next_page)
            return redirect(redirect_url)
        else:
            if not username or not password:
                error = 'Введите имя пользователя и пароль'
            else:
                error = 'Неверное имя пользователя или пароль'
    
    return render_template(
        'login.html', 
        error=error, 
        get_prefixed_login_url=lambda: URL_PREFIX + '/login',
        next_page=next_page
    )


def authenticate_user(username, password):
    if not username or not password:
        return None
    
    users_data = load_users(USERS_FILE, hash_password)
    
    for user in users_data.get('users', []):
        if user['username'] == username:
            if verify_password(password, user['password_hash']):
                return User(
                    user['id'], 
                    user['username'], 
                    user.get('is_admin', False)
                )
            return None
    return None


def get_safe_redirect_url(next_page):
    if not next_page:
        return URL_PREFIX + '/admin'
    
    if not next_page.startswith(URL_PREFIX):
        return URL_PREFIX + '/' + next_page.lstrip('/')
    
    return next_page


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(URL_PREFIX + '/')


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            flash('Заполните все поля', 'error')
            return redirect(URL_PREFIX + '/change-password')
        
        if new_password != confirm_password:
            flash('Новые пароли не совпадают', 'error')
            return redirect(URL_PREFIX + '/change-password')
        
        if len(new_password) < 6:
            flash('Пароль должен быть не менее 6 символов', 'error')
            return redirect(URL_PREFIX + '/change-password')
        
        users_data = load_users(USERS_FILE, hash_password)
        user_found = None
        user_index = None
        for idx, user in enumerate(users_data.get('users', [])):
            if user['username'] == current_user.username:
                user_found = user
                user_index = idx
                break
        
        if not user_found or not verify_password(current_password, user_found['password_hash']):
            flash('Текущий пароль неверен', 'error')
            return redirect(URL_PREFIX + '/change-password')
        
        users_data['users'][user_index]['password_hash'] = hash_password(new_password)
        save_users(USERS_FILE, users_data)
        
        flash('Пароль успешно изменён', 'success')
        return redirect(URL_PREFIX + '/admin')
    
    return render_template('change_password.html')


@app.route('/')
def index():
    try:
        audit_catalog_item_open(
            item_path='/',
            item_name='Главная страница',
            status_code=200,
            item_type='index',
            description='Открытие главной страницы каталога'
        )
    except Exception as e:
        app.logger.error(f"Ошибка аудита главной страницы: {e}")
    
    response = send_from_directory('.', 'index.html')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/content')
def content_page():
    """
    Страница содержания (аккордеон)
    """
    response = render_template('content.html')
    # Добавляем заголовки для предотвращения кэширования
    response = make_response(response)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


@app.route('/admin')
@login_required
@admin_required_decorator
def admin():
    try:
        ip_address = request.remote_addr or '127.0.0.1'
        user_id = getattr(g, 'user_id', None)
        username = getattr(g, 'username', 'anonymous')
        
        audit_catalog_item_open(
            item_path='/admin',
            item_name='Панель администратора',
            status_code=200,
            item_type='admin_page',
            description='Открытие панели администратора',
            ip_address=ip_address,
            user_id=user_id,
            username=username
        )
    except Exception as e:
        app.logger.error(f"Ошибка аудита панели администратора: {e}")
    
    response = send_from_directory('.', 'admin.html')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/video-player')
def video_player():
    try:
        ip_address = request.remote_addr or '127.0.0.1'
        user_id = getattr(g, 'user_id', None)
        username = getattr(g, 'username', 'anonymous')
        
        audit_catalog_item_open(
            item_path='/video-player',
            item_name='Видеоплеер',
            status_code=200,
            item_type='video_player_page',
            description='Открытие страницы видеоплеера',
            ip_address=ip_address,
            user_id=user_id,
            username=username
        )
    except Exception as e:
        app.logger.error(f"Ошибка аудита видеоплеера: {e}")
    
    response = send_from_directory('.', 'video-player.html')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/api/catalog')
def get_catalog():
    audit_web_resource('view', 'catalog', description='Просмотр каталога веб-ресурсов')
    
    catalog = load_catalog(CATALOG_FILE)
    permanent_items = load_permanent_items(PERMANENT_FILE)
    permanent_paths = set(permanent_items.get('permanent_items', []))
    mark_permanent_recursive(catalog.get('children', []), permanent_paths)
    
    response = jsonify(catalog)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/api/parser/status')
@login_required
@admin_required_decorator
def get_parser_status():
    return jsonify({
        'status': parser_status.get('running', False),
        'running': parser_status.get('running', False),
        'last_run': parser_status.get('last_run'),
        'message': parser_status.get('message', 'Нет данных'),
        'images': parser_status.get('images', []),
        'logs': parser_logs[-50:],
        'error_logs_available': os.path.exists(ERROR_LOG_FILE)
    })


@app.route('/api/parser/start', methods=['POST'])
@login_required
@admin_required_decorator
@csrf.exempt
def start_parser():
    if not parser_status['running']:
        parser_status['running'] = True
        parser_status['message'] = 'Парсинг запущен...'
        
        thread = threading.Thread(target=run_parser_task)
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'started'})
    return jsonify({'status': 'already_running'})


@app.route('/api/parser/reset', methods=['POST'])
@login_required
@admin_required_decorator
@csrf.exempt
def reset_parser():
    global parser_status
    parser_status = {'running': False, 'last_run': None, 'message': 'Парсер не запущен', 'images': parser_status.get('images', [])}
    return jsonify({'status': 'reset'})


@app.route('/api/audit/logs', methods=['GET', 'POST', 'OPTIONS'])
@csrf.exempt
def handle_audit_logs():
    from flask_login import current_user
    
    if request.method == 'OPTIONS':
        response = make_response('')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRFToken'
        return response
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            if not data or 'event_type' not in data or 'object_id' not in data:
                return jsonify({'error': 'Требуемые поля: event_type и object_id'}), 400
            
            event_type = data.get('event_type')
            object_id = data.get('object_id')
            object_type = data.get('object_type', 'web_event')
            description = data.get('description', '')
            additional_data = data.get('additional_data', {})
            status = data.get('status')
            
            username = current_user.username if hasattr(current_user, 'username') and current_user.is_authenticated else None
            
            from utils.audit_utils import log_audit_event
            audit_entry = log_audit_event(
                event_type=event_type,
                object_id=object_id,
                object_type=object_type,
                description=description,
                additional_data=additional_data,
                username=username,
                status=status
            )
            
            return jsonify({
                'success': True,
                'message': 'Событие аудита сохранено',
                'audit_id': audit_entry.get('id')
            }), 201
            
        except Exception as e:
            app.logger.error(f"Ошибка при сохранении события аудита: {e}")
            return jsonify({'error': f'Ошибка: {str(e)}'}), 500
    
    else:
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Требуется авторизация администратора'}), 403
        
        try:
            date = request.args.get('date')
            limit = int(request.args.get('limit', 100))
            offset = int(request.args.get('offset', 0))
            event_type = request.args.get('event_type')
            object_id = request.args.get('object_id')
            
            result = load_audit_logs(
                date=date,
                limit=limit,
                offset=offset,
                event_type=event_type,
                object_id=object_id
            )
            
            return jsonify(result)
        except ValueError as e:
            return jsonify({'error': f'Неверный формат параметров: {str(e)}'}), 400
        except Exception as e:
            audit_error('audit_logs_error', 'audit_logs', 
                       description=f'Ошибка получения журнала аудита: {str(e)}',
                       exception=e)
            return jsonify({'error': f'Ошибка: {str(e)}'}), 500


@app.route('/api/permanent', methods=['GET', 'POST', 'DELETE'])
@login_required
@admin_required_decorator
@csrf.exempt
def permanent_api():
    permanent_data = load_permanent_items(PERMANENT_FILE)
    
    if request.method == 'POST':
        path = request.json.get('path')
        if path and path not in permanent_data['permanent_items']:
            permanent_data['permanent_items'].append(path)
            save_permanent_items(PERMANENT_FILE, permanent_data)
        return jsonify({'status': 'success'})
    
    elif request.method == 'DELETE':
        path = request.json.get('path')
        if path in permanent_data['permanent_items']:
            permanent_data['permanent_items'].remove(path)
            save_permanent_items(PERMANENT_FILE, permanent_data)
        return jsonify({'status': 'success'})
    
    return jsonify(permanent_data)


@app.route('/api/items', methods=['POST', 'PUT', 'DELETE'])
@login_required
@admin_required_decorator
@csrf.exempt
def items_api():
    catalog = load_catalog(CATALOG_FILE)
    data = request.json or {}
    path = data.get('path', '').strip('/')

    def get_target_list(parent_path):
        if not parent_path:
            return catalog['children']
        parent = find_item_by_path(catalog['children'], parent_path)
        return parent.get('children') if parent else None

    if request.method == 'POST':
        parent_path = data.get('parent_path', '')
        target = get_target_list(parent_path)
        if target is None:
            return jsonify({'error': 'Родительская папка не найдена'}), 404

        new_item = {
            'name': data.get('name'),
            'icon': data.get('icon', 'folder.png'),
            'children': []
        }
        if data.get('url'):
            new_item['url'] = data['url']

        target.append(new_item)
        save_catalog(CATALOG_FILE, catalog)

        return jsonify({'status': 'success', 'message': 'Элемент создан'})

    elif request.method == 'PUT':
        updates = data.get('updates', {})
        if updates.get('icon'):
            updates['permanent'] = True

        success = update_item_by_path(catalog['children'], path, updates)
        if not success:
            return jsonify({'error': 'Элемент не найден'}), 404

        save_catalog(CATALOG_FILE, catalog)
        return jsonify({'status': 'success', 'message': 'Элемент обновлён'})

    elif request.method == 'DELETE':
        if delete_item_by_path(catalog['children'], path):
            save_catalog(CATALOG_FILE, catalog)
            return jsonify({'status': 'success', 'message': 'Элемент удалён'})
        return jsonify({'error': 'Элемент не найден'}), 404

    return jsonify({'error': 'Недопустимый метод'}), 400


@app.route('/api/images')
def get_images():
    images = []
    seen_paths = set()
    
    parser_images_data = load_json_file(PARSER_IMAGES_FILE, default={'images': []})
    parser_images = parser_images_data.get('images', [])
    
    for icon_url in parser_images:
        normalized_url = normalize_url(icon_url)
        if normalized_url and normalized_url not in seen_paths:
            try:
                decoded_url = unquote(normalized_url)
                filename = decoded_url.split('/')[-1]
            except:
                filename = os.path.basename(normalized_url)
            images.append({'name': filename, 'path': normalized_url})
            seen_paths.add(normalized_url)
    
    if parser_status.get('images'):
        for icon_url in parser_status['images']:
            normalized_url = normalize_url(icon_url)
            if normalized_url and normalized_url not in seen_paths:
                try:
                    decoded_url = unquote(normalized_url)
                    filename = decoded_url.split('/')[-1]
                except:
                    filename = os.path.basename(normalized_url)
                images.append({'name': filename, 'path': normalized_url})
                seen_paths.add(normalized_url)
    
    response = Response(json.dumps(images, ensure_ascii=False), mimetype='application/json; charset=utf-8')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/page/<path:filename>')
def serve_page_image(filename):
    page_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'page')
    return send_from_directory(page_dir, filename, max_age=86400)


@app.route('/css/<path:filename>')
def serve_css(filename):
    css_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'css')
    response = send_from_directory(css_dir, filename, max_age=86400)
    response.headers['Content-Type'] = 'text/css; charset=utf-8'
    return response


@app.route('/js/<path:filename>')
def serve_js(filename):
    js_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'js')
    response = send_from_directory(js_dir, filename, max_age=86400)
    response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return response


@app.route('/api/video-proxy')
def proxy_video():
    video_url = request.args.get('url', '')
    
    if not video_url:
        return jsonify({'error': 'URL не указан'}), 400
    
    parsed = urlparse(video_url)
    allowed_domains = ['vm-ftp.anosov.ru', 'testnavi.onrender.com']
    if parsed.netloc not in allowed_domains:
        return jsonify({'error': 'Недоверенный домен'}), 403
    
    try:
        video_content_types = {
            '.mp4': 'video/mp4',
            '.webm': 'video/webm',
            '.ogg': 'video/ogg',
            '.mov': 'video/quicktime',
            '.avi': 'video/x-msvideo',
            '.mkv': 'video/x-matroska',
            '.flv': 'video/x-flv',
            '.wmv': 'video/x-ms-wmv',
            '.m4v': 'video/x-m4v'
        }

        from urllib.parse import unquote
        decoded_url = unquote(video_url).strip()
        ext = os.path.splitext(decoded_url)[1].lower()
        content_type = video_content_types.get(ext, 'video/mp4')

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        }
        
        head_response = requests.head(video_url, headers=headers, timeout=30, allow_redirects=True, verify=False)
        head_response.raise_for_status()
        file_size = int(head_response.headers.get('Content-Length', 0))
        
        supports_ranges = head_response.headers.get('Accept-Ranges', '').lower() == 'bytes'
        
        range_header = request.headers.get('Range', '')
        
        if range_header and supports_ranges and file_size > 0:
            range_match = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if range_match:
                start = int(range_match.group(1))
                end = int(range_match.group(2)) if range_match.group(2) else file_size - 1
                end = min(end, file_size - 1)
                
                headers['Range'] = f'bytes={start}-{end}'
                response = requests.get(video_url, headers=headers, timeout=60, stream=True, verify=False)
                response.raise_for_status()
                
                proxy_response = Response(
                    response.iter_content(chunk_size=8192),
                    status=206,
                    mimetype=content_type
                )
                proxy_response.headers['Content-Length'] = str(end - start + 1)
                proxy_response.headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'
                proxy_response.headers['Accept-Ranges'] = 'bytes'
                proxy_response.headers['Content-Disposition'] = f'inline; filename*=UTF-8\'\'{os.path.basename(decoded_url)}'
                proxy_response.headers.pop('X-Download-Options', None)
                return proxy_response
        
        response = requests.get(video_url, headers=headers, timeout=60, stream=True, verify=False)
        response.raise_for_status()
        
        proxy_response = Response(
            response.iter_content(chunk_size=8192),
            status=response.status_code,
            mimetype=content_type
        )

        if file_size > 0:
            proxy_response.headers['Content-Length'] = str(file_size)

        proxy_response.headers['Content-Disposition'] = f'inline; filename*=UTF-8\'\'{os.path.basename(decoded_url)}'
        proxy_response.headers['Accept-Ranges'] = 'bytes'
        proxy_response.headers['Cache-Control'] = 'public, max-age=3600'
        proxy_response.headers.pop('X-Download-Options', None)
        proxy_response.headers.pop('Content-Transfer-Encoding', None)

        return proxy_response

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Ошибка загрузки видео: {str(e)}'}), 500


if __name__ == '__main__':
    # Убедиться, что директория данных существует
    ensure_data_dir(DATA_DIR)
    
    # Инициализировать файл пользователей если не существует
    load_users(USERS_FILE, hash_password)
    
    print("🚀 Запуск сервера...")
    app.run(debug=True, host='0.0.0.0', port=5000)