# -*- coding: utf-8 -*-
import os
import io
import base64
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg') # Usar backend no interactivo ANTES de importar pyplot
import matplotlib.pyplot as plt
import seaborn as sns
import datetime
import traceback
import pytz
import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func # Para func.count y func.distinct
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response, send_file
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from functools import wraps
try:
    from data_manager import DataManager
    from threat_simulator import ThreatSimulator
    from threat_detector import ThreatDetector
    from alert_manager import AlertManager
    from admin_manager import AdminManager
    print("DEBUG: Clases Manager importadas OK.")
except ImportError as e:
    print(f"FATAL ERROR: No se pudo importar clase manager: {e}")
    print("Asegúrate que los archivos .py de las clases (data_manager.py, etc.) estén en la misma carpeta que app.py o sean instalables.")
    exit()
print("DEBUG: Definiendo decorador admin_required...")
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not hasattr(current_user, 'is_admin') or not current_user.is_admin:
            flash("Acceso no autorizado. Solo para administradores.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
print("DEBUG: Creando instancia de Flask app...")
app = Flask(__name__)
print("DEBUG: Instancia Flask creada.")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3_v6")
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
TEMP_SIM_FOLDER = os.path.join(BASE_DIR, 'temp_sim_data')
SAVED_PLOTS_FOLDER = os.path.join(BASE_DIR, 'saved_plots')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['SAVED_PLOTS_FOLDER'] = SAVED_PLOTS_FOLDER
app.config['MODEL_FOLDER'] = MODEL_DIR
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
print(f"DEBUG: Carpetas configuradas: UPLOAD={app.config['UPLOAD_FOLDER']}, TEMP_SIM={app.config['TEMP_SIM_FOLDER']}, PLOTS={app.config['SAVED_PLOTS_FOLDER']}, MODELS={app.config['MODEL_FOLDER']}")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "cyber_db")
db_uri = f'mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
print(f"DEBUG: Configurando URI de BD: {db_uri[:db_uri.find('@')+1]}********")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
print("DEBUG: Inicializando SQLAlchemy...")
try:
    db = SQLAlchemy(app)
    print("DEBUG: SQLAlchemy inicializado.")
except Exception as e_sql:
    print(f"FATAL ERROR: Inicializando SQLAlchemy: {e_sql}"); exit()
print("DEBUG: Inicializando LoginManager...")
try:
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
    login_manager.login_message_category = "info"
    print("DEBUG: Configuración LoginManager completa.")
except Exception as e_login:
    print(f"FATAL ERROR: Inicializando LoginManager: {e_login}"); exit()
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_SIM_FOLDER'], exist_ok=True)
os.makedirs(app.config['SAVED_PLOTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
try:
    print("DEBUG: Inicializando Managers...")
    data_manager = DataManager(upload_folder='uploads', processed_filename='datos_preprocesados.csv')
    simulator = ThreatSimulator()
    alert_manager = AlertManager()
    detector = ThreatDetector(model_dir=app.config['MODEL_FOLDER'])
    admin_manager = AdminManager(detector_instance=detector)
    print("DEBUG: Managers inicializados.")
    if hasattr(admin_manager, 'load_system_config'):
        system_config = admin_manager.load_system_config()
        print(f"DEBUG: Configuración del sistema cargada desde AdminManager: {system_config}")
    else:
        system_config = {'glm_threshold': 0.7} # Valor por defecto si no se puede cargar
        print(f"DEBUG: Configuración del sistema inicializada por defecto: {system_config}")
        
    if hasattr(detector, 'prediction_threshold'): # Sincronizar umbral del detector con la config cargada/default
        detector.prediction_threshold = system_config.get('glm_threshold', 0.7)
except NameError as ne:
     print(f"FATAL ERROR: Parece que una clase Manager no está definida o importada: {ne}"); exit()
except Exception as e:
    print(f"FATAL ERROR inicializando manager o cargando config: {e}\n{traceback.format_exc()}"); exit()
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) # bcrypt hashes are typically 60 chars
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def set_password(self, password):
        try:
            password_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        except Exception as e: print(f"Error al hashear la contraseña para {self.username}: {e}"); raise ValueError("Error al establecer la contraseña") from e
    def check_password(self, password):
        if not self.password_hash: print(f"WARN: Intento de verificar contraseña sin hash para usuario {self.id}"); return False
        try:
            password_bytes = password.encode('utf-8')
            stored_hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, stored_hash_bytes)
        except ValueError as ve: print(f"ERROR (ValueError) al verificar contraseña para usuario {self.id}: {ve}. Hash inválido?"); return False
        except Exception as e: print(f"ERROR general al verificar contraseña para usuario {self.id}: {e}"); return False
        
    def __repr__(self): return f'<User {self.username}>'
class UserActivityLog(db.Model):
    __tablename__ = 'user_activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    user = db.relationship('User', backref=db.backref('activity_logs', lazy='dynamic'))
    def __repr__(self):
        return f'<UserActivityLog User:{self.user_id} - Action:{self.action} @ {self.timestamp}>'
print("DEBUG: Modelo User definido.")
@login_manager.user_loader
def load_user(user_id):
    print(f"DEBUG: load_user llamado para ID: {user_id}")
    try:
        user = db.session.get(User, int(user_id))
        if user: print(f"DEBUG: Usuario {user.username} encontrado.")
        else: print(f"DEBUG: Usuario ID {user_id} no encontrado.")
        return user
    except ValueError: print(f"ERROR: ID de usuario inválido: {user_id}"); return None
    except Exception as e: print(f"ERROR cargando usuario ID {user_id}: {e}"); return None
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember_me = BooleanField('Recuérdame')
    submit = SubmitField('Iniciar Sesión')
class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password', message='Las contraseñas no coinciden.')])
    submit = SubmitField('Registrarse')
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('Este nombre de usuario ya existe. Por favor, elige otro.')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first(): raise ValidationError('Este email ya está registrado. Por favor, usa otro.')
class UserAdminForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Nueva Contraseña (dejar vacío para no cambiar)')
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email
    def validate_username(self, username):
        if username.data != self.original_username:
            if User.query.filter_by(username=username.data).first(): raise ValidationError('Este nombre de usuario ya existe.')
    def validate_email(self, email):
        if email.data != self.original_email:
            if User.query.filter_by(email=email.data).first(): raise ValidationError('Este email ya está registrado.')
class DeleteUserForm(FlaskForm): # Usado para CSRF en la eliminación de usuarios
    submit = SubmitField('Eliminar Usuario')
class DeleteLogsForm(FlaskForm): # Nuevo formulario para CSRF en eliminación de logs
    submit = SubmitField('Eliminar Logs')
    
print("DEBUG: Formularios definidos.")
@app.context_processor
def inject_global_vars(): return {'current_year': datetime.datetime.now().year, 'now': datetime.datetime.now}
@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%Y-%m-%d %H:%M:%S'):
    if not value:
        return "N/A"
    local_tz = pytz.timezone('America/Guayaquil') # Define your local timezone
    if isinstance(value, str):
        dt = None
        # Try to parse ISO format string which might come from session or other sources
        try:
            # Handle strings that might have fractional seconds
            dt_naive = datetime.datetime.fromisoformat(value.split('.')[0]) if '.' in value else datetime.datetime.fromisoformat(value)
            # Assume the string timestamp is in UTC if it's coming from DB or similar utcnow() source
            dt_utc = pytz.utc.localize(dt_naive)
            dt_local = dt_utc.astimezone(local_tz)
            return dt_local.strftime(format)
        except ValueError:
            # Fallback for other string formats if needed
            for fmt_str in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
                try:
                    dt_naive = datetime.datetime.strptime(value, fmt_str)
                    # Assume the string timestamp is in UTC
                    dt_utc = pytz.utc.localize(dt_naive)
                    dt_local = dt_utc.astimezone(local_tz)
                    return dt_local.strftime(format)
                except ValueError:
                    pass
            print(f"WARN: format_datetime no pudo parsear string con zona horaria: {value}")
            return value # Return original if all parsing fails
    elif isinstance(value, datetime.datetime):
        try:
            if value.tzinfo is None: # If naive datetime, assume it's UTC from utcnow()
                dt_utc = pytz.utc.localize(value)
            else: # If already timezone-aware, ensure it's UTC before converting
                dt_utc = value.astimezone(pytz.utc)
            
            dt_local = dt_utc.astimezone(local_tz)
            return dt_local.strftime(format)
        except Exception as e_fmt:
            print(f"WARN: format_datetime err formateando dt con zona horaria: {e_fmt}")
            return str(value) # Fallback
    else:
        print(f"WARN: format_datetime recibió tipo inesperado: {type(value)}")
        return str(value)
def generate_last_detection_csv(results):
    if not results: return None
    output = io.StringIO()
    try:
        output.write(f"Reporte Última Detección\n")
        output.write(f"Timestamp,{results.get('ts', 'N/A')}\n")
        output.write(f"Fuente Datos,{results.get('src', 'N/A')}\n")
        output.write(f"Filas Analizadas,{results.get('rows', 'N/A')}\n")
        output.write(f"Umbral GLM,{results.get('thr', 'N/A')}\n\n")
        metrics = results.get('metrics', {})
        if metrics:
            output.write("Metricas Modelo:\nMetrica,Valor\n")
            simple_metrics = {k: v for k, v in metrics.items() if isinstance(v, (int, float, str, bool)) and k not in ['report', 'confusion_matrix', 'classes']}
            for name, value in simple_metrics.items():
                output.write(f"{name.replace('_', ' ').title()},{value}\n")
            report = metrics.get('report', {})
            if report and isinstance(report, dict):
                output.write("\nReporte Clasificacion:\n")
                try:
                    pd.DataFrame(report).transpose().to_csv(output, index=True, header=True, float_format='%.4f')
                except Exception as e_rep_csv:
                    output.write(f"Error_generando_reporte_clasificacion,{e_rep_csv}\n")
            cm = metrics.get('confusion_matrix')
            if cm is not None:
                output.write("\nMatriz Confusion:\n")
                try:
                    cm_arr = np.array(cm)
                    classes = metrics.get('classes', ['BENIGN', 'ATTACK'])
                    output.write("," + ",".join([f"Prediccion {c}" for c in classes]) + "\n")
                    for i, row_data in enumerate(cm_arr):
                        output.write(f"Real {classes[i]}," + ",".join(map(str, row_data)) + "\n")
                except Exception as e_cm_csv:
                    output.write(f"Error_generando_matriz_confusion,{e_cm_csv}\n")
        summary = results.get('summary', {})
        if summary:
            output.write("\nResumen Detecciones:\nEtiqueta,Cantidad\n")
            for label, count in summary.items():
                output.write(f"{label},{count}\n")
        head = results.get('head', []) # 'head' might not exist if run_detection doesn't provide it
        if head and isinstance(head, (list, pd.DataFrame)): # check if head is a list (of dicts) or DataFrame
            output.write("\nVista Previa Resultados (Primeras Filas):\n")
            try:
                # Ensure head is a DataFrame for to_csv
                if isinstance(head, list):
                    df_head = pd.DataFrame(head)
                else: # it's already a DataFrame
                    df_head = head
                
                if not df_head.empty:
                     df_head.to_csv(output, index=False, header=True)
                else:
                    output.write("No_hay_datos_en_vista_previa\n")

            except Exception as e_head_csv:
                output.write(f"Error_generando_vista_previa,{e_head_csv}\n")
        output.seek(0)
        return output.getvalue()
    except Exception as e_csv:
        print(f"Error generando CSV completo: {e_csv}")
        return None
print("DEBUG: Funciones reporte OK.")
def generate_plot_base64_and_save(plot_func, *args, **kwargs):
    img_buffer = io.BytesIO()
    fig = None
    save_dir = kwargs.pop('save_dir', app.config.get('SAVED_PLOTS_FOLDER', os.path.join(BASE_DIR, 'saved_plots')))
    save_plot = kwargs.pop('save_plot', True)

    if save_plot:
        try:
            os.makedirs(save_dir, exist_ok=True)
        except Exception as e_mkdir:
            print(f"FATAL ERROR: No se pudo crear el directorio para guardar gráficos en '{save_dir}': {e_mkdir}")
            save_plot = False

    try:
        fig = plt.figure(figsize=kwargs.pop('figsize', (6, 4)))
        plot_func(fig=fig, *args, **kwargs)
        plt.tight_layout()
        plt.savefig(img_buffer, format='png', bbox_inches='tight')
        img_buffer.seek(0)
        base64_url = f"data:image/png;base64,{base64.b64encode(img_buffer.getvalue()).decode('utf8')}"
        
        filename = None
        if save_plot:
            if not save_dir:
                print("WARN plot_save: Directorio para guardar gráficos (save_dir) no configurado.")
                return base64_url, None
            else:
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                
                # --- CAMBIO CLAVE AQUÍ ---
                # 1. Obtenemos el título original (ej: "Matriz Confusión (Última Detección)")
                title_raw = kwargs.get('title', 'plot')
                # 2. Aplicamos secure_filename para limpiar acentos y caracteres especiales ANTES de guardar
                safe_base_filename = secure_filename(title_raw)
                # 3. Construimos el nombre de archivo final usando la base ya limpia
                filename = f"{safe_base_filename}_{ts}.png"
                # --- FIN DEL CAMBIO CLAVE ---
                
                filepath = os.path.join(save_dir, filename)
                
                try:
                    with open(filepath, 'wb') as f:
                        f.write(img_buffer.getvalue())
                    print(f"SUCCESS: Gráfico guardado exitosamente en: {filepath}")
                    if not os.path.exists(filepath):
                        print(f"ERROR CRÍTICO: El sistema operativo no creó el archivo en {filepath}.")
                        filename = None
                except Exception as e_save:
                    print(f"ERROR al guardar el gráfico en el archivo {filepath}: {e_save}")
                    filename = None
        
        return base64_url, filename

    except Exception as e:
        print(f"ERROR generando/guardando plot: {e}\n{traceback.format_exc()}")
        return None, None
    finally:
        if fig:
            plt.close(fig)
def plot_confusion_matrix_func(cm, fig, classes=None, title='Matriz Confusión'):
    if classes is None: classes = ['BENIGN', 'ATTACK']
    ax = fig.add_subplot(111); cm_arr = np.array(cm); sns.heatmap(cm_arr, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False, xticklabels=classes, yticklabels=classes, annot_kws={"size": 10}); ax.set_xlabel('Predicción'); ax.set_ylabel('Real');
    ax.set_title(title)
print("DEBUG: Funciones gráficos OK.")
# --- RUTAS AUTENTICACIÓN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            try:
                log_entry = UserActivityLog(user_id=user.id, action='inicio_sesion', details=f"Inicio de sesión desde IP: {request.remote_addr}")
                db.session.add(log_entry)
                db.session.commit()
                print(f"INFO: Usuario {user.username} inició sesión.")
            except Exception as e:
                print(f"Error al registrar actividad de inicio de sesión para {user.username}: {e}")
            
            flash(f'Inicio de sesión exitoso para {user.username}.', 'success')
            next_page = request.args.get('next')
            if next_page and urlparse(next_page).netloc == '': print(f"DEBUG: Redirigiendo a 'next' page: {next_page}"); return redirect(next_page)
            else: print("DEBUG: Redirigiendo al dashboard."); return redirect(url_for('dashboard'))
        else: flash('Login fallido. Verifica usuario y contraseña.', 'error'); print(f"WARN: Login fallido para usuario: {form.username.data}")
    return render_template('login.html', title='Iniciar Sesión', form=form)
@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        try:
            log_entry = UserActivityLog(user_id=current_user.id, action='cierre_sesion')
            db.session.add(log_entry)
            db.session.commit()
            print(f"INFO: Usuario {current_user.username} cerró sesión.")
        except Exception as e:
            print(f"Error al registrar actividad de cierre de sesión para {current_user.username}: {e}")
    logout_user()
    flash('Has cerrado sesión correctamente.', 'info'); return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            user.is_admin = (User.query.count() == 0); db.session.add(user)
            db.session.commit()
            flash(f'¡Cuenta creada para {form.username.data}! Ahora puedes iniciar sesión.', 'success')
            print(f"INFO: Nuevo usuario registrado: {form.username.data}{' (admin)' if user.is_admin else ''}")
            try:
                log_details = f"Usuario {user.username} creado."
                if current_user.is_authenticated and current_user.is_admin: # Aunque current_user no debería estar auth aquí
                     log_details = f"Usuario {user.username} creado por admin {current_user.username}." # Esto es más para creación desde admin
                log_entry = UserActivityLog(user_id=user.id, action='creacion_usuario', details=log_details)
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e:
                print(f"Error al registrar actividad de creación de usuario para {user.username}: {e}")
            return redirect(url_for('login'))
        except ValidationError as ve: print(f"WARN: Error de validación en registro: {ve}") # Esto no debería ocurrir con validate_on_submit
        except Exception as e:
            db.session.rollback()
            err_msg = str(e)
            if 'Duplicate entry' in err_msg: # Chequeo más específico
                if f"'{form.username.data}'" in err_msg and 'for key \'users.username\'' in err_msg: flash('Error: El nombre de usuario ya existe.', 'error')
                elif f"'{form.email.data}'" in err_msg and 'for key \'users.email\'' in err_msg: flash('Error: El email ya está registrado.', 'error')
                else: flash(f'Error de base de datos (duplicado no especificado): {err_msg}', 'error')
            else: flash(f'Error al crear la cuenta: {err_msg}', 'error')
            print(f"ERROR al registrar usuario {form.username.data}: {e}\n{traceback.format_exc()}")
        return render_template('register.html', title='Registro', form=form) # Para mostrar errores de validación del form
    return render_template('register.html', title='Registro', form=form)
# --- RUTAS PRINCIPALES ---
@app.route('/')
@login_required
def dashboard():
    print("DEBUG: Accediendo a /dashboard")
    try:
        log_entry = UserActivityLog(user_id=current_user.id, action='acceso_panel_control')
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Error al registrar acceso al panel de control para {current_user.username}: {e}")
    active_alerts = []; last_detection = None; model_status = "No Disponible"; recent_alerts = []
    try:
        active_alerts = alert_manager.get_alerts(show_all=False)
        detection_history = alert_manager.get_detection_history()
        last_detection = detection_history[-1] if detection_history else None
        model_is_loaded = (detector is not None and hasattr(detector, 'model') and detector.model is not None)
        model_status = "Modelo Cargado     ✅    " if model_is_loaded else "Modelo No Cargado     ❌    "
        all_alerts_sorted = alert_manager.get_alerts(show_all=True) # Ordenadas por timestamp desc
        recent_alerts = all_alerts_sorted[:5]
    except AttributeError as ae: print(f"ERROR: Atributo/Método faltante en manager para dashboard: {ae}"); flash(f"Error interno ({ae}).", "danger"); model_status = "Error Interno"
    except Exception as e: print(f"ERROR cargando datos del dashboard: {e}\n{traceback.format_exc()}"); flash("Error al cargar los datos del dashboard.", "error"); active_alerts, last_detection, model_status, recent_alerts = [], None, "Error", []
    return render_template('dashboard.html', active_alerts_count=len(active_alerts), last_detection=last_detection, model_status=model_status, recent_alerts=recent_alerts)
@app.route('/data', methods=['GET', 'POST'])
@login_required
def manage_data():
    if request.method == 'POST':
        action = request.form.get('action')
        url = url_for('manage_data') # Definir url una vez
        try:
            if action == 'upload':
                if 'file' not in request.files: flash('No se incluyó el archivo.', 'error'); return redirect(url)
                file = request.files['file']; fname = file.filename
                if fname == '': flash('No se seleccionó ningún archivo.', 'warning'); return redirect(url)
                if file and allowed_file(fname):
                    fname = secure_filename(fname); fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname); file.save(fpath)
                    ok, result = data_manager.load_csv_data(fpath)
                    if ok:
                        flash(f"Archivo '{fname}' cargado.", 'success'); session['loaded_filepath'] = fpath; session.pop('processed_data_info', None)
                        try:
                            log_entry = UserActivityLog(user_id=current_user.id, action='carga_datos', details=f"Archivo: {fname}")
                            db.session.add(log_entry); db.session.commit()
                        except Exception as e: print(f"Error registrando carga de datos: {e}")
                    else: flash(f"Error al cargar '{fname}': {result}", 'error'); session.pop('loaded_filepath', None)
                elif file: flash(f"Tipo de archivo no permitido: '{fname}'. Solo CSV.", 'error')
            elif action == 'preprocess':
                df_loaded = data_manager.get_loaded_data()
                if df_loaded is not None and not df_loaded.empty:
                    try:
                        processed_df_result, msg = data_manager.preprocess_data(df_loaded.copy())
                        if processed_df_result is not None:
                            flash(msg, 'success'); session['processed_data_info'] = {'rows': len(processed_df_result), 'cols': len(processed_df_result.columns), 'ts': datetime.datetime.now().isoformat(timespec='seconds'), 'source_file': os.path.basename(session.get('loaded_filepath', 'N/A'))}
                            try:
                                log_entry = UserActivityLog(user_id=current_user.id, action='preprocesamiento_datos', details=f"Fuente: {session.get('processed_data_info', {}).get('source_file')}, Filas: {len(processed_df_result)}")
                                db.session.add(log_entry); db.session.commit()
                            except Exception as e: print(f"Error registrando preprocesamiento: {e}")
                        else: flash(f"Error en preprocesamiento: {msg}", 'error'); session.pop('processed_data_info', None)
                    except Exception as e_proc_call: print(f"ERROR llamando data_manager.preprocess_data: {e_proc_call}\n{traceback.format_exc()}"); flash(f"Error crítico preprocesamiento: {e_proc_call}", "danger"); session.pop('processed_data_info', None)
                else: flash('No hay datos cargados para preprocesar.', 'warning'); session.pop('processed_data_info', None)
            else: flash('Acción desconocida.', 'warning')
        except Exception as e: flash(f"Error crítico en gestión de datos: {e}", "error"); print(f"ERROR manage_data POST: {e}\n{traceback.format_exc()}"); session.pop('loaded_filepath', None); session.pop('processed_data_info', None)
        return redirect(url)
    if request.method == 'GET':
        try:
            log_entry = UserActivityLog(user_id=current_user.id, action='acceso_gestion_datos')
            db.session.add(log_entry); db.session.commit()
        except Exception as e: print(f"Error registrando acceso a gestión de datos: {e}")
    loaded_preview_headers = None; loaded_preview_data = None; processed_preview_headers = None; processed_preview_data = None
    p_info = session.get('processed_data_info'); l_path = session.get('loaded_filepath')
    l_fname = os.path.basename(l_path) if l_path and os.path.exists(l_path) else None
    try:
        df_loaded_for_preview = data_manager.get_loaded_data()
        if df_loaded_for_preview is not None and not df_loaded_for_preview.empty:
            df_loaded_head = df_loaded_for_preview.head(10); loaded_preview_headers = df_loaded_head.columns.tolist(); loaded_preview_data = [[item if pd.notna(item) else '' for item in row] for row in df_loaded_head.values.tolist()]
        df_processed_for_preview = data_manager.get_processed_data()
        if df_processed_for_preview is not None and not df_processed_for_preview.empty:
            df_processed_head = df_processed_for_preview.head(10); processed_preview_headers = df_processed_head.columns.tolist(); processed_preview_data = [[item if pd.notna(item) else '' for item in row] for row in df_processed_head.values.tolist()]
    except Exception as e: print(f"ERROR manage_data GET (previews): {e}\n{traceback.format_exc()}"); flash("Error preparando vistas previas.", "error")
    return render_template('data_management.html', loaded_filename=l_fname, processed_info=p_info, loaded_preview_headers=loaded_preview_headers, loaded_preview_data=loaded_preview_data, processed_preview_headers=processed_preview_headers, processed_preview_data=processed_preview_data)
@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    if request.method == 'POST':
        try:
            dur = int(request.form.get('duration', 60))
            intensity = int(request.form.get('intensity', 5))
            attacks_raw = request.form.getlist('attacks')
            attacks = [a.strip() for a in attacks_raw if isinstance(a, str) and a.strip()]
            if not attacks:
                attacks = ['DDoS', 'Scan']

            if dur <= 0: raise ValueError("Duración debe ser > 0.")
            if not (1 <= intensity <= 10): raise ValueError("Intensidad debe ser entre 1-10.")

            cfg = {"duration": dur, "intensity": intensity, "attacks": attacks}

            # Llamada al simulador (esto ya está bien)
            df_sim_result = simulator.run_simulation(cfg)

            if df_sim_result is not None and not df_sim_result.empty:
                sim_id = str(uuid.uuid4())
                fname = f"sim_data_{sim_id}.pkl"
                fpath = os.path.join(app.config['TEMP_SIM_FOLDER'], fname)
                try:
                    df_sim_result.to_pickle(fpath)
                    label_distribution = {}
                    if 'label' in df_sim_result.columns:
                        label_distribution = df_sim_result['label'].value_counts().to_dict()

                    session['simulation_info'] = {
                        'rows_generated': len(df_sim_result), 'config': cfg,
                        'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
                        'filepath': fpath, 'label_distribution': label_distribution
                    }
                    if hasattr(simulator, 'add_to_history'):
                        simulator.add_to_history(session['simulation_info'].copy())

                    flash(f'Simulación completada y guardada. Generados {len(df_sim_result)} registros.', 'success')

                    try:
                        log_details = f"Config: {cfg}, Filas generadas: {len(df_sim_result)}, Archivo: {fname}"
                        log_entry = UserActivityLog(user_id=current_user.id, action='ejecucion_simulador', details=log_details)
                        db.session.add(log_entry)
                        db.session.commit()
                    except Exception as e:
                        print(f"Error registrando ejecución de simulador: {e}")

                except Exception as e_save:
                    flash(f"Error guardando la simulación: {e_save}", "error")
                    print(f"ERROR guardando pickle de simulación: {e_save}\n{traceback.format_exc()}")
                    session.pop('simulation_info', None)
            else:
                flash('La simulación no generó datos.', 'warning')
                session.pop('simulation_info', None)

        except ValueError as ve:
            flash(f'Entrada inválida para la simulación: {ve}', 'error')
        except Exception as e:
            flash(f'Error inesperado en la simulación: {e}', 'error')
            print(f"ERROR simulate POST: {e}\n{traceback.format_exc()}")
            session.pop('simulation_info', None)

        return redirect(url_for('simulate'))

    # --- BLOQUE GET CORREGIDO ---
    # Este es el bloque que se ejecuta después de la redirección para mostrar la página
    if request.method == 'GET':
        try:
            log_entry = UserActivityLog(user_id=current_user.id, action='acceso_pagina_simulador')
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            print(f"Error registrando acceso a página de simulador: {e}")

        sim_info = session.get('simulation_info')
        history = simulator.get_history() if hasattr(simulator, 'get_history') else []
        
        # --- LÓGICA DE VISTA PREVIA RESTAURADA ---
        preview_headers = None
        preview_data = None
        
        if sim_info and sim_info.get('filepath') and os.path.exists(sim_info['filepath']):
            try:
                df_preview = pd.read_pickle(sim_info['filepath']).head(10)
                if not df_preview.empty:
                    preview_headers = df_preview.columns.tolist()
                    preview_data = [[item if pd.notna(item) else '' for item in row] for row in df_preview.values.tolist()]
                else:
                    flash("La Última simulación se ejecutó, pero no produjo datos válidos para la vista previa.", "warning")
            except Exception as e_load:
                print(f"WARN: No se pudo cargar el pickle de la simulación para la vista previa: {e_load}")
                flash("La Última simulación se ejecutó, pero no produjo datos válidos para la vista previa o hubo un error al cargarla.", "warning")
        
        return render_template('simulator.html',
                               simulation_history=history,
                               last_simulation_info=sim_info,
                               preview_headers=preview_headers,
                               preview_data=preview_data)
@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    history = alert_manager.get_detection_history()
    session_res = session.get('last_detection_results')
    # Inicialización de variables para la plantilla GET
    model_metrics_eval, evaluation_report_data, evaluation_cm_plot_url, evaluation_cm_filename = None, None, None, None
    detection_preview_headers, detection_preview_data, detection_preview_message = None, None, "Ejecute una nueva detección para ver la vista previa."
    detection_cm_plot_url, detection_cm_filename, active_alerts = None, None, []
    has_proc = data_manager.get_processed_data() is not None and not data_manager.get_processed_data().empty
    sim_info_session = session.get('simulation_info')
    has_sim = sim_info_session and sim_info_session.get('filepath') and os.path.exists(sim_info_session['filepath'])

    if request.method == 'GET':
        # El bloque GET no necesita cambios, está bien como está.
        try:
            log_entry = UserActivityLog(user_id=current_user.id, action='acceso_pagina_deteccion')
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            print(f"Error registrando acceso a página de detección: {e}")
        try:
            eval_metrics = detector.evaluate_on_test_set() if hasattr(detector, 'evaluate_on_test_set') else None
            if eval_metrics and isinstance(eval_metrics, dict) and eval_metrics.get('accuracy') is not None:
                model_metrics_eval = eval_metrics
                if model_metrics_eval.get('confusion_matrix') is not None:
                    try:
                        evaluation_cm_plot_url, evaluation_cm_filename = generate_plot_base64_and_save(
                            plot_confusion_matrix_func, model_metrics_eval['confusion_matrix'],
                            classes=model_metrics_eval.get('classes'), title='Matriz_Confusion_Evaluacion_General',
                            save_plot=True, save_dir=app.config['SAVED_PLOTS_FOLDER'])
                    except Exception as e_cm_gen:
                        print(f"ERROR generando plot CM eval: {e_cm_gen}")
                if model_metrics_eval.get('report') and isinstance(model_metrics_eval.get('report'), dict):
                    evaluation_report_data = model_metrics_eval.get('report')

            if session_res and session_res.get('metrics', {}).get('confusion_matrix') is not None:
                try:
                    detection_cm_plot_url, detection_cm_filename = generate_plot_base64_and_save(
                        plot_confusion_matrix_func, session_res['metrics']['confusion_matrix'],
                        classes=session_res['metrics'].get('classes'), title='Matriz_Confusion_Ultima_Deteccion',
                        save_plot=True, save_dir=app.config['SAVED_PLOTS_FOLDER'])
                except Exception as e_cm_det_sess:
                    print(f"ERROR generando plot CM última detección (sesión): {e_cm_det_sess}")
            try:
                active_alerts = alert_manager.get_alerts(show_all=False)
            except Exception as e_al:
                print(f"ERROR obteniendo alertas: {e_al}")
                flash("Error cargando alertas.", "error")
        except Exception as e_get_main:
            print(f"ERROR general en GET /detect: {e_get_main}\n{traceback.format_exc()}")
            flash("Error interno preparando página de detección.", "danger")
        return render_template('detection.html', has_processed_data=has_proc, has_simulation_data=has_sim,
                               current_model_metrics=model_metrics_eval,
                               evaluation_report_data=evaluation_report_data,
                               evaluation_cm_plot_url=evaluation_cm_plot_url,
                               evaluation_cm_filename=evaluation_cm_filename,
                               last_detection_results=session_res, detection_preview_headers=None,
                               detection_preview_data=None, detection_preview_message=detection_preview_message,
                               detection_cm_plot_url=detection_cm_plot_url,
                               detection_cm_filename=detection_cm_filename, detection_history=history,
                               active_alerts=active_alerts)
    
    elif request.method == 'POST':
        df_to_detect = None
        src_info = "N/A"
        rows_count = 0
        try:
            ds = request.form.get('datasource')
            if ds == 'processed':
                df_proc = data_manager.get_processed_data()
                if df_proc is not None and not df_proc.empty:
                    df_to_detect = df_proc.copy()
                    src_info = "Datos Preprocesados Cargados"
                    rows_count = len(df_to_detect)
                else:
                    flash("No hay datos preprocesados disponibles.", "warning")
                    return redirect(url_for('detect'))

            elif ds == 'simulation':
                sim = session.get('simulation_info')
                if sim and sim.get('filepath') and os.path.exists(sim['filepath']):
                    df_sim_raw = pd.read_pickle(sim['filepath'])
                    print(f"INFO: Cargado archivo de simulación guardado: {sim['filepath']} con {len(df_sim_raw)} registros.")

                    if df_sim_raw is not None and not df_sim_raw.empty:
                        df_to_process, _ = data_manager.preprocess_data(df_sim_raw.copy())
                        if df_to_process is None:
                            raise RuntimeError("Falló el preprocesamiento de la simulación cargada.")

                        # --- INICIO DEL CAMBIO CLAVE: DICCIONARIO DE TRADUCCIÓN 100% COMPLETO ---
                        translation_map = {
                            'dst_port': 'destination_port', 'tot_fwd_pkts': 'total_fwd_packets',
                            'tot_bwd_pkts': 'total_backward_packets', 'totlen_fwd_pkts': 'total_length_of_fwd_packets',
                            'totlen_bwd_pkts': 'total_length_of_bwd_packets', 'fwd_pkt_len_max': 'fwd_packet_length_max',
                            'fwd_pkt_len_min': 'fwd_packet_length_min', 'fwd_pkt_len_mean': 'fwd_packet_length_mean',
                            'fwd_pkt_len_std': 'fwd_packet_length_std', 'bwd_pkt_len_max': 'bwd_packet_length_max',
                            'bwd_pkt_len_min': 'bwd_packet_length_min', 'bwd_pkt_len_mean': 'bwd_packet_length_mean',
                            'bwd_pkt_len_std': 'bwd_packet_length_std', 'flow_byts_s': 'flow_bytes_s',
                            'flow_pkts_s': 'flow_packets_s', 'fwd_iat_tot': 'fwd_iat_total',
                            'bwd_iat_tot': 'bwd_iat_total', 'fwd_header_len': 'fwd_header_length',
                            'bwd_header_len': 'bwd_header_length', 'fwd_pkts_s': 'fwd_packets_s',
                            'bwd_pkts_s': 'bwd_packets_s', 'pkt_len_min': 'min_packet_length',
                            'pkt_len_max': 'max_packet_length', 'pkt_len_mean': 'packet_length_mean',
                            'pkt_len_std': 'packet_length_std', 'pkt_len_var': 'packet_length_variance',
                            'fin_flag_cnt': 'fin_flag_count', 'syn_flag_cnt': 'syn_flag_count',
                            'rst_flag_cnt': 'rst_flag_count', 'psh_flag_cnt': 'psh_flag_count',
                            'ack_flag_cnt': 'ack_flag_count', 'urg_flag_cnt': 'urg_flag_count',
                            'cwe_flag_count': 'cwe_flag_count', 'ece_flag_cnt': 'ece_flag_count',
                            'pkt_size_avg': 'average_packet_size', 'fwd_seg_size_avg': 'avg_fwd_segment_size',
                            'bwd_seg_size_avg': 'avg_bwd_segment_size', 'fwd_byts_b_avg': 'fwd_byts_b_avg',
                            'fwd_pkts_b_avg': 'fwd_pkts_b_avg', 'fwd_blk_rate_avg': 'fwd_blk_rate_avg',
                            'bwd_byts_b_avg': 'bwd_byts_b_avg', 'bwd_pkts_b_avg': 'bwd_pkts_b_avg',
                            'bwd_blk_rate_avg': 'bwd_blk_rate_avg', 'subflow_fwd_byts': 'subflow_fwd_bytes',
                            'subflow_bwd_byts': 'subflow_bwd_bytes', 'init_fwd_win_byts': 'init_win_bytes_forward',
                            'init_bwd_win_byts': 'init_win_bytes_backward', 'fwd_act_data_pkts': 'act_data_pkt_fwd',
                            'fwd_seg_size_min': 'min_seg_size_forward',
                            # --- REGLAS FALTANTES AÑADIDAS ---
                            'subflow_fwd_pkts': 'subflow_fwd_packets',
                            'subflow_bwd_pkts': 'subflow_bwd_packets'
                        }
                        
                        if hasattr(detector, 'feature_names_') and detector.feature_names_ and 'total_fwd_packets' in detector.feature_names_:
                            print("INFO [Traductor]: Modelo tipo CIS2017 detectado. Aplicando traducción a datos simulados.")
                            df_to_process.rename(columns=translation_map, inplace=True, errors='ignore')
                        else:
                            print("INFO [Traductor]: Modelo tipo CIS2018 detectado. No se requiere traducción.")

                        df_to_detect = df_to_process.copy()
                        src_info = f"Última Simulación Guardada ({os.path.basename(sim['filepath'])})"
                        rows_count = len(df_to_detect)
                    else:
                        raise FileNotFoundError("El archivo de simulación está vacío.")
                else:
                    flash("No hay datos de la última simulación disponibles. Por favor, ejecute una nueva simulación.", "warning")
                    return redirect(url_for('detect'))
            else:
                flash("Fuente de datos inválida.", "danger")
                return redirect(url_for('detect'))

            if df_to_detect is not None and not df_to_detect.empty:
                final_output_detection = detector.run_detection(df_to_detect.copy())
                if final_output_detection and isinstance(final_output_detection, dict) and 'data' in final_output_detection:
                    df_res_detection = final_output_detection.get('data')
                    if df_res_detection is not None and not df_res_detection.empty:
                        current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold', 0.7)
                        results_for_session_minimal = {
                            'ts': datetime.datetime.now().isoformat(timespec='seconds'), 
                            'src': src_info, 'rows': rows_count, 'thr': current_threshold, 
                            'metrics': final_output_detection.get('metrics', {}), 
                            'summary': final_output_detection.get('detection_summary', {}), 
                            'head': df_res_detection.head().to_dict('records')
                        }
                        session['last_detection_results'] = results_for_session_minimal
                        alert_manager.add_detection_to_history(results_for_session_minimal.copy())
                        
                        try:
                            log_details = f"Fuente: {src_info}, Filas: {rows_count}, Umbral: {current_threshold}, Resumen: {results_for_session_minimal.get('summary', {})}"
                            log_entry = UserActivityLog(user_id=current_user.id, action='ejecucion_deteccion', details=log_details)
                            db.session.add(log_entry)
                            db.session.commit()
                        except Exception as e:
                            print(f"Error registrando ejecución de detección: {e}")
                            
                        if 'prediction_label' in df_res_detection.columns:
                            n_alerts, _ = alert_manager.generate_alerts(df_res_detection)
                            if n_alerts > 0:
                                flash(f"{n_alerts} nuevas alertas generadas.", "info")
                        
                        flash("Detección completada.", "success")
                        
                        df_preview_head = df_res_detection.head(10)
                        detection_preview_headers = df_preview_head.columns.tolist()
                        detection_preview_data = [[item if pd.notna(item) else '' for item in row] for row in df_preview_head.values.tolist()]
                        metrics_this_detection = final_output_detection.get('metrics', {})
                        
                        if metrics_this_detection.get('confusion_matrix') is not None:
                            try:
                                detection_cm_plot_url, detection_cm_filename = generate_plot_base64_and_save(
                                    plot_confusion_matrix_func, 
                                    metrics_this_detection['confusion_matrix'], 
                                    classes=metrics_this_detection.get('classes'), 
                                    title='Matriz_Confusion_Esta_Deteccion', 
                                    save_plot=True, 
                                    save_dir=app.config['SAVED_PLOTS_FOLDER']
                                )
                            except Exception as e_cm_post:
                                print(f"ERROR generando plot CM para POST: {e_cm_post}")
                        
                        eval_metrics_post = detector.evaluate_on_test_set() if hasattr(detector, 'evaluate_on_test_set') else None
                        if eval_metrics_post and isinstance(eval_metrics_post, dict) and eval_metrics_post.get('accuracy') is not None:
                            model_metrics_eval = eval_metrics_post
                            if model_metrics_eval.get('confusion_matrix') is not None:
                                try:
                                    evaluation_cm_plot_url, evaluation_cm_filename = generate_plot_base64_and_save(
                                        plot_confusion_matrix_func, 
                                        model_metrics_eval['confusion_matrix'], 
                                        classes=model_metrics_eval.get('classes'), 
                                        title='Matriz_Confusion_Evaluacion_General', 
                                        save_plot=True, 
                                        save_dir=app.config['SAVED_PLOTS_FOLDER']
                                    )
                                except Exception as e_cm_gen_post:
                                    print(f"ERROR generando plot CM eval para POST: {e_cm_gen_post}")
                            if model_metrics_eval.get('report') and isinstance(model_metrics_eval.get('report'), dict):
                                evaluation_report_data = model_metrics_eval.get('report')
                        
                        active_alerts_post = alert_manager.get_alerts(show_all=False)
                        
                        return render_template('detection.html', 
                                               has_processed_data=has_proc, 
                                               has_simulation_data=has_sim, 
                                               current_model_metrics=model_metrics_eval, 
                                               evaluation_report_data=evaluation_report_data, 
                                               evaluation_cm_plot_url=evaluation_cm_plot_url, 
                                               evaluation_cm_filename=evaluation_cm_filename, 
                                               last_detection_results=results_for_session_minimal, 
                                               detection_preview_headers=detection_preview_headers, 
                                               detection_preview_data=detection_preview_data, 
                                               detection_preview_message=None, 
                                               detection_cm_plot_url=detection_cm_plot_url, 
                                               detection_cm_filename=detection_cm_filename, 
                                               detection_history=alert_manager.get_detection_history(), 
                                               active_alerts=active_alerts_post)
                    else:
                        flash("Detección no produjo datos de resultados.", "warning")
                else:
                    flash("Función de detección no produjo resultados válidos.", "warning")
            else:
                flash("Error: No se pudieron preparar datos para detección.", "danger")
        except Exception as e_main_post:
            flash(f"Error interno grave en detección: {e_main_post}", "danger")
            print(f"ERROR general en POST /detect: {e_main_post}\n{traceback.format_exc()}")
        
        return redirect(url_for('detect'))

@app.route('/download_plot/<path:filename>')
@login_required
def download_plot(filename):
    print(f"DEBUG: Solicitud descarga gráfico: {filename}"); safe_filename = secure_filename(filename)
    if not safe_filename or '..' in safe_filename or safe_filename.startswith(('/', '\\')): print(f"WARN: Intento de descarga de archivo inválido/peligroso: {filename}"); flash("Nombre de archivo inválido.", "danger"); return redirect(url_for('dashboard'))
    plot_dir = app.config.get('SAVED_PLOTS_FOLDER', os.path.join(BASE_DIR, 'saved_plots')); filepath = os.path.join(plot_dir, safe_filename); print(f"DEBUG: Buscando gráfico en ruta absoluta: {filepath}")
    if os.path.exists(filepath) and os.path.commonpath([plot_dir]) == os.path.commonpath([plot_dir, filepath]): # Security check
         try: print(f"INFO: Enviando archivo de gráfico: {filepath}"); return send_file(filepath, as_attachment=True)
         except Exception as e: print(f"ERROR al enviar archivo de gráfico {filepath}: {e}"); flash("Error al intentar descargar el gráfico.", "error"); return redirect(url_for('detect'))
    else: print(f"WARN: Archivo de gráfico no encontrado o fuera del directorio permitido: {filepath}"); flash("El archivo del gráfico solicitado no se encontró.", "warning"); return redirect(url_for('detect'))
@app.route('/mark_alert_reviewed/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_reviewed(alert_id):
    origin_page = request.form.get('origin', 'detect'); redirect_url = url_for(origin_page)
    try:
        success = alert_manager.mark_alert_reviewed(alert_id)
        if success:
            flash(f"Alerta ID {alert_id} marcada como revisada.", 'success')
            try:
                log_entry = UserActivityLog(user_id=current_user.id, action='revision_alerta', details=f"ID Alerta: {alert_id}")
                db.session.add(log_entry); db.session.commit()
            except Exception as e: print(f"Error registrando revisión de alerta: {e}")
        else: flash(f"No se pudo marcar alerta {alert_id} (no existe o error).", 'warning')
    except Exception as e: flash(f"Error al marcar alerta {alert_id}: {e}", "error"); print(f"ERROR marcar alerta {alert_id}: {e}\n{traceback.format_exc()}")
    return redirect(redirect_url)
@app.route('/report/last_detection_csv')
@login_required
def download_last_detection_csv():
    results = session.get('last_detection_results')
    if not results: flash("No hay resultados de última detección.", "warning"); return redirect(url_for('detect'))
    try:
        csv_content = generate_last_detection_csv(results)
        if csv_content is None: raise ValueError("Generación de CSV devolvió None.")
        response = make_response(csv_content); ts_actual = datetime.datetime.now().strftime('%Y%m%d_%H%M%S'); filename = f"reporte_deteccion_{ts_actual}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename=\"{filename}\""; response.headers["Content-Type"] = "text/csv; charset=utf-8"
        try:
            log_entry = UserActivityLog(user_id=current_user.id, action='descarga_reporte_deteccion', details=f"Archivo: {filename}")
            db.session.add(log_entry); db.session.commit()
        except Exception as e: print(f"Error registrando descarga de reporte: {e}")
        return response
    except Exception as e: print(f"ERROR generando/enviando reporte CSV: {e}\n{traceback.format_exc()}"); flash(f"Error interno generando reporte CSV: {e}", "error"); return redirect(url_for('detect'))
# --- RUTAS ADMIN ---
def get_saved_models_list():
    if hasattr(detector, 'get_saved_model_list'):
        try: return detector.get_saved_model_list()
        except Exception as e: print(f"ERROR [App]: Llamando detector.get_saved_model_list(): {e}"); return []
    else: # Fallback si el método no existe en el detector
        print("WARN [App]: detector no tiene método get_saved_model_list(). Intentando fallback manual.")
        try:
             model_folder = app.config.get('MODEL_FOLDER', 'models'); active_model_name = detector.active_model_name if hasattr(detector, 'active_model_name') else "active_model.joblib"
             models = [f for f in os.listdir(model_folder) if f.endswith(('.joblib', '.pkl')) and f != active_model_name and not f.endswith(('_scaler.joblib', '_scaler.pkl', '_test_set.joblib', '_test_set.pkl'))]
             return sorted(models)
        except Exception as e_fb: print(f"ERROR [App]: Fallback get_saved_models_list falló: {e_fb}"); return []
@app.route('/admin', methods=['GET']) # Solo GET para la página principal de admin
@login_required
@admin_required
def admin_landing():
    print("DEBUG: GET /admin")
    try:
        log_entry = UserActivityLog(user_id=current_user.id, action='acceso_pagina_administracion')
        db.session.add(log_entry); db.session.commit()
    except Exception as e: print(f"Error registrando acceso a admin: {e}")
    # Filtros
    filter_user_username = request.args.get('filter_user_username', '')
    filter_action = request.args.get('filter_action', '')
    saved_models = []; current_threshold = 0.7; current_severity = 'Media'; current_notify_email = False; severity_levels = ['Baja', 'Media', 'Alta', 'Crítica'];
    logs = ["No se pudieron cargar los logs."] # Default
    
    user_activity_logs_query = UserActivityLog.query.join(User).order_by(UserActivityLog.timestamp.desc())
    if filter_user_username:
        user_activity_logs_query = user_activity_logs_query.filter(User.username.ilike(f"%{filter_user_username}%"))
    if filter_action:
        user_activity_logs_query = user_activity_logs_query.filter(UserActivityLog.action == filter_action)
    
    # Seleccionar columnas explícitamente para evitar problemas con objetos User completos
    user_activity_logs_paginated = user_activity_logs_query.add_columns(
        User.username,
        UserActivityLog.timestamp,
        UserActivityLog.action,
        UserActivityLog.details
    ).limit(100).all() # Mantenemos el límite para la visualización
    # Para el desplegable de filtro de acciones
    distinct_actions_tuples = db.session.query(func.distinct(UserActivityLog.action)).order_by(UserActivityLog.action).all()
    distinct_actions = [action_tuple[0] for action_tuple in distinct_actions_tuples]
    try:
        current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold', 0.7)
        if hasattr(alert_manager, 'config'): alert_config = alert_manager.config; current_severity = alert_config.get('severity_threshold', 'Media'); current_notify_email = alert_config.get('notify_email', False)
        if hasattr(alert_manager, 'get_severity_levels'): severity_levels = alert_manager.get_severity_levels()
        if hasattr(admin_manager, 'get_system_logs'):
            try: logs = admin_manager.get_system_logs()
            except Exception as e_log: print(f"ERROR obteniendo logs de sistema: {e_log}"); logs = ["Error al cargar logs del sistema."]
        else: logs = ["Funcionalidad de logs de sistema no implementada."]
        saved_models = get_saved_models_list()
    except Exception as e: print(f"ERROR cargando datos para /admin: {e}\n{traceback.format_exc()}"); flash("Error al cargar página de admin.", "error")
    
    delete_logs_form = DeleteLogsForm() # Para CSRF
    return render_template('admin.html',
                           glm_threshold=current_threshold, alert_severity_threshold=current_severity,
                           notify_email=current_notify_email, alert_severity_levels=severity_levels,
                           system_logs=logs, saved_models_list=saved_models,
                           user_activity_logs=user_activity_logs_paginated, # Logs filtrados y paginados
                           distinct_actions=distinct_actions, # Para el desplegable de filtro
                           filter_user_username=filter_user_username, # Para repoblar el formulario
                           filter_action=filter_action, # Para repoblar el formulario
                           delete_logs_form=delete_logs_form)
@app.route('/admin/action', methods=['POST'])
@login_required
@admin_required
def admin_actions():
    action = request.form.get('action')
    log_details_admin_action = f"Acción admin: {action}" # Base para el log
    should_redirect = True # Por defecto, redirigir al final

    try:
        if action == 'update_threshold':
            thr_str = request.form.get('glm_threshold_admin')
            try:
                thr = float(thr_str)
                if 0.0 < thr < 1.0:
                    if hasattr(detector, 'prediction_threshold'):
                        detector.prediction_threshold = thr
                    if 'glm_threshold' in system_config: # Asumiendo que system_config es un dict global
                        system_config['glm_threshold'] = thr 
                    if hasattr(admin_manager, 'save_system_config'):
                        admin_manager.save_system_config(system_config)
                    flash(f"Umbral GLM actualizado a {thr:.2f}.", "success")
                    log_details_admin_action += f", Nuevo Umbral: {thr:.2f}"
                else:
                    flash("Umbral GLM debe estar entre 0.0 y 1.0.", "warning")
            except ValueError:
                flash("Valor de umbral GLM inválido.", "danger")
                log_details_admin_action += f", Falló: Valor de umbral inválido '{thr_str}'."
        
        elif action == 'update_alert_config':
            sev = request.form.get('alert_severity_threshold_admin')
            notify = request.form.get('notify_email_admin') == 'on'
            if hasattr(alert_manager, 'update_config'):
                if alert_manager.update_config(severity_threshold=sev, notify_email=notify):
                    flash("Configuración de alertas actualizada.", "success")
                else:
                    flash("Error actualizando configuración de alertas.", "warning")
            log_details_admin_action += f", Severidad: {sev}, Notificación Email: {notify}"

        elif action == 'retrain': # Entrena con los datos actualmente procesados en DataManager
            df_proc = data_manager.get_processed_data()
            if df_proc is not None and not df_proc.empty:
                # --- MODIFICACIÓN: Olvidar estructura de características anterior ---
                if hasattr(detector, 'feature_names_'):
                    detector.feature_names_ = None 
                app.logger.info(f"[{action.upper()}]: Nombres de características reiniciados. Se derivarán del dataset procesado actual.")
                log_details_admin_action += ", Nombres de características reiniciados para derivar del dataset actual."
                # --- FIN MODIFICACIÓN ---
                
                # Tu código espera 2 valores de retorno: success (booleano), msg (string con detalles/métricas)
                success, msg = detector.train_and_save_model(df_proc.copy())
                
                flash(msg, 'success' if success else 'danger')
                log_details_admin_action += f", Filas: {len(df_proc)}, Éxito: {success}, Mensaje: {msg}"
            else:
                flash("No hay datos preprocesados para reentrenamiento.", 'warning')
                log_details_admin_action += ", Falló: No hay datos preprocesados."
        
        elif action == 'add_data_and_retrain': # Añade nuevos datos a los existentes y reentrena
            should_redirect = False 
            log_details_admin_action += " - Intento de Añadir Datos y Reentrenar."
            
            # Asegúrate de que el nombre del input file en tu HTML sea 'new_data_file'
            if 'new_data_file' not in request.files:
                flash('No se seleccionó ningún archivo para añadir datos.', 'warning')
                log_details_admin_action += " Falló: No se incluyó archivo."
            else:
                file = request.files['new_data_file']
                if file.filename == '':
                    flash('No se seleccionó ningún archivo.', 'warning')
                    log_details_admin_action += " Falló: Nombre de archivo vacío."
                # Asegúrate de que la función `allowed_file` esté definida en tu app.py
                elif file and allowed_file(file.filename):
                    new_filepath = None
                    try:
                        df_existing_processed = data_manager.get_processed_data()
                        if df_existing_processed is None or df_existing_processed.empty:
                            flash('Error: No hay datos procesados existentes. Carga y preprocesa datos primero a través de la página de Gestión de Datos.', 'danger')
                            log_details_admin_action += " Falló: No hay datos preprocesados existentes."
                        else:
                            new_filename_secure = secure_filename(file.filename)
                            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                                os.makedirs(app.config['UPLOAD_FOLDER'])
                            new_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_new_data_for_retrain_{new_filename_secure}")
                            file.save(new_filepath)
                            log_details_admin_action += f" Archivo nuevo temporal: {new_filename_secure}."
                            
                            # Cargar SOLO los datos del nuevo archivo para preprocesarlos
                            # data_manager.load_csv_data actualiza self.loaded_data
                            load_ok, load_msg = data_manager.load_csv_data(new_filepath) 
                            if not load_ok:
                                flash(f"Error cargando archivo nuevo '{new_filename_secure}': {load_msg}", 'danger')
                                log_details_admin_action += f" Falló carga del nuevo archivo: {load_msg}."
                            else:
                                df_new_raw = data_manager.get_loaded_data() # Obtener los datos recién cargados del nuevo archivo
                                log_details_admin_action += f" Cargado nuevo archivo ({df_new_raw.shape[0]} filas raw)."
                                
                                # Preprocesar solo los datos del nuevo archivo
                                df_new_processed, preproc_msg = data_manager.preprocess_data(df_new_raw.copy())
                                
                                if df_new_processed is None or df_new_processed.empty:
                                    flash(f"Error preprocesando el nuevo archivo '{new_filename_secure}': {preproc_msg}", 'danger')
                                    log_details_admin_action += f" Falló preprocesamiento del nuevo archivo: {preproc_msg}."
                                else:
                                    log_details_admin_action += f" Preprocesado nuevo archivo ({df_new_processed.shape[0]} filas)."
                                    
                                    # Lógica para combinar con datos existentes:
                                    expected_cols = df_existing_processed.columns.tolist()
                                    # Asegurar que la columna 'label' (o la que uses) esté en ambos
                                    label_col = getattr(detector, 'target_col', 'label') # Obtener la columna objetivo del detector
                                    if label_col not in df_new_processed.columns:
                                        flash(f"Error: La columna '{label_col}' falta en el nuevo archivo preprocesado.", 'danger')
                                        log_details_admin_action += f" Falló combinación: Falta la columna '{label_col}' en el nuevo archivo."
                                    
                                    # Verificar si todas las columnas esperadas (features + label) están en el nuevo df
                                    # Es importante que df_new_processed tenga las mismas features que df_existing_processed
                                    # O que _clean_col_name haya producido nombres consistentes.
                                    
                                    actual_new_cols = df_new_processed.columns.tolist()
                                    missing_in_new = set(expected_cols) - set(actual_new_cols)
                                    extra_in_new = set(actual_new_cols) - set(expected_cols)

                                    if missing_in_new:
                                        # Si faltan columnas que estaban en el original, no se puede combinar directamente si se espera consistencia total.
                                        # O se rellenan con NaN/0 o se da error. Tu código actual da error.
                                        flash(f"Error: Faltan columnas en el nuevo archivo preprocesado para poder combinar: {list(missing_in_new)}. Columnas extra (serán ignoradas si no están en el set original): {list(extra_in_new)}", 'danger')
                                        log_details_admin_action += f" Falló combinación: Faltan columnas {list(missing_in_new)}."
                                    else:
                                        # Alinear columnas del nuevo df_new_processed al orden de df_existing_processed
                                        # y tomar solo las columnas que existen en el df original para asegurar la concatenación.
                                        df_new_processed_aligned = df_new_processed[expected_cols]
                                        
                                        df_combined = pd.concat([df_existing_processed, df_new_processed_aligned], ignore_index=True)
                                        rows_before_dedup = len(df_combined)
                                        df_combined.drop_duplicates(inplace=True)
                                        rows_after_dedup = len(df_combined)
                                        new_rows_added = rows_after_dedup - len(df_existing_processed) if rows_after_dedup > len(df_existing_processed) else 0 # Puede ser negativo si los nuevos datos eran todos duplicados y el df_existing tenía duplicados que se limpiaron por el concat+drop_duplicates general
                                        log_details_admin_action += f" Combinado ({rows_before_dedup} -> {rows_after_dedup} filas). {max(0,new_rows_added)} filas nuevas únicas añadidas."
                                        
                                        if df_combined.empty:
                                            flash("Error: No quedan datos tras combinar y eliminar duplicados.", "danger")
                                            log_details_admin_action += " Falló: Sin datos tras combinar."
                                        else:
                                            # --- MODIFICACIÓN: Olvidar estructura de características anterior ---
                                            # Aplicar también aquí si el df_combined puede tener una estructura de features
                                            # diferente a la del modelo activo cargado al inicio.
                                            if hasattr(detector, 'feature_names_'):
                                                detector.feature_names_ = None
                                            app.logger.info(f"[{action.upper()}]: Nombres de características reiniciados. Se derivarán del dataset combinado.")
                                            log_details_admin_action += ", Nombres de características reiniciados para derivar del dataset combinado."
                                            # --- FIN MODIFICACIÓN ---

                                            success_train, msg_train = detector.train_and_save_model(df_combined.copy())
                                            if success_train:
                                                # Actualizar los datos procesados en DataManager con el conjunto combinado
                                                if hasattr(data_manager, 'update_processed_data'): 
                                                    success_update, msg_update = data_manager.update_processed_data(df_combined.copy()) 
                                                    if success_update:
                                                        flash(f"Modelo reentrenado con datos combinados ({max(0,new_rows_added)} filas nuevas únicas añadidas). {msg_train}", 'success')
                                                        log_details_admin_action += f" Éxito reentrenamiento y actualización de datos procesados: {msg_train}."
                                                    else:
                                                        flash(f"¡Advertencia! Modelo reentrenado, pero falló al actualizar los datos procesados en DataManager: {msg_update}.", 'warning')
                                                        log_details_admin_action += f" Reentrenamiento OK, pero falló actualización de datos procesados: {msg_update}."
                                                else: # Si DataManager no tiene update_processed_data
                                                    flash(f"Modelo reentrenado con datos combinados. {msg_train} (Nota: DataManager no actualizó su dataset procesado).", 'success')
                                                    log_details_admin_action += f" Éxito reentrenamiento ({msg_train}). DataManager no actualizó su dataset procesado."
                                            else: # Falló el entrenamiento
                                                flash(f"Falló el reentrenamiento con datos combinados: {msg_train}", 'danger')
                                                log_details_admin_action += f" Falló reentrenamiento con datos combinados: {msg_train}."
                    except Exception as e_inc:
                        flash(f'Error crítico en Añadir Datos y Reentrenar: {str(e_inc)}', 'danger')
                        log_details_admin_action += f" Error crítico: {str(e_inc)}."
                        app.logger.error(f"ERROR [App] AddData&Retrain: {str(e_inc)}\n{traceback.format_exc()}")
                    finally:
                        if new_filepath and os.path.exists(new_filepath):
                            try:
                                os.remove(new_filepath)
                            except Exception as e_del_temp:
                                app.logger.warning(f"WARN [App]: No se pudo eliminar archivo temporal {new_filepath}: {str(e_del_temp)}")
                else: # not allowed_file
                    flash('Tipo de archivo no permitido. Solo se permiten archivos CSV.', 'danger') # Cambiado 'error' a 'danger'
                    log_details_admin_action += " Falló: Tipo de archivo no permitido."
            
            try:
                # Asumiendo que UserActivityLog y db están configurados
                log_entry = UserActivityLog(user_id=current_user.id, action='admin_add_data_retrain', details=log_details_admin_action)
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e_log:
                app.logger.error(f"Error registrando acción admin (add_data_and_retrain): {str(e_log)}")
            
            return redirect(url_for('admin_landing'))

        elif action == 'save_model':
            save_name = request.form.get('save_name')
            if save_name and hasattr(detector, 'save_active_model_as'):
                base_name = os.path.splitext(save_name)[0]
                if not base_name:
                    flash("Nombre de archivo para guardar inválido.", "warning")
                    log_details_admin_action += f", Falló guardado: Nombre base vacío '{save_name}'."
                else:
                    success, msg = detector.save_active_model_as(base_name)
                    flash(msg, 'success' if success else 'danger')
                    log_details_admin_action += f", Nombre Modelo Guardado: {base_name}, Éxito: {success}"
            else:
                flash("No se proporcionó un nombre para guardar o la función no está disponible.", "warning")

        elif action == 'load_model':
            filename_to_load = request.form.get('model_filename_to_load')
            if filename_to_load and hasattr(detector, 'load_model_as_active'):
                success, msg = detector.load_model_as_active(filename_to_load)
                flash(msg, 'success' if success else 'danger')
                log_details_admin_action += f", Archivo Modelo Cargado: {filename_to_load}, Éxito: {success}"
            else:
                flash("No se seleccionó archivo o la función de carga no está disponible.", "warning")

        elif action == 'delete_model':
            filename_to_delete = request.form.get('model_filename_to_delete')
            if filename_to_delete and hasattr(detector, 'delete_saved_model'):
                success, msg = detector.delete_saved_model(filename_to_delete)
                flash(msg, 'success' if success else 'danger')
                log_details_admin_action += f", Archivo Modelo Eliminado: {filename_to_delete}, Éxito: {success}"
            else:
                flash("No se seleccionó archivo para eliminar o la función no está disponible.", "warning")
        
        elif action == 'delete_all_alerts':
            if hasattr(alert_manager, 'delete_all_alerts'):
                success, msg = alert_manager.delete_all_alerts()
                flash(msg, 'success' if success else 'danger') # Cambiado 'error' a 'danger'
                log_details_admin_action += f", Éxito: {success}"
            else:
                flash("Función para eliminar alertas no disponible.", "danger")
                log_details_admin_action += ", Falló: Función no disponible."
        
        else:
            flash(f"Acción administrativa desconocida: '{action}'.", 'warning')
            log_details_admin_action += " - Acción desconocida."

        if action != 'add_data_and_retrain':
            try:
                # Asumiendo que UserActivityLog y db están configurados
                log_entry = UserActivityLog(user_id=current_user.id, action=f'admin_action_{action}', details=log_details_admin_action)
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e_log:
                app.logger.error(f"Error registrando acción admin ({action}): {str(e_log)}")
    
    except Exception as e_global: 
        flash(f"Error procesando la acción administrativa '{action}': {str(e_global)}", "danger") # Cambiado 'error' a 'danger'
        app.logger.error(f"ERROR admin POST action '{action}': {str(e_global)}\n{traceback.format_exc()}")
        if action != 'add_data_and_retrain':
            try:
                log_details_admin_action += f" - Error Global: {str(e_global)}"
                # Asumiendo que UserActivityLog y db están configurados
                log_entry = UserActivityLog(user_id=current_user.id, action=f'admin_action_error_{action}', details=log_details_admin_action)
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e_log_err:
                app.logger.error(f"Error registrando acción admin con error ({action}): {str(e_log_err)}")
    
    if should_redirect:
        return redirect(url_for('admin_landing'))

@app.route('/admin/logs/delete_user_activity', methods=['POST'])
@login_required
@admin_required
def delete_user_activity_logs():
    form = DeleteLogsForm() # CSRF
    if form.validate_on_submit(): 
        try:
            num_rows_deleted = UserActivityLog.query.delete()
            db.session.commit()
            flash(f'Se eliminaron {num_rows_deleted} registros del historial de actividad de usuarios.', 'success')
            print(f"INFO: Admin {current_user.username} eliminó todos los logs de actividad de usuarios ({num_rows_deleted} filas).")
            try:
                log_entry = UserActivityLog(user_id=current_user.id, action='eliminacion_logs_actividad', details=f"{num_rows_deleted} registros eliminados.")
                db.session.add(log_entry)
                db.session.commit()
            except Exception as e:
                 print(f"Error registrando eliminación de logs de actividad: {e}")
        except Exception as e:
            db.session.rollback()
            flash('Error al eliminar el historial de actividad de usuarios.', 'error')
            print(f"ERROR al eliminar logs de actividad: {e}\n{traceback.format_exc()}")
    else:
        flash('Error en la solicitud de borrado de logs (posiblemente CSRF). Intenta de nuevo.', 'danger')
    return redirect(url_for('admin_landing'))
# --- RUTAS GESTIÓN USUARIOS (Admin) ---
@app.route('/admin/users')
@login_required
@admin_required
def list_users():
    try:
        log_entry = UserActivityLog(user_id=current_user.id, action='acceso_lista_usuarios')
        db.session.add(log_entry); db.session.commit()
    except Exception as e: print(f"Error registrando acceso a lista de usuarios: {e}")
    users = []; delete_form = DeleteUserForm() # Para CSRF en el botón de eliminar de cada usuario
    try: users = User.query.order_by(User.username).all()
    except Exception as e: print(f"Err obtener users: {e}"); flash("Error cargar usuarios.", "error")
    return render_template('users_list.html', users=users, delete_form=delete_form)
@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    form = UserAdminForm() # Usar UserAdminForm que tiene validación de original_username/email
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data, is_admin=form.is_admin.data)
            if form.password.data: user.set_password(form.password.data) # Contraseña es obligatoria para nuevo usuario
            else: flash("Contraseña obligatoria al crear usuario.", "danger"); return render_template('user_form.html', title='Crear Usuario', form=form, is_new=True)
            db.session.add(user); db.session.commit(); flash(f'Usuario "{user.username}" creado.', 'success')
            try:
                log_details = f"Admin {current_user.username} creó usuario: {user.username}, Email: {user.email}, Admin: {user.is_admin}"
                log_entry = UserActivityLog(user_id=current_user.id, action='admin_creacion_usuario', details=log_details)
                db.session.add(log_entry); db.session.commit()
            except Exception as e: print(f"Error registrando creación de usuario por admin: {e}")
            return redirect(url_for('list_users'))
        except ValidationError as ve: flash(f"Error validación: {ve}", 'danger') # Ya manejado por UserAdminForm
        except Exception as e: db.session.rollback(); flash(f'Error al crear usuario: {e}', 'danger'); print(f"ERR crear usuario: {e}")
        return render_template('user_form.html', title='Crear Usuario', form=form, is_new=True) # Repopulate on error
    return render_template('user_form.html', title='Crear Usuario', form=form, is_new=True)
@app.route('/admin/users/<int:user_id_to_edit>/edit', methods=['GET', 'POST']) # Renombrado para claridad
@login_required
@admin_required
def edit_user(user_id_to_edit): # Renombrado user_id a user_id_to_edit
    user = User.query.get_or_404(user_id_to_edit)
    form = UserAdminForm(original_username=user.username, original_email=user.email) # Pasar originales
    if form.validate_on_submit():
        try:
            original_details = f"Original - Usuario: {user.username}, Email: {user.email}, Admin: {user.is_admin}"
            user.username=form.username.data; user.email=form.email.data; user.is_admin=form.is_admin.data;
            password_changed = False
            if form.password.data: user.set_password(form.password.data); password_changed = True
            db.session.commit(); flash(f'Usuario "{user.username}" actualizado.' + (' (Contraseña cambiada)' if password_changed else ''), 'success')
            try:
                updated_details = f"Admin {current_user.username} editó usuario ID {user_id_to_edit}: {user.username}. Nuevo Email: {user.email}, Admin: {user.is_admin}, PasswdCambiado: {password_changed}. {original_details}"
                log_entry = UserActivityLog(user_id=current_user.id, action='admin_edicion_usuario', details=updated_details)
                db.session.add(log_entry); db.session.commit()
            except Exception as e: print(f"Error registrando edición de usuario por admin: {e}")
            return redirect(url_for('list_users'))
        except ValidationError as ve: flash(f"Error validación: {ve}", 'danger')
        except Exception as e: db.session.rollback(); flash(f'Error al actualizar usuario: {e}', 'danger'); print(f"ERR edit user {user_id_to_edit}: {e}")
        form.username.data = user.username 
        form.email.data = user.email
        form.is_admin.data = user.is_admin
        return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user, is_new=False)
    elif request.method == 'GET': form.username.data = user.username; form.email.data = user.email; form.is_admin.data = user.is_admin
    return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user, is_new=False)
@app.route('/admin/users/<int:user_id_to_delete>/delete', methods=['POST']) # Renombrado user_id
@login_required
@admin_required
def delete_user(user_id_to_delete): # Renombrado user_id
    user_to_delete = User.query.get_or_404(user_id_to_delete)
    if user_to_delete.id == current_user.id: flash("No puedes eliminar tu propia cuenta.", "danger"); return redirect(url_for('list_users'))
    form = DeleteUserForm() # CSRF
    if form.validate_on_submit():
        try:
            username_deleted = user_to_delete.username
            db.session.delete(user_to_delete); db.session.commit(); flash(f'Usuario "{username_deleted}" eliminado.', 'success')
            try:
                log_entry = UserActivityLog(user_id=current_user.id, action='admin_eliminacion_usuario', details=f"Admin {current_user.username} eliminó usuario: {username_deleted} (ID: {user_id_to_delete})")
                db.session.add(log_entry); db.session.commit()
            except Exception as e: print(f"Error registrando eliminación de usuario por admin: {e}")
        except Exception as e: db.session.rollback(); flash(f'Error al eliminar "{user_to_delete.username}": {e}', 'danger'); print(f"ERROR al eliminar usuario {user_id_to_delete}: {e}")
    else: flash("Error en solicitud de borrado (CSRF).", "danger")
    return redirect(url_for('list_users'))
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    global system_config, detector, alert_manager # Declarar explícitamente para modificación
    if request.method == 'POST':
        log_details_settings = "Usuario cambió configuración: "
        changed_anything = False
        try:
            thr_str = request.form.get('glm_threshold')
            if thr_str is not None: # Solo si se envió el campo
                 thr = float(thr_str)
                 if 0.0 < thr < 1.0:
                     if detector.prediction_threshold != thr : # Solo loguear y guardar si hay cambio
                        if hasattr(detector, 'prediction_threshold'): detector.prediction_threshold = thr
                        system_config['glm_threshold'] = thr
                        if hasattr(admin_manager, 'save_system_config'): admin_manager.save_system_config(system_config)
                        flash(f"Umbral detección actualizado a {thr:.2f}.", "success")
                        log_details_settings += f"Umbral GLM a {thr:.2f}. "
                        changed_anything = True
                 else: flash("Umbral GLM fuera de rango (0.0-1.0).", "warning")
            
            sev = request.form.get('severity_threshold'); email_notify_on = request.form.get('notify_email') == 'on'
            if hasattr(alert_manager, 'update_config'):
                 current_config_am = alert_manager.config # Obtener config actual para comparar
                 if current_config_am.get('severity_threshold') != sev or current_config_am.get('notify_email') != email_notify_on:
                      if alert_manager.update_config(severity_threshold=sev, notify_email=email_notify_on): flash("Config. alertas actualizada.", "success")
                      else: flash("Error actualizando config. alertas.", "warning")
                      log_details_settings += f"Severidad Alertas a {sev}, Notif. Email a {email_notify_on}. "
                      changed_anything = True
            
            if changed_anything:
                try:
                    log_entry = UserActivityLog(user_id=current_user.id, action='cambio_configuracion_personal', details=log_details_settings.strip())
                    db.session.add(log_entry); db.session.commit()
                except Exception as e: print(f"Error registrando cambio de config. personal: {e}")
            return redirect(url_for('settings'))
        except Exception as e: print(f"ERROR POST /settings: {e}\n{traceback.format_exc()}"); flash(f"Error guardando config.: {e}", "danger")
    if request.method == 'GET':
        try:
            log_entry = UserActivityLog(user_id=current_user.id, action='acceso_pagina_configuracion')
            db.session.add(log_entry); db.session.commit()
        except Exception as e: print(f"Error registrando acceso a config.: {e}")
    current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold', 0.7)
    current_severity = 'Media'; current_notify_email = False; severity_levels = ['Baja', 'Media', 'Alta', 'Crítica'] # Defaults
    if hasattr(alert_manager, 'config'): current_severity = alert_manager.config.get('severity_threshold', 'Media'); current_notify_email = alert_manager.config.get('notify_email', False)
    if hasattr(alert_manager, 'get_severity_levels'): severity_levels = alert_manager.get_severity_levels()
    return render_template('settings.html', title='Configuración', glm_threshold=current_threshold, severity_threshold=current_severity, notify_email=current_notify_email, alert_severity_levels=severity_levels)
if __name__ == '__main__':
     with app.app_context():
         print("INFO: Verificando/Creando tablas BD...")
         t_start = datetime.datetime.now()
         try:
             db.create_all()
             t_end = datetime.datetime.now(); print(f"INFO: db.create_all() completado en {(t_end - t_start).total_seconds():.2f}s.")
             if User.query.count() == 0:
                 print("INFO: No existen usuarios. Creando 'admin' inicial...")
                 try:
                     admin_user = User(username='admin', email='admin@example.com', is_admin=True)
                     admin_user.set_password('ChangeMe123!'); db.session.add(admin_user); db.session.commit()
                     print("INFO: Usuario 'admin' creado con contraseña 'ChangeMe123!'. ¡CAMBIAR INMEDIATAMENTE!")
                     try:
                         log_entry = UserActivityLog(user_id=admin_user.id, action='creacion_admin_inicial', details='Usuario admin inicial creado automáticamente.')
                         db.session.add(log_entry); db.session.commit()
                     except Exception as e_log_admin: print(f"Error registrando creación admin inicial: {e_log_admin}")
                 except Exception as e_adm: db.session.rollback(); print(f"ERROR crítico creando admin inicial: {e_adm}")
         except Exception as e_db_init: print(f"FATAL ERROR inicializando BD: {e_db_init}"); print("Verifica conexión y servidor MySQL."); exit()
     print("INFO: Iniciando servidor Flask...")
     app.run(host='0.0.0.0', port=5000, debug=True)