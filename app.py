import os
import io
import base64
import pandas as pd
import numpy as np
import matplotlib

# Usar backend no interactivo ANTES de importar pyplot
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import datetime
import traceback
import uuid

# --- IMPORTACIONES PARA LOGIN Y BD ---
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
# Usar bcrypt directamente es más seguro que depender solo de Werkzeug para hash
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# --- FIN IMPORTACIONES LOGIN Y BD ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response, send_file
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


# Importa tus clases manager
try:
    from data_manager import DataManager
    from threat_simulator import ThreatSimulator
    from threat_detector import ThreatDetector
    from alert_manager import AlertManager
    from admin_manager import AdminManager
except ImportError as e:
    print(f"FATAL ERROR: No se pudo importar clase manager: {e}"); exit()

from functools import wraps 

print("DEBUG: Definiendo decorador admin_required...")
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acceso no autorizado. Solo para administradores.", "error")
            return redirect(url_for('dashboard')) # O url_for('login') si prefieres
        return f(*args, **kwargs)
    return decorated_function

# --- Configuración de la App ---
print("DEBUG: Creando instancia de Flask app...")
app = Flask(__name__)
print("DEBUG: Instancia Flask creada.")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3_v4") # Cambié un poco por si acaso

# Carpetas
UPLOAD_FOLDER = 'uploads'
TEMP_SIM_FOLDER = 'temp_sim_data'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
print(f"DEBUG: Carpetas configuradas: UPLOAD={app.config['UPLOAD_FOLDER']}, TEMP_SIM={app.config['TEMP_SIM_FOLDER']}")

# --- CONFIGURACIÓN DE BASE DE DATOS (¡¡¡AJUSTAR!!!) ---
DB_USER = "root"
DB_PASS = "" # Contraseña VACÍA por defecto en XAMPP. ¡CAMBIAR si pusiste una!
DB_HOST = "localhost"
DB_NAME = "cyber_db"
db_uri = f'mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
print(f"DEBUG: Configurando URI de BD: {db_uri[:db_uri.find('@')+1]}********")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False

# --- INICIALIZACIÓN DE EXTENSIONES ---
print("DEBUG: Inicializando SQLAlchemy...")
try: db = SQLAlchemy(app); print("DEBUG: SQLAlchemy inicializado.")
except Exception as e_sql: print(f"FATAL ERROR: Inicializando SQLAlchemy: {e_sql}"); exit()

print("DEBUG: Inicializando LoginManager...")
try: login_manager = LoginManager(app); print(f"DEBUG: LoginManager instanciado: {login_manager}"); login_manager.login_view = 'login'; login_manager.login_message = "Por favor, inicia sesión."; login_manager.login_message_category = "info"; print("DEBUG: Configuración LoginManager completa.")
except Exception as e_login: print(f"FATAL ERROR: Inicializando LoginManager: {e_login}"); exit()
# --- FIN INICIALIZACIÓN ---

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_SIM_FOLDER'], exist_ok=True)

# --- Instancias Globales (Managers) ---
def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
try: print("DEBUG: Inicializando Managers..."); data_manager = DataManager(); simulator = ThreatSimulator(); alert_manager = AlertManager(); model_file_path = None; detector = ThreatDetector(model_path=model_file_path); admin_manager = AdminManager(detector_instance=detector); print("DEBUG: Managers inicializados.")
except Exception as e: print(f"FATAL ERROR inicializando manager: {e}\n{traceback.format_exc()}"); exit()

detection_history = []

# --- MODELO DE BASE DE DATOS (USUARIO) ---
print("DEBUG: Definiendo modelo User...")
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) # Bcrypt hash tiene 60 chars
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    

    # --- MÉTODO set_password (CORRECTAMENTE FORMATEADO) ---
    def set_password(self, password):
        """Hashea la contraseña y la guarda."""
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        

    # --- MÉTODO check_password (CORRECTAMENTE FORMATEADO) ---
    def check_password(self, password):
        """Verifica una contraseña contra el hash guardado."""
        # Comprobar primero si hay hash guardado
        if not self.password_hash:
             return False
        try:
            password_bytes = password.encode('utf-8')
            stored_hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, stored_hash_bytes)
        except Exception as e:
             # Loggear el error es importante en producción
             print(f"ERROR verificando password para user {self.id}: {e}")
             return False # Ser cauto y devolver False si hay error

    def __repr__(self):
        return f'<User {self.username}>'
print("DEBUG: Modelo User definido.")

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    try: return User.query.get(int(user_id))
    except Exception as e: print(f"Error cargando user_id {user_id}: {e}"); return None

# --- FORMULARIOS (Flask-WTF) ---
print("DEBUG: Definiendo Formularios...")
class LoginForm(FlaskForm): username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)]); password = PasswordField('Contraseña', validators=[DataRequired()]); remember_me = BooleanField('Recuérdame'); submit = SubmitField('Iniciar Sesión')
class RegistrationForm(FlaskForm): username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)]); email = StringField('Email', validators=[DataRequired(), Email()]); password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)]); confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password', message='Las contraseñas no coinciden.')]); submit = SubmitField('Registrarse')
def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('Usuario ya existe.')
        def validate_email(self, email):
            if User.query.filter_by(email=email.data).first(): raise ValidationError('Email ya registrado.')
print("DEBUG: Formularios definidos.")

print("DEBUG: Definiendo Formularios Admin User...")

class UserAdminForm(FlaskForm):
    """Formulario base para Crear y Editar usuarios desde el panel Admin."""
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # La contraseña es opcional al editar, solo necesaria para crear o cambiar
    password = PasswordField('Contraseña (dejar vacío para no cambiar)')
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')

    # Validadores personalizados para verificar unicidad de username y email
    # Se llamarán automáticamente si el campo tiene un validador con el mismo nombre
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(UserAdminForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        # Solo validar si el username ha cambiado
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Este nombre de usuario ya está en uso.')

    def validate_email(self, email):
        # Solo validar si el email ha cambiado
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Este email ya está registrado.')

class DeleteUserForm(FlaskForm):
    """Formulario simple para confirmar la eliminación de un usuario."""
    submit = SubmitField('Eliminar Usuario')

print("DEBUG: Formularios Admin User definidos.")

# --- Context Processor ---
@app.context_processor
def inject_current_year(): return {'current_year': datetime.datetime.now().year}

# --- Filtro Jinja2 para Fechas ---
@app.template_filter('format_datetime')
def format_datetime_filter(iso_string, format='%Y-%m-%d %H:%M:%S'):
    if not iso_string: return "N/A";
    try: dt = datetime.datetime.fromisoformat(iso_string); return dt.strftime(format);
    except: return iso_string
    
    print("DEBUG: Definiendo funciones de reporte...")

def generate_last_detection_csv(detection_results):
    """Genera el contenido CSV para los últimos resultados de detección."""
    if not detection_results:
        return None

    output = io.StringIO()

    # Añadir información de resumen
    output.write("Reporte de Última Detección\n")
    output.write(f"Timestamp: {detection_results.get('timestamp', 'N/A')}\n")
    output.write(f"Fuente de Datos: {detection_results.get('source_info', 'N/A')}\n")
    output.write(f"Filas Analizadas: {detection_results.get('rows_analyzed', 'N/A')}\n")
    output.write(f"Umbral del Modelo: {detection_results.get('model_threshold', 'N/A')}\n\n")

    # Añadir métricas
    metrics = detection_results.get('metrics', {})
    if metrics:
        output.write("Métricas del Modelo:\n")
        # Intenta añadir métricas simples como accuracy, precisión, etc.
        simple_metrics = {k: v for k, v in metrics.items() if not isinstance(v, (dict, list))}
        for name, value in simple_metrics.items():
            output.write(f"{name.replace('_', ' ').title()},{value}\n")

        # Manejar reporte de clasificación si está presente
        classification_report = metrics.get('report', {})
        if classification_report and isinstance(classification_report, dict):
             output.write("\nReporte de Clasificación:\n")
             try:
                 # Convertir el diccionario del reporte a DataFrame de pandas
                 # Asumimos que el reporte tiene la estructura { 'clase': { 'metricas' }, ... }
                 report_df = pd.DataFrame(classification_report).transpose()
                 # Escribir el DataFrame a CSV, incluyendo el índice (las clases)
                 report_df.to_csv(output, index=True, header=True)
             except Exception as e:
                 output.write(f"Error al formatear reporte de clasificación en CSV: {e}\n")

    # Añadir resumen de detecciones (conteo por etiqueta)
    summary = detection_results.get('detection_summary', {})
    if summary:
        output.write("\nResumen de Detecciones:\n")
        output.write("Etiqueta,Cantidad\n")
        for label, count in summary.items():
            output.write(f"{label},{count}\n")

    # Añadir vista previa de datos (primeras 100 filas)
    data_head_records = detection_results.get('data_head', [])
    if data_head_records:
        output.write("\nVista Previa de Datos (Primeras 100 filas):\n")
        try:
            # Crear DataFrame desde la lista de diccionarios
            data_head_df = pd.DataFrame(data_head_records)
            # Escribir el DataFrame a CSV, sin el índice numérico de pandas
            data_head_df.to_csv(output, index=False)
        except Exception as e:
            output.write(f"Error al formatear vista previa de datos en CSV: {e}\n")

    output.seek(0) # Volver al inicio del objeto StringIO
    return output.getvalue() # Retornar el contenido como string

print("DEBUG: Funciones de reporte definidas.")

# --- Helper para Gráficos ---
def generate_plot_base64(plot_function, *args, **kwargs):
    """Ejecuta una función de ploteo y devuelve la imagen como base64."""
    # Nivel 1 de indentación (dentro de la función)
    img = io.BytesIO()
    fig = None # Para asegurar que cerramos la figura
    try:
        # Nivel 2 de indentación (dentro de try)
        fig = plt.figure(figsize=kwargs.pop('figsize', (5, 4))) # Permitir pasar figsize
        plot_function(fig=fig, *args, **kwargs) # Pasar figura a la función de ploteo
        plt.savefig(img, format='png', bbox_inches='tight') # Guardar en buffer
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8') # Codificar
        return f"data:image/png;base64,{plot_url}"
    except Exception as e:
        # Nivel 2 de indentación (dentro de except)
        print(f"Error generando gráfico: {e}\n{traceback.format_exc()}")
        return None
    finally:
        # Nivel 2 de indentación (dentro de finally)
        # Asegurar que la figura se cierra siempre para liberar memoria
        if fig:
            # Nivel 3 de indentación (dentro de if)
            plt.close(fig)
# --- Fin de la función ---
# --- Rutas de Flask ---
print("DEBUG: Definiendo rutas Flask...")

print("DEBUG: Definiendo funciones de gráficos...")

# Asegúrate de que generate_plot_base64 esté definida antes de esta función si la pones después

def plot_confusion_matrix_func(cm, fig, classes=['BENIGN', 'ATTACK'], title='Matriz de Confusión'):
    """
    Genera un plot de la matriz de confusión en la figura de matplotlib proporcionada.
    Args:
        cm (list or np.array): La matriz de confusión (ej: [[TN, FP], [FN, TP]]).
        fig (matplotlib.figure.Figure): La figura de matplotlib donde dibujar.
        classes (list): Lista de nombres de clases (ej: ['BENIGN', 'ATTACK']).
        title (str): Título del plot.
    """
    try:
        ax = fig.add_subplot(111) # Añadir un subplot a la figura
        # Asegurarse de que cm es un numpy array para seaborn si no lo es ya
        cm_array = np.array(cm)
        sns.heatmap(cm_array, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False)

        # Etiquetas y título
        ax.set_xlabel('Predicción')
        ax.set_ylabel('Valor Real')
        ax.set_title(title)
        ax.xaxis.set_ticklabels(classes)
        ax.yaxis.set_ticklabels(classes)

        # Asegurar que las etiquetas no se corten
        plt.tight_layout()

    except Exception as e:
        print(f"Error en plot_confusion_matrix_func: {e}\n{traceback.format_exc()}")
        # Puedes añadir un mensaje de error en el plot si quieres, por ejemplo:
        # fig.text(0.5, 0.5, f'Error generando plot:\n{e}', horizontalalignment='center', verticalalignment='center', color='red', fontsize=10)


print("DEBUG: Funciones de gráficos definidas.")

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirigir si ya está autenticado
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm() # Crear instancia del formulario

    # Procesar si el formulario se envió (POST) y es válido
    if form.validate_on_submit():
        # --- CORRECCIÓN: Buscar al usuario ANTES de usar la variable 'user' ---
        user = User.query.filter_by(username=form.username.data).first()

        # --- CORRECCIÓN: Usar if/else multi-línea ---
        # Verificar si se encontró el usuario Y si la contraseña es correcta
        if user and user.check_password(form.password.data):
            # --- Código si el login es exitoso (indentado) ---
            login_user(user, remember=form.remember_me.data)
            flash(f'Inicio de sesión exitoso para {user.username}!', 'success')

            # Redirigir a la página 'next' si existe, o al dashboard
            next_page = request.args.get('next')
            # Comprobación de seguridad para evitar redirecciones abiertas
            if next_page and url_parse(next_page).netloc == '':
                 return redirect(next_page)
            else:
                 return redirect(url_for('dashboard'))
        else:
            # --- Código si el login falla (indentado) ---
            # Si el usuario no existe o la contraseña es incorrecta
            flash('Inicio de sesión fallido. Verifica usuario y contraseña.', 'error')
        # --- Fin del if/else ---

    # Mostrar la plantilla de login para solicitudes GET o si el form no es válido
    return render_template('login.html', title='Iniciar Sesión', form=form)
@app.route('/logout')
@login_required
def logout(): logout_user(); flash('Sesión cerrada.', 'info'); return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Nivel 0 indentación (inicio de función)
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Nivel 1 indentación (dentro del if validate)
        try:
            # Nivel 2 indentación (dentro del try)
            new_user = User(username=form.username.data, email=form.email.data)
            new_user.set_password(form.password.data) # Hashear contraseña

            # Comprobar si es el primer usuario DENTRO del try
            # Nivel 2 indentación
            if User.query.count() == 0:
                # Nivel 3 indentación (dentro del if anidado)
                new_user.is_admin = True
                print(f"INFO: Primer usuario '{new_user.username}' reg. como admin.")

            # Añadir y guardar en BD DENTRO del try
            # Nivel 2 indentación
            db.session.add(new_user)
            db.session.commit()
            flash(f'Cuenta creada para {form.username.data}! Inicia sesión.', 'success')
            print(f"INFO: Nuevo user: {form.username.data}")
            return redirect(url_for('login'))
        # Nivel 1 indentación (except al mismo nivel que try)
        except Exception as e:
            # Nivel 2 indentación (dentro del except)
            db.session.rollback() # Revertir cambios en caso de error
            flash(f'Error creando cuenta: {e}', 'error')
            print(f"ERROR registro: {e}\n{traceback.format_exc()}")
    # Nivel 0 indentación (return para método GET o si el form no validó en POST)
    return render_template('register.html', title='Registro', form=form)

# --- RUTAS PRINCIPALES (Protegidas) ---
@app.route('/')
@login_required
def dashboard():
    try: active_alerts = [a for a in alert_manager.alerts if not a.get('reviewed')]; last_detection_entry = detection_history[-1] if detection_history else None; model_status = "Real" if detector.model else "Simulado"; all_alerts_sorted = alert_manager.get_alerts(show_all=True); recent_alerts = all_alerts_sorted[:5]
    except Exception as e: print(f"ERROR dashboard: {e}\n{traceback.format_exc()}"); flash("Error dashboard.", "error"); active_alerts, last_detection_entry, model_status, recent_alerts = [], None, "Error", []
    return render_template('dashboard.html', active_alerts_count=len(active_alerts), last_detection=last_detection_entry, model_status=model_status, recent_alerts=recent_alerts)

@app.route('/data', methods=['GET', 'POST'])
@login_required
def manage_data():
    if request.method == 'POST':
        action = request.form.get('action'); redirect_url = url_for('manage_data')
        try:
            if action == 'upload':
                if 'file' not in request.files: flash('No se encontró archivo.', 'error'); return redirect(redirect_url)
                file = request.files['file']; filename = file.filename
                if filename == '': flash('No se seleccionó archivo.', 'warning'); return redirect(redirect_url)
                if file and allowed_file(filename):
                    filename = secure_filename(filename); filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename); file.save(filepath)
                    success, message = data_manager.load_csv_data(filepath)
                    # --- Bloque if/else corregido (multi-línea) ---
                    if success:
                        flash(message, 'success')
                        session['loaded_filepath'] = filepath
                        session.pop('processed_data_info', None)
                    else:
                        flash(message, 'error')
                        session.pop('loaded_filepath', None)
                elif file:
                    flash(f"Tipo archivo no permitido.", 'error')
            elif action == 'preprocess':
                if data_manager.loaded_data is not None:
                    success, message = data_manager.preprocess_data()
                    if success:
                        flash(message, 'success')
                        session['processed_data_info'] = {'rows': len(data_manager.processed_data), 'cols': len(data_manager.processed_data.columns), 'timestamp': datetime.datetime.now().isoformat(timespec='seconds')}
                    else:
                        flash(message, 'error')
                        session.pop('processed_data_info', None)
                else:
                    flash('Primero carga archivo CSV.', 'warning')
            else:
                flash('Acción desconocida.', 'warning')
        except Exception as e:
            flash(f"Error inesperado: {e}", "error")
            print(f"ERROR manage_data POST: {e}\n{traceback.format_exc()}")
        return redirect(redirect_url)
    # GET Request
    try: loaded_head_html = data_manager.get_loaded_data_head_html(); processed_head_html = data_manager.get_processed_data_head_html(); processed_info = session.get('processed_data_info'); loaded_filepath = session.get('loaded_filepath'); loaded_filename = os.path.basename(loaded_filepath) if loaded_filepath and os.path.exists(loaded_filepath) else None
    except Exception as e: print(f"ERROR manage_data GET: {e}\n{traceback.format_exc()}"); flash("Error vistas previas.", "error"); loaded_head_html, processed_head_html, processed_info, loaded_filename = "<p>Err</p>", "<p>Err</p>", None, None
    return render_template('data_management.html', loaded_head_html=loaded_head_html, processed_head_html=processed_head_html, loaded_filename=loaded_filename, processed_info=processed_info)

@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    if request.method == 'POST':
        try:
            duration = int(request.form.get('duration', '60')); intensity = int(request.form.get('intensity', '5'))
            attacks_list = request.form.getlist('attacks'); attacks = [a.strip() for a in attacks_list if a.strip()] or ['Attack']
            if duration <= 0: raise ValueError("Duración > 0");
            if not (1 <= intensity <= 10): raise ValueError("Intensidad 1-10")
            config = {"duration": duration, "intensity": intensity, "attacks": attacks}
            print(f"INFO: Solicitud simulación: {config}"); sim_result_df = simulator.run_simulation(config)
            if sim_result_df is not None and not sim_result_df.empty:
                sim_id = str(uuid.uuid4()); temp_filename = f"sim_data_{sim_id}.pkl"; temp_filepath = os.path.join(app.config['TEMP_SIM_FOLDER'], temp_filename)
                try: sim_result_df.to_pickle(temp_filepath); print(f"INFO: Simulación guardada: {temp_filepath}"); session.pop('last_simulation_data', None); session['simulation_ran'] = True; session['last_simulation_filepath'] = temp_filepath; session['simulation_info'] = {'rows_generated': len(sim_result_df), 'config': config, 'timestamp': datetime.datetime.now().isoformat(timespec='seconds'), 'filepath': temp_filepath}; flash(f'Simulación completada ({len(sim_result_df)} registros).', 'success')
                except Exception as e_save: flash(f"Error guardando simulación: {e_save}", "error"); print(f"ERROR guardando pickle: {e_save}\n{traceback.format_exc()}"); session.clear()
            else: flash('Simulación no generó datos.', 'warning'); session.pop('simulation_ran', None); session.pop('last_simulation_filepath', None); session.pop('simulation_info', None)
        except ValueError as ve: flash(f'Entrada inválida: {ve}', 'error')
        except Exception as e: flash(f'Error inesperado simulación: {e}', 'error'); print(f"ERROR simulate POST: {e}\n{traceback.format_exc()}"); session.pop('simulation_ran', None); session.pop('last_simulation_filepath', None); session.pop('simulation_info', None)
        return redirect(url_for('simulate'))
    # GET Request
    try: last_sim_info = session.get('simulation_info'); last_sim_preview_df = None; sim_history = simulator.get_history()
    except Exception as e: print(f"ERROR simulate GET: {e}\n{traceback.format_exc()}"); flash("Error cargando datos simulación.", "error"); last_sim_info, last_sim_preview_df, sim_history = None, None, []
    return render_template('simulator.html', simulation_history=sim_history, last_simulation_info=last_sim_info, last_simulation_preview_df=last_sim_preview_df)

@app.route('/report/last_detection_csv')
@login_required # Protege esta ruta
# @admin_required # Opcional: si solo los admins pueden descargar reportes
def download_last_detection_csv():
    """Ruta para descargar el reporte CSV de la última detección."""
    # Obtener los últimos resultados de detección de la sesión
    last_results = session.get('last_detection_results')

    if not last_results:
        flash("No hay resultados de detección recientes para generar reporte.", "warning")
        return redirect(url_for('detect')) # Redirige de vuelta a la página de detección

    try:
        # Generar el contenido CSV
        csv_content = generate_last_detection_csv(last_results)

        if csv_content is None:
             flash("Error al generar el contenido del reporte CSV.", "error")
             return redirect(url_for('detect'))

        # Crear una respuesta Flask para servir el archivo
        response = make_response(csv_content)

        # Establecer las cabeceras para forzar la descarga y nombrar el archivo
        timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"reporte_deteccion_{timestamp_str}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-type"] = "text/csv" # Tipo MIME para CSV

        print(f"INFO: Reporte CSV generado y enviado: {filename}")
        return response # Retorna la respuesta con el archivo

    except Exception as e:
        print(f"ERROR generando reporte CSV: {e}\n{traceback.format_exc()}")
        flash("Error interno al generar el reporte CSV.", "error")
        return redirect(url_for('detect')) # Redirige en caso de error interno

@app.route('/detect', methods=['GET', 'POST'])
@login_required # Asegúrate de que este decorador esté presente y alineado a la izquierda
def detect(): # La definición de la función también debe estar alineada a la izquierda
    print(f"DEBUG: Accediendo a ruta /detect con método {request.method}")
    # Obtener historial al inicio para que esté disponible tanto en POST como en GET
    detection_history = alert_manager.get_detection_history()

    if request.method == 'POST': # La sentencia if para el método POST
        print("DEBUG: Procesando solicitud POST para /detect")
        try: # <-- Primer try block (para manejar errores generales del POST)
            # --- Procesar Selección de Fuente de Datos ---
            datasource = request.form.get('datasource')
            print(f"DEBUG: Fuente de datos seleccionada: {datasource}")
            df_to_detect = None
            source_info = "Fuente Desconocida" # Inicializar source_info

            if datasource == 'processed': # Indentado dentro del try de POST
                processed_data_obj = data_manager.get_processed_data() # Indentado dentro del if
                if processed_data_obj is not None and not processed_data_obj.empty: # Indentado dentro del if
                    df_to_detect = processed_data_obj # Indentado dentro del if
                    source_info = "Datos Cargados y Preprocesados" # Indentado dentro del if
                else: # Indentado al mismo nivel que el if processed_data_obj
                    flash("No hay datos cargados y preprocesados disponibles.", "warning") # Indentado dentro del else
                    print("WARN: Intento de detección con datos preprocesados pero no disponibles.") # Indentado dentro del else

            elif datasource == 'simulation': # Indentado al mismo nivel que el if datasource == 'processed'
                sim_info = session.get('simulation_info') # Indentado dentro del elif
                if sim_info and sim_info.get('filepath') and os.path.exists(sim_info['filepath']): # Indentado dentro del elif
                    try: # <-- try block para cargar datos de simulación
                        print(f"INFO: Cargando datos de simulación desde {sim_info['filepath']}") # Indentado dentro del try
                        df_to_detect = pd.read_pickle(sim_info['filepath']) # Indentado dentro del try
                        source_info = f"Datos de Simulación ({os.path.basename(sim_info['filepath'])})" # Indentado dentro del try
                    except Exception as e: # <-- except block para cargar datos de simulación (alineado con su try)
                        print(f"ERROR cargando datos de simulación para detección: {e}\n{traceback.format_exc()}") # Indentado dentro del except
                        flash(f"Error al cargar datos de simulación para detección: {e}", "danger") # Indentado dentro del except
                        df_to_detect = None # Indentado dentro del except
                else: # Indentado al mismo nivel que el if sim_info
                    flash("No hay datos de simulación disponibles.", "warning") # Indentado dentro del else
                    print("WARN: Intento de detección con datos de simulación pero no disponibles.") # Indentado dentro del else

            else: # Indentado al mismo nivel que if/elif datasource
                flash("Fuente de datos no válida seleccionada.", "danger") # Indentado dentro del else
                print(f"WARN: Fuente de datos no válida seleccionada: {datasource}") # Indentado dentro del else

            # --- Ejecutar Detección ---
            detection_output = None
            if df_to_detect is not None and not df_to_detect.empty: # Indentado dentro del try de POST
                print(f"INFO: Iniciando detección: {source_info} ({len(df_to_detect)} filas)...") # Indentado dentro del if
                try: # <-- try block para la ejecución del detector
                    # Esta es la llamada principal al detector
                    detection_output = detector.run_detection(df_to_detect) # Indentado dentro del try
                    print("INFO: Ejecución de detección completada.") # Indentado dentro del try

                except Exception as e: # <-- except block para la ejecución del detector (alineado con su try)
                    print(f"ERROR durante la ejecución del detector: {e}\n{traceback.format_exc()}") # Indentado dentro del except
                    flash(f"Error durante la detección: {e}", "danger") # Indentado dentro del except
                    detection_output = None # Asegurar que detection_output sea None si hay error

            # --- Guardar Resultados en Sesión e Historial y Generar Alertas ---
            if detection_output is not None: # Indentado dentro del try de POST
                print("DEBUG: Procesando resultados de detección...") # Indentado dentro del if
                try: 
                    if request.method == 'POST':
                        if detection_output is not None:
                            print("DEBUG: Procesando resultados de detección...")
                            try:
                                results_for_session_and_history = {
                                    'timestamp': datetime.datetime.now().isoformat(),
                                    'source_info': source_info,
                                    'rows_analyzed': len(df_to_detect) if df_to_detect is not None else 0,
                                    'model_threshold': getattr(detector, 'prediction_threshold', None), # Re-verifica esta línea
                                    'metrics': detection_output.get('metrics', {}), # Re-verifica esta línea
                                    'detection_summary': detection_output.get('detection_summary', {}),
                                    }
                                print("\n--- DEBUG: Contenido de detection_output retornado por detector.run_detection ---")
                                print(f"DEBUG: detection_output: {detection_output}") # Imprime el diccionario completo retornado
                                print("\n--- DEBUG: Contenido de results_for_session_and_history antes de guardar ---")
                                print(f"DEBUG: results_for_session_and_history: {results_for_session_and_history}")
                                print("--- FIN DEBUG ---\n")
                                history_summary = results_for_session_and_history.copy()
                                history_summary.pop('data_head', None)
                                print("\n--- DEBUG: history_summary final antes de añadir a alert_manager ---")
                                print(f"DEBUG: history_summary: {history_summary}")
                                print("--- FIN DEBUG ---\n")
                                alert_manager.add_detection_to_history(history_summary)
                                print("INFO: Resumen de detección añadido al historial.")
                            except Exception as e:
                                results_for_session_and_history = { # Indentado dentro del try
                        'timestamp': datetime.datetime.now().isoformat(), # Guardar como ISO string para compatibilidad de sesión
                        'source_info': source_info, # Info sobre la fuente de datos
                        'rows_analyzed': len(df_to_detect) if df_to_detect is not None else 0,
'model_threshold': getattr(detector, 'prediction_threshold', None),
'metrics': detection_output.get('metrics', {}),
                        'detection_summary': detection_output.get('detection_summary', {}), # Guardar resumen (dict)
                        
            
                    }
                    
                                        

                    # Limitar las filas para la vista previa en sesión para evitar Cookie too large
                    max_rows_head = 5 # <-- LIMITAR FILAS AQUÍ PARA LA SESION
                    detection_data_df = detection_output.get('data') # Obtener el DF con las columnas originales + predicciones
                    if detection_data_df is not None and not detection_data_df.empty:
                        # Convertir las primeras N filas a lista de diccionarios para guardar en sesión
                        # Seleccionar solo las columnas que queremos mostrar en la vista previa
                        preview_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label']
                        # Asegurarnos de que las columnas existen antes de seleccionarlas
                        available_preview_cols = [col for col in preview_cols if col in detection_data_df.columns]

                        if available_preview_cols:
                            results_for_session_and_history['data_head'] = detection_data_df[available_preview_cols].head(max_rows_head).to_dict('records')
                        else:
                            # Si no hay columnas de vista previa disponibles, guardar todas las columnas (limitado por max_rows_head)
                            print("WARN: Columnas requeridas para vista previa no encontradas. Guardando todas las columnas del head.")
                            results_for_session_and_history['data_head'] = detection_data_df.head(max_rows_head).to_dict('records')

                    else:
                        print("WARN: No hay DataFrame de detección disponible para data_head.")
                        results_for_session_and_history['data_head'] = [] # Asegurar que siempre sea una lista

                    # Store results in session
                    session['last_detection_results'] = results_for_session_and_history
                    print("DEBUG: Resultados de detección guardados en sesión.")

                    # Add summary to history managed by AlertManager
                    # Asegurar que solo guardamos un resumen en el historial (sin el data_head completo)
                    history_summary = results_for_session_and_history.copy()
                    history_summary.pop('data_head', None) # Eliminar data_head del historial para mantenerlo ligero
                    alert_manager.add_detection_to_history(history_summary)
                    print("INFO: Resumen de detección añadido al historial.")

                    # Generar alertas basadas en los resultados (usando el DataFrame completo, no solo el head)
                    # Asume que generate_alerts espera el DataFrame o una lista de resultados específicos
                    alert_manager.generate_alerts(detection_output.get('data')) # Pasa el DataFrame completo si generate_alerts lo espera así
                    print(f"INFO: Nuevas alertas generadas (cumpliendo umbral '{alert_manager.config.get('severity_threshold', 'Media')}').")

                    flash("Detección completada exitosamente.", "success")
                    print("SUCCESS: Detección completada.")

                except Exception as e: # <-- except block para procesar resultados post-detección (alineado con su try)
                    print(f"ERROR procesando resultados post-detección: {e}\n{traceback.format_exc()}")
                    flash(f"Error al procesar resultados de detección: {e}", "danger")

            else: # Indentado al mismo nivel que el 'if detection_output is not None:'
                # Esto ocurre si df_to_detect estaba vacío o si run_detection retornó None
                if df_to_detect is not None and not df_to_detect.empty: # Comprobar si había datos para detectar
                    flash("La detección no produjo resultados válidos.", "warning")
                    print("WARN: Detección no produjo resultados válidos.")
                # Si no había datos para detectar, el mensaje ya se flasheó antes.
                print("DEBUG: detection_output estaba None o df_to_detect estaba vacío/None.")


        except Exception as e: # <-- except block para el try principal de POST (alineado con el primer 'try:')
            print(f"ERROR general en POST /detect: {e}\n{traceback.format_exc()}")
            flash(f"Error interno al iniciar la detección: {e}", "danger")

        # Después de procesar POST (éxito o error), redirigir a la misma ruta GET
        # La ruta GET leerá los resultados (si se guardaron en la sesión) o mostrará el estado inicial
        print("DEBUG: Redirigiendo a /detect GET después de POST.")
        return redirect(url_for('detect')) # <-- RETORNO después de POST (indentado al mismo nivel que el if request.method)


    # GET Request (Este bloque maneja la solicitud GET inicial o la redirección después de POST)
    # Bloque try principal para todo el procesamiento de la solicitud GET
    try: # <-- Segundo try block (para manejar errores generales del GET)
        
        # Inicializar variables con valores por defecto seguros
        last_results = session.get('last_detection_results')
        cm_plot_url = None
        report_df = None
        metrics = None # Define metrics initially as None
        data_head_html = None # Variable para almacenar la cadena HTML de la vista previa de datos

        # --- Procesar Métricas si están Disponibles ---
        # Comprobar si hay resultados en la sesión y si el diccionario de métricas existe y es un diccionario
        if last_results and isinstance(last_results.get('metrics'), dict): # Indentado dentro del try de GET
            metrics = last_results['metrics'] # Asignar metrics si es válido (indentado dentro del if)
            print("DEBUG: Métricas encontradas en la sesión.")

        # Si las métricas están disponibles, procesar el plot y el reporte
        if metrics: # Indentado dentro del try de GET
            print("DEBUG: Procesando métricas para vista GET.")
            # --- Procesar Plot de Matriz de Confusión ---
            # Comprobar si los datos de la matriz de confusión existen
            if metrics.get('confusion_matrix') is not None: # Indentado dentro del if metrics
                try: # <-- try block específicamente para la generación del plot CM
                    # generate_plot_base64 requiere la función de ploteo y los datos
                    # Asegúrate de que plot_confusion_matrix_func está definida antes de esta ruta
                    cm_plot_url = generate_plot_base64(plot_confusion_matrix_func, metrics['confusion_matrix']) # Indentado dentro del try
                    print("DEBUG: Plot CM generado.")
                except Exception as e: # <-- except block para la generación del plot CM (alineado con su try)
                    print(f"ERROR generando plot CM: {e}\n{traceback.format_exc()}") # Indentado dentro del except
                    cm_plot_url = None # Establecer a None si falla la generación del plot (indentado dentro del except)

            # --- Procesar Reporte de Clasificación ---
            # Comprobar si los datos del reporte existen
            if metrics.get('report') is not None: # Indentado dentro del if metrics
                try: # <-- Try block para convertir el diccionario del reporte a DataFrame
                    report_df = pd.DataFrame(metrics['report']).transpose() # Indentado dentro del try
                    print("DEBUG: Reporte convertido a DataFrame.")
                except Exception as e: # <-- except block para convertir reporte a DF (alineado con su try)
                    print(f"WARN: Falló la conversión del reporte a DF: {e}") # Indentado dentro del except
                    report_df = None # Asignar None si falla la conversión (indentado dentro del except)
            # --- Fin Procesar Reporte de Clasificación ---
        # --- Fin Procesar Métricas si están Disponibles ---


        # --- Manejar Vista Previa de Datos en App.py (para mostrar en el template GET) ---
        # Esta lógica genera el HTML para mostrar las primeras filas guardadas en sesión
        if last_results and last_results.get('data_head'): # Indentado dentro del try de GET
            data_head_records = last_results['data_head'] # Obtener la lista de dicts (limitada a 5 en POST) (indentado dentro del if)
            if data_head_records: # Comprobar si la lista de registros no está vacía (indentado dentro del if)
                print("DEBUG: Generando vista previa de datos HTML.")
                try: # <-- try block para generar HTML de vista previa
                    # Convertir la lista de dicts a DataFrame de pandas
                    preview_df = pd.DataFrame(data_head_records) # Indentado dentro del try
                    # Seleccionar columnas específicas para la tabla de vista previa
                    # Asegúrate de que los nombres de columna coinciden exactamente con tu DataFrame
                    required_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label']
                    # Comprobar si todas las columnas requeridas existen antes de seleccionar
                    available_cols = [col for col in required_cols if col in preview_df.columns] # Indentado dentro del try

                    if available_cols: # <--- INICIO IF correctamente indentado (dentro del try)
                        # Generar HTML tabla para las columnas seleccionadas
                        data_head_html = preview_df[available_cols].to_html(classes=['data-table', 'table-sm'], border=0, index=False) # max_rows handled by head(5) in POST (indentado dentro del if)
                        print("DEBUG: HTML de vista previa generado con columnas requeridas.")
                    else: # <--- ELSE correctamente indentado (alineado con el 'if available_cols:')
                        print("WARN: Ninguna de las columnas requeridas para vista previa de datos encontrada en data_head. Generando con columnas disponibles.") # Indentado dentro del else
                        # Fallback: generar HTML para todas las columnas disponibles si ninguna de las requeridas existe
                        data_head_html = preview_df.to_html(classes=['data-table', 'table-sm'], border=0, index=False) # Indentado dentro del else
                        print("DEBUG: HTML de vista previa generado con todas las columnas disponibles.")


                except Exception as e: # <--- EXCEPT para el 'try' que intenta generar el HTML (alineado con su try)
                    print(f"ERROR generando HTML para vista previa de datos: {e}\n{traceback.format_exc()}") # Indentado dentro del except
                    data_head_html = "<p>Error al cargar vista previa de datos.</p>" # Mensaje de error si falla la generación HTML (indentado dentro del except)
            else: # <--- ELSE para el 'if data_head_records:' (alineado con el if)
                # Mensaje si data_head existe en la sesión pero es una lista vacía
                data_head_html = "<p>No hay datos disponibles para la vista previa.</p>" # Indentado dentro del else
                print("DEBUG: data_head estaba vacío o None, no se generó HTML de vista previa.")
        else: # <--- ELSE para el 'if last_results and last_results.get('data_head'):' (alineado con el if)
             # Mensaje si no hay last_results o data_head en la sesión
             data_head_html = "<p>No hay resultados de detección previos para mostrar la vista previa.</p>"
             print("DEBUG: No hay last_detection_results o data_head en sesión.")
        # --- Fin Manejar Vista Previa de Datos ---


        # --- Verificar disponibilidad de datos para el formulario (para mostrar en el template GET) ---
        print("DEBUG: Verificando disponibilidad de datos para el formulario GET.")
        # Check if simulation data file exists based on session info
        sim_info = session.get('simulation_info', {}) # Usar .get con {} para evitar error si 'simulation_info' no existe
        sim_filepath = sim_info.get('filepath')
        has_simulation_file = sim_filepath and os.path.exists(sim_filepath)
        print(f"DEBUG: Archivo simulación disponible: {has_simulation_file}")

        # Check if processed data exists in the DataManager instance
        processed_data_obj = data_manager.get_processed_data()
        has_processed = processed_data_obj is not None and not processed_data_obj.empty
        print(f"DEBUG: Datos preprocesados disponibles: {has_processed}")
        # --- Fin Verificar disponibilidad de datos ---


    except Exception as e: # <-- except block principal para el TRY de la solicitud GET (alineado con el 'try:' al inicio del bloque GET)
        print(f"ERROR general en GET /detect: {e}\n{traceback.format_exc()}")
        flash("Error preparando página de detección.", "error")
        # Asegurar que todas las variables pasadas a la plantilla tengan valores por defecto seguros en caso de CUALQUIER error en el try
        last_results = None
        cm_plot_url = None
        report_df = None
        data_head_html = "<p>Error al cargar la página de detección.</p>" # Mensaje de error genérico para la vista previa
        has_processed = False
        has_simulation_file = False
        # detection_history y detector se asumen disponibles globalmente o manejados fuera de este error específico


    # --- RETURN FINAL ---
    # Esta sentencia return está FUERA del bloque try/except principal de GET
    # Asegura que la función siempre devuelve una respuesta, incluso si hay un error en el try de GET
    print("DEBUG: Renderizando template detection.html...")
    return render_template('detection.html', # <-- LA SENTENCIA RETURN FINAL, DEBE ESTAR ALINEADA CON LA SENTENCIA 'try:' y 'except:' principal del bloque GET
        has_processed_data=has_processed,
        has_simulation_data=has_simulation_file,
        last_results=last_results, # Todavía pasamos last_results por si el template lo usa en otras partes
        report_df=report_df,
        cm_plot_url=cm_plot_url,
        data_head_html=data_head_html, # Pasamos la cadena HTML generada para la vista previa de datos
        detection_history=detection_history, # Se asume globalmente accesible o manejado (se obtiene al inicio de la función)
        detector=detector # Se asume globalmente accesible
    )
# En app.py

# ... (importaciones y otras rutas) ...

@app.route('/alerts', methods=['GET', 'POST'])
@login_required
def alerts():
    # Determinar la URL de redirección al principio es útil
    redirect_url = url_for('alerts', show_all=request.args.get('show_all', 'false'))

    if request.method == 'POST':
        action = request.form.get('action') # Obtener la acción del formulario

        try:
            # === MANEJAR LA NUEVA ACCIÓN 'delete_all' ===
            if action == 'delete_all':
                print("INFO: Solicitud para borrar todas las alertas recibida.")
                # Suponiendo que tu alert_manager tiene un método delete_all_alerts()
                # Este método debería devolver (True/False, mensaje)
                success, message = alert_manager.delete_all_alerts()
                flash(message, 'success' if success else 'error')
            # === FIN MANEJO 'delete_all' ===

            # === LÓGICA EXISTENTE (Marcar como revisada) ===
            # Si la acción no es 'delete_all', asumimos que es marcar una alerta.
            # Verificamos si se envió 'alert_id'.
            else:
                alert_id_str = request.form.get('alert_id')
                if alert_id_str:
                    alert_id = int(alert_id_str) # Puede lanzar ValueError
                    success_mark = alert_manager.mark_alert_reviewed(alert_id)
                    flash(f"Alerta {alert_id} marcada como revisada.", 'success') if success_mark else flash(f"No se pudo marcar la alerta {alert_id}.", 'warning')
                else:
                    # Si no es 'delete_all' y no hay 'alert_id', es una solicitud POST inesperada
                    flash("Acción desconocida o ID de alerta faltante.", 'warning')
            # === FIN LÓGICA EXISTENTE ===

        except ValueError:
             # Este error solo ocurriría al intentar convertir alert_id_str a int
            flash("ID de alerta inválido.", 'error')
        except Exception as e:
            flash(f"Error procesando la solicitud: {e}", "error")
            print(f"ERROR alerts POST: {e}\n{traceback.format_exc()}")

        # Redirigir siempre después de procesar el POST para evitar reenvíos
        return redirect(redirect_url)

    # --- Solicitud GET (sin cambios) ---
    try:
        show_all = request.args.get('show_all', 'false').lower() == 'true'
        current_alerts = alert_manager.get_alerts(show_all) # Obtener alertas (activas o todas)
    except Exception as e:
        print(f"ERROR alerts GET: {e}\n{traceback.format_exc()}")
        flash("Error al obtener las alertas.", "error")
        current_alerts, show_all = [], False # Valores seguros en caso de error

    return render_template('alerts.html', alerts=current_alerts, show_all=show_all)

@app.route('/admin')
@login_required
def admin_landing():
    if not current_user.is_admin: flash("No tienes permisos.", "error"); return redirect(url_for('dashboard'))
    try: system_config = admin_manager.get_config(); alert_config = alert_manager.config; system_logs = admin_manager.get_system_logs()
    except Exception as e: print(f"ERROR admin GET: {e}\n{traceback.format_exc()}"); flash("Error cargar datos admin.", "error"); system_config, alert_config, system_logs = {}, {}, "Err logs."
    alert_severity_levels = ['Baja', 'Media', 'Alta', 'Crítica']
    return render_template('admin.html', system_config=system_config, alert_config=alert_config, alert_severity_levels=alert_severity_levels, system_logs=system_logs)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
# @admin_required  # Opcional: si solo los administradores pueden cambiar la configuración
def settings():
    print(f"DEBUG: Accediendo a ruta /settings con método {request.method}")

    global system_config, detector, alert_manager

    if request.method == 'POST':
        print("DEBUG: Procesando solicitud POST para /settings")
        try:
            # --- Actualizar configuración del sistema y del detector ---
            new_glm_threshold_str = request.form.get('glm_threshold')

            if new_glm_threshold_str:
                try:
                    new_glm_threshold = float(new_glm_threshold_str)
                    if 0.0 <= new_glm_threshold <= 1.0:
                        system_config['glm_threshold'] = new_glm_threshold
                        if 'detector' in globals() and detector is not None:
                            detector.prediction_threshold = new_glm_threshold
                            print(f"INFO: Umbral del detector actualizado a {new_glm_threshold}.")
                        else:
                            print("WARN: Instancia de detector no disponible para actualizar el umbral.")
                        flash(f"Umbral del modelo actualizado a {new_glm_threshold:.2f}.", "success")
                        print(f"INFO: Umbral del modelo actualizado a {new_glm_threshold}.")
                    else:
                        flash("Error: El umbral del modelo debe estar entre 0.0 y 1.0.", "warning")
                        print(f"WARN: Intento de actualizar umbral con valor fuera de rango: {new_glm_threshold}")
                except ValueError:
                    flash("Error: El umbral del modelo debe ser un número válido.", "warning")
                    print(f"WARN: Intento de actualizar umbral con valor no numérico: {new_glm_threshold_str}")

            # --- Actualizar configuración de alertas ---
            new_severity_threshold = request.form.get('severity_threshold')
            new_notify_email = request.form.get('notify_email') == 'on'

            if 'alert_manager' in globals() and alert_manager is not None:
                alert_manager.update_config(severity_threshold=new_severity_threshold, notify_email=new_notify_email)
                print("INFO: Configuración de alertas procesada.")
            else:
                print("WARN: Instancia de AlertManager no disponible para procesar configuración de alertas.")

            return redirect(url_for('settings'))

        except Exception as e:
            print(f"ERROR procesando solicitud POST para /settings: {e}\n{traceback.format_exc()}")
            flash("Error interno al guardar configuración.", "danger")
            return redirect(url_for('settings'))

    try:
        print("DEBUG: Procesando solicitud GET para /settings")
        current_glm_threshold = system_config.get('glm_threshold', 0.7)
        print(f"DEBUG: Umbral actual para vista GET: {current_glm_threshold}")

        current_severity_threshold = 'Media'
        current_notify_email = False

        if 'alert_manager' in globals() and alert_manager is not None:
            current_severity_threshold = alert_manager.config.get('severity_threshold', 'Media')
            current_notify_email = alert_manager.config.get('notify_email', False)
            print(f"DEBUG: Config alertas para vista GET: Severidad={current_severity_threshold}, Email={current_notify_email}")
        else:
            print("WARN: Instancia de AlertManager no disponible para obtener config de alertas en GET.")

        return render_template('settings.html',
                               title='Configuración',
                               glm_threshold=current_glm_threshold,
                               severity_threshold=current_severity_threshold,
                               notify_email=current_notify_email,
                               alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica']
                               )
    except Exception as e:
        print(f"ERROR preparando página de configuración GET: {e}\n{traceback.format_exc()}")
        flash("Error al cargar la página de configuración.", "danger")
        return render_template('settings.html',
                               title='Configuración',
                               glm_threshold=system_config.get('glm_threshold', 0.7),
                               severity_threshold='Media',
                               notify_email=False,
                               alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica']
                               )


@app.route('/admin/action', methods=['POST'])
@login_required
def admin_actions():
    if not current_user.is_admin: flash("Acción no autorizada.", "error"); return redirect(url_for('dashboard'))
    action = request.form.get('action')
    try:
        if action == 'update_threshold': new_threshold = float(request.form.get('glm_threshold')); success, message = admin_manager.update_glm_threshold(new_threshold); flash(message, 'success' if success else 'error')
        elif action == 'update_alert_config': severity = request.form.get('alert_severity_threshold'); notify = 'notify_email' in request.form; success = alert_manager.update_config(severity_threshold=severity, notify_email=notify); flash("Config. alertas actualizada.", "success") if success else flash("No se pudo actualizar.", "warning")
        elif action == 'retrain': retrain_msg = admin_manager.trigger_retraining(); flash(retrain_msg, 'info')
        elif action == 'go_to_user_list': return redirect(url_for('list_users')) # Asegúrate que este link exista en admin.html si lo necesitas
        else: flash(f"Acción admin '{action}' desconocida.", 'warning')
    except ValueError: flash("Valor numérico inválido.", 'error')
    except Exception as e: flash(f"Error acción admin: {e}", "error"); print(f"ERROR admin POST: {e}\n{traceback.format_exc()}")
    return redirect(url_for('admin_landing'))

@app.route('/admin/users')
@login_required
@admin_required 
def list_users():
    if not current_user.is_admin: flash("No tienes permisos.", "error"); return redirect(url_for('dashboard'))
    try: all_users = User.query.order_by(User.username).all()
    except Exception as e: print(f"Error obteniendo usuarios: {e}\n{traceback.format_exc()}"); flash("Error al cargar usuarios.", "error"); all_users = []
    return render_template('users_list.html', users=all_users)

@app.route('/users/manage') # Ruta placeholder usuarios
@login_required # Proteger también por si acaso
def manage_users_placeholder():
    # Quizás añadir chequeo de admin aquí también
    # if not current_user.is_admin: return redirect(url_for('dashboard'))
    flash("La gestión de usuarios aún no está implementada.", "info")
    return render_template('users_placeholder.html')


# --- RUTAS DE GESTIÓN DE USUARIOS (Admin) ---




@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required # Solo admins pueden crear usuarios
def create_user():
    """Página para crear un nuevo usuario (solo admin)."""
    form = UserAdminForm() # Usamos el formulario admin
    if form.validate_on_submit():
        try:
            # Verificar si el username o email ya existen (aunque el form ya lo hace, es una capa extra)
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                 flash('Nombre de usuario ya existe.', 'danger')
                 return render_template('user_form.html', title='Crear Usuario', form=form)

            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                 flash('Email ya registrado.', 'danger')
                 return render_template('user_form.html', title='Crear Usuario', form=form)

            new_user = User(username=form.username.data,
                            email=form.email.data,
                            is_admin=form.is_admin.data)
            # La contraseña es obligatoria al crear
            if form.password.data:
                 new_user.set_password(form.password.data)
            else:
                 flash("La contraseña es obligatoria para crear un nuevo usuario.", "danger")
                 return render_template('user_form.html', title='Crear Usuario', form=form) # Volver a mostrar el form

            db.session.add(new_user)
            db.session.commit()
            flash(f'Usuario "{new_user.username}" creado exitosamente.', 'success')
            print(f"INFO: Admin {current_user.username} creó usuario {new_user.username}.")
            return redirect(url_for('list_users')) # Redirigir a la lista
        except Exception as e:
            db.session.rollback() # Revertir cambios en caso de error
            flash(f'Error creando usuario: {e}', 'danger')
            print(f"ERROR creando usuario admin: {e}\n{traceback.format_exc()}")

    # Si es GET o el formulario no validó
    return render_template('user_form.html', title='Crear Usuario', form=form)


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required # Solo admins pueden editar usuarios
def edit_user(user_id):
    """Página para editar un usuario existente (solo admin)."""
    user = User.query.get_or_404(user_id) # Obtener el usuario por ID, o mostrar 404

    # Pre-llenar el formulario con los datos actuales del usuario para GET
    # Usamos el formulario base con los originales para la validación de unicidad
    form = UserAdminForm(original_username=user.username, original_email=user.email)

    if form.validate_on_submit():
        try:
            # Actualizar datos del usuario
            user.username = form.username.data
            user.email = form.email.data
            user.is_admin = form.is_admin.data

            # Solo cambiar la contraseña si se proporcionó una nueva
            if form.password.data:
                 user.set_password(form.password.data)
                 flash('Contraseña de usuario actualizada.', 'info') # Notificar que la contraseña fue cambiada

            db.session.commit()
            flash(f'Usuario "{user.username}" actualizado exitosamente.', 'success')
            print(f"INFO: Admin {current_user.username} editó usuario {user.username} (ID: {user.id}).")
            return redirect(url_for('list_users')) # Redirigir a la lista
        except Exception as e:
            db.session.rollback() # Revertir cambios
            flash(f'Error actualizando usuario: {e}', 'danger')
            print(f"ERROR editando usuario admin {user_id}: {e}\n{traceback.format_exc()}")

    # Si es GET, pre-llenar el formulario para mostrar
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.is_admin.data = user.is_admin
        # No pre-llenamos el campo de contraseña por seguridad

    # Renderizar la misma plantilla de formulario, pero para edición
    return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required # Solo admins pueden eliminar
def delete_user(user_id):
    """Ruta para eliminar un usuario (solo admin)."""
    user = User.query.get_or_404(user_id) # Obtener usuario a eliminar

    # Opcional: añadir una verificación para no permitir que un admin se elimine a sí mismo
    if user.id == current_user.id:
        flash("No puedes eliminar tu propia cuenta de administrador.", "danger")
        return redirect(url_for('list_users'))

    # Opcional: Puedes usar el formulario de confirmación si lo deseas, o simplemente procesar el POST
    # form = DeleteUserForm()
    # if form.validate_on_submit(): # Si usas un formulario con submit
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuario "{user.username}" eliminado exitosamente.', 'success')
        print(f"INFO: Admin {current_user.username} eliminó usuario {user.username} (ID: {user.id}).")
    except Exception as e:
        db.session.rollback() # Revertir cambios
        flash(f'Error eliminando usuario "{user.username}": {e}', 'danger')
        print(f"ERROR eliminando usuario admin {user_id}: {e}\n{traceback.format_exc()}")

    # Siempre redirigir a la lista de usuarios después de la operación
    return redirect(url_for('list_users'))

# --- Ejecución ---
if __name__ == '__main__':
    # Usar el contexto de la aplicación para operaciones de BD al inicio
    with app.app_context():
        print("INFO: Creando tablas BD si no existen...");
        time_start = datetime.datetime.now()
        # --- Bloque try/except externo para la conexión/creación inicial ---
        try:
            # Intentar crear todas las tablas definidas en los modelos
            db.create_all()
            print(f"INFO: Tablas verificadas/creadas ({(datetime.datetime.now() - time_start).total_seconds():.2f}s).")

            # Comprobar si ya existen usuarios para no intentar crear el admin de nuevo
            if User.query.count() == 0:
                print("INFO: No existen usuarios. Creando usuario admin inicial...")
                # --- Bloque try/except interno para la creación del admin ---
                try:
                    admin_user = User(username='admin', email='admin@example.com', is_admin=True)
                    admin_user.set_password('password') # ¡CAMBIAR ESTA CONTRASEÑA POR DEFECTO!
                    db.session.add(admin_user)
                    db.session.commit()
                    print("INFO: Usuario 'admin' creado / pass: 'password'. ¡POR FAVOR CAMBIARLA!")
                # Manejar error específico al crear el admin
                except Exception as e_admin:
                    db.session.rollback() # Revertir si falla la creación del admin
                    print(f"ERROR: No se pudo crear usuario admin inicial: {e_admin}")
                # --- Fin try/except interno ---

        # Manejar error general de conexión o creación de tablas
        except Exception as e_db:
            print(f"ERROR: No se pudo conectar o crear tablas en la BD: {e_db}")
            print("Verifica la configuración deSQLALCHEMY_DATABASE_URI y que el servidor MySQL esté corriendo.")
            exit() # Salir si no se puede inicializar la BD
        # --- Fin try/except externo ---

    # Iniciar el servidor Flask (fuera del with app.app_context() para la creación inicial)
    print("INFO: Iniciando servidor Flask...")
    # Cambiar debug=False para producción
    app.run(host='0.0.0.0', port=5000, debug=True)