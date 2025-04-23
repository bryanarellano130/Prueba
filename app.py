# -*- coding: utf-8 -*-
import os
import io
import base64
import pandas as pd
import numpy as np
import matplotlib
# Usar backend no interactivo ANTES de importar pyplot para evitar problemas en servidor
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import datetime
import traceback
import uuid
import json # Para manejar datos complejos en sesión o historial
import joblib # Necesario para cargar modelos/scalers joblib

# --- IMPORTACIONES PARA LOGIN Y BD ---
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange, Optional
# Usar bcrypt directamente es más seguro que depender solo de Werkzeug para hash
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# CORREGIDO: Importar url_parse de werkzeug.urls
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request, session, send_file, make_response

# --- IMPORTACIONES PARA REPORTES ---
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# --- IMPORTACIONES DE CLASES MANAGER (Asegúrate que estos archivos existan en la misma carpeta o PYTHONPATH) ---
# Asumo que estas clases tienen los métodos llamados en app.py
# Por ejemplo:
# DataManager: __init__(upload_folder), load_csv_data(filepath) # <--- CORREGIDO aquí el nombre esperado
# ThreatSimulator: __init__(temp_folder), run_simulation(...)
# ThreatDetector: __init__(model=None, scaler=None, threshold=...),
#                 detect_threats(filepath_or_df), is_model_loaded(), is_scaler_loaded(), get_config(), update_config(), get_model_info(), load_model(path), load_scaler(path)
# AlertManager: __init__(), generate_alerts(detection_results), get_recent_alerts(), get_all_alerts()
# AdminManager: __init__(detector_instance, model_folder), retrain_model()
try:
    from data_manager import DataManager
    from threat_simulator import ThreatSimulator
    from threat_detector import ThreatDetector
    from alert_manager import AlertManager
    from admin_manager import AdminManager # Asegúrate de que esta clase esté en admin_manager.py
except ImportError as e:
    # Imprime un error más detallado si falla la importación
    print(f"FATAL ERROR: No se pudo importar una clase manager: {e}")
    print("Asegúrate de que los archivos .py (data_manager.py, threat_simulator.py, etc.)")
    print("se encuentren en el mismo directorio que app.py o en el PYTHONPATH.")
    exit()

# --- DECORADOR PARA REQUERIR ROL DE ADMIN ---
from functools import wraps
print("DEBUG: Definiendo decorador admin_required...")
def admin_required(f):
    """
    Decorador para restringir el acceso a rutas solo a usuarios administradores.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Debes iniciar sesión para acceder a esta página.", "warning")
            return redirect(url_for('login', next=request.url))
        if not current_user.is_admin:
            flash("Acceso no autorizado. Esta sección es solo para administradores.", "danger")
            return redirect(url_for('dashboard')) # O a donde quieras redirigir a no-admins
        return f(*args, **kwargs)
    return decorated_function
print("DEBUG: Decorador admin_required definido.")

# --- Configuración de la Aplicación Flask ---
print("DEBUG: Creando instancia de Flask app...")
app = Flask(__name__)
print("DEBUG: Instancia Flask creada.")

# Clave secreta: MUY IMPORTANTE cambiarla en producción y guardarla de forma segura (ej. variable de entorno)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3_th1s")

# --- Configuración de Carpetas ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
TEMP_SIM_FOLDER = os.path.join(BASE_DIR, 'temp_sim_data')
MODEL_FOLDER = os.path.join(BASE_DIR, 'modelo') # Carpeta para modelos guardados
REPORT_FOLDER = os.path.join(BASE_DIR, 'reports') # Carpeta para guardar reportes generados
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['MODEL_FOLDER'] = MODEL_FOLDER # Usamos 'modelo'
app.config['REPORT_FOLDER'] = REPORT_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'csv'} # Solo permitir archivos CSV por ahora

# Asegurarse de que las carpetas existan
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_SIM_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True) # Crear carpeta 'modelo'
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
print(f"DEBUG: Carpetas configuradas y creadas si no existían.")

# --- CONFIGURACIÓN DE BASE DE DATOS (MySQL con XAMPP por defecto) ---
# ¡¡¡IMPORTANTE!!! Ajusta estos valores si tu configuración de MySQL es diferente.
# Especialmente DB_PASS si le pusiste contraseña a root en XAMPP.
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "") # Contraseña VACÍA por defecto en XAMPP
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "cyber_db") # Asegúrate que esta BD exista en tu MySQL

# Usar mysqlconnector (pip install mysql-connector-python)
db_uri = f'mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
print(f"DEBUG: Configurando URI de BD: mysql+mysqlconnector://{DB_USER}:******@{DB_HOST}/{DB_NAME}")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recomendado desactivar
app.config['SQLALCHEMY_ECHO'] = False # Poner True para ver las queries SQL (útil para debug)

# --- INICIALIZACIÓN DE EXTENSIONES ---
print("DEBUG: Inicializando SQLAlchemy...")
try:
    db = SQLAlchemy(app)
    print("DEBUG: SQLAlchemy inicializado.")
except Exception as e_sql:
    print(f"FATAL ERROR: Inicializando SQLAlchemy: {e_sql}")
    print("Verifica la cadena de conexión y que el servidor MySQL esté corriendo.")
    exit()

print("DEBUG: Inicializando LoginManager...")
try:
    login_manager = LoginManager(app)
    login_manager.login_view = 'login' # Ruta a la que redirigir si se necesita login
    login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
    login_manager.login_message_category = "info" # Categoría de mensaje flash
    print("DEBUG: Configuración LoginManager completa.")
except Exception as e_login:
    print(f"FATAL ERROR: Inicializando LoginManager: {e_login}")
    exit()

# --- Instancias Globales de los Managers ---
# (Se inicializan aquí para que estén disponibles en toda la app)
print("DEBUG: Inicializando Managers...")
try:
    data_manager = DataManager(upload_folder=app.config['UPLOAD_FOLDER'])

    # --- Carga del Modelo y Scaler ---
    # Rutas esperadas para los archivos guardados por data_model.py
    model_path = os.path.join(app.config['MODEL_FOLDER'], 'modelo_glm.joblib')
    scaler_path = os.path.join(app.config['MODEL_FOLDER'], 'scaler.joblib')

    # Intentar cargar el scaler y el modelo
    loaded_scaler = None
    loaded_model = None
    print(f"DEBUG: Intentando cargar scaler desde: {scaler_path}")
    if os.path.exists(scaler_path):
        try:
            loaded_scaler = joblib.load(scaler_path)
            print("INFO: Scaler cargado exitosamente.")
        except Exception as e:
            print(f"ERROR: No se pudo cargar el scaler desde '{scaler_path}': {e}")
            loaded_scaler = None # Asegurarse de que sea None si falla
    else:
        print(f"WARN: Archivo de scaler NO encontrado en '{scaler_path}'") # Cambiado a WARN

    print(f"DEBUG: Intentando cargar modelo desde: {model_path}")
    if os.path.exists(model_path):
        try:
            loaded_model = joblib.load(model_path)
            print("INFO: Modelo cargado exitosamente.")
        except Exception as e:
            print(f"ERROR: No se pudo cargar el modelo desde '{model_path}': {e}")
            loaded_model = None # Asegurarse de que sea None si falla
    else:
        print(f"WARN: Archivo de modelo NO encontrado en '{model_path}'") # Cambiado a WARN

    # Inicializar ThreatDetector pasando el modelo y scaler cargados (pueden ser None)
    # Asumo que ThreatDetector.__init__ maneja None para model y scaler
    detector = ThreatDetector(model=loaded_model, scaler=loaded_scaler)

    # Pasar instancia del detector y la carpeta del modelo al AdminManager
    admin_manager = AdminManager(detector_instance=detector, model_folder=app.config['MODEL_FOLDER'])

    # Otros managers
    simulator = ThreatSimulator(temp_folder=app.config['TEMP_SIM_FOLDER'])
    alert_manager = AlertManager() # Podría necesitar configuración de BD o archivo

    print("DEBUG: Managers inicializados.")
except Exception as e:
    print(f"FATAL ERROR inicializando manager: {e}\n{traceback.format_exc()}")
    exit()

# --- Almacenamiento Temporal de Resultados (Considerar mover a BD para persistencia) ---
# Usaremos la sesión de Flask para almacenar temporalmente info del último análisis
# session['last_analysis'] = {'data_info': {...}, 'detection_results': {...}, 'simulation_results': {...}}

# --- MODELO DE BASE DE DATOS (USUARIO) ---
print("DEBUG: Definiendo modelo User...")
class User(db.Model, UserMixin):
    __tablename__ = 'users' # Nombre explícito de la tabla
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True) # Index para búsquedas rápidas
    email = db.Column(db.String(120), unique=True, nullable=False, index=True) # Index para búsquedas rápidas
    # Aumentar longitud si usas algoritmos de hash más largos en el futuro
    # bcrypt genera hashes de 60 caracteres
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """Hashea la contraseña usando bcrypt y la guarda."""
        password_bytes = password.encode('utf-8')
        # gensalt() genera un salt único para cada contraseña
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')

    def check_password(self, password):
        """Verifica una contraseña contra el hash guardado."""
        if not self.password_hash:
            return False # No hay hash guardado
        try:
            password_bytes = password.encode('utf-8')
            stored_hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, stored_hash_bytes)
        except Exception as e:
            # Loggear el error es importante en producción
            print(f"ERROR verificando password para user {self.id}: {e}")
            return False # Ser cauto y devolver False si hay error

    def __repr__(self):
        # Representación útil para debugging
        return f'<User id={self.id} username={self.username} email={self.email} admin={self.is_admin}>'
print("DEBUG: Modelo User definido.")

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """Función requerida por Flask-Login para cargar un usuario desde la sesión."""
    try:
        # Intenta obtener el usuario por ID. Retorna None si no existe.
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Error en user_loader para user_id {user_id}: {e}")
        return None # Importante retornar None si hay error o no se encuentra

# --- FORMULARIOS (Flask-WTF) ---
print("DEBUG: Definiendo Formularios...")
class LoginForm(FlaskForm):
    """Formulario de inicio de sesión."""
    username = StringField('Usuario', validators=[DataRequired("El nombre de usuario es obligatorio."), Length(min=3, max=80)])
    password = PasswordField('Contraseña', validators=[DataRequired("La contraseña es obligatoria.")])
    remember_me = BooleanField('Recuérdame')
    submit = SubmitField('Iniciar Sesión')

class RegistrationForm(FlaskForm):
    """Formulario de registro de nuevos usuarios."""
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email("Introduce una dirección de email válida.")])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6, message="La contraseña debe tener al menos 6 caracteres.")])
    confirm_password = PasswordField('Confirmar Contraseña',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message='Las contraseñas no coinciden.')])
    submit = SubmitField('Registrarse')

    # Validadores personalizados para asegurar unicidad
    def validate_username(self, username):
        """Verifica si el nombre de usuario ya existe."""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nombre de usuario ya está en uso. Por favor, elige otro.')

    def validate_email(self, email):
        """Verifica si el email ya está registrado."""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este email ya está registrado. Por favor, usa otro.')

class UserAdminForm(FlaskForm):
    """Formulario para Crear y Editar usuarios desde el panel Admin."""
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # La contraseña es opcional al editar, solo necesaria para crear o cambiar
    # Usar Optional() para que no sea requerido si está vacío
    password = PasswordField('Contraseña (dejar vacío para no cambiar)', validators=[Optional(), Length(min=6)])
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')

    # Guardamos el usuario original para comparar en validaciones
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(UserAdminForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        # Solo validar si el username ha cambiado O si es un usuario nuevo (original_username es None)
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Este nombre de usuario ya está en uso.')

    def validate_email(self, email):
        # Solo validar si el email ha cambiado O si es un usuario nuevo (original_email es None)
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Este email ya está registrado.')

class DeleteUserForm(FlaskForm):
    """Formulario simple para confirmar la eliminación de un usuario."""
    submit = SubmitField('Confirmar Eliminación')

# --- Formularios para Simulación y Configuración ---
class SimulationForm(FlaskForm):
    """Formulario para configurar la simulación de ataques."""
    attack_type = SelectField('Tipo de Ataque', choices=[ # Añade aquí los tipos de ataque que soporta tu simulador
        ('DoS', 'Denegación de Servicio (DoS)'),
        ('PortScan', 'Escaneo de Puertos'),
        ('BruteForce', 'Fuerza Bruta (SSH/FTP)'),
        # ... otros tipos ...
    ], validators=[DataRequired()])
    target_ip = StringField('IP Objetivo (Opcional)', validators=[Optional()]) # O hacerlo requerido si siempre se necesita
    duration = IntegerField('Duración (segundos)', default=60, validators=[DataRequired(), NumberRange(min=10, max=3600)])
    intensity = SelectField('Intensidad', choices=[('low', 'Baja'), ('medium', 'Media'), ('high', 'Alta')], default='medium')
    submit = SubmitField('Iniciar Simulación')

class ModelConfigForm(FlaskForm):
    """Formulario para configurar parámetros del modelo (ej. umbral)."""
    # Ajusta los parámetros según lo que tu ThreatDetector permita configurar
    detection_threshold = FloatField('Umbral de Detección', default=0.5, validators=[DataRequired(), NumberRange(min=0.0, max=1.0)])
    # Podrías añadir más campos aquí si el modelo tiene otros hiperparámetros ajustables en tiempo real
    submit = SubmitField('Actualizar Configuración')
print("DEBUG: Formularios definidos.")

# --- Funciones Auxiliares ---
def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_plot_base64(plot_function, *args, **kwargs):
    """
    Ejecuta una función de ploteo de matplotlib y devuelve la imagen como string base64.
    La función de ploteo debe aceptar 'fig' como argumento.
    """
    img = io.BytesIO()
    fig = None # Para asegurar que cerramos la figura
    try:
        # Crear figura con tamaño personalizable
        fig = plt.figure(figsize=kwargs.pop('figsize', (6, 4))) # Tamaño por defecto
        # Llamar a la función que dibuja en la figura
        plot_function(fig=fig, *args, **kwargs)
        # Guardar la figura en el buffer de memoria
        plt.savefig(img, format='png', bbox_inches='tight') # bbox_inches='tight' ajusta el padding
        img.seek(0) # Rebobinar el buffer
        # Codificar en base64 y decodificar a utf8 para string HTML
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        return f"data:image/png;base64,{plot_url}"
    except Exception as e:
        print(f"Error generando gráfico: {e}\n{traceback.format_exc()}")
        return None # Retornar None si falla la generación
    finally:
        # Asegurar que la figura se cierra siempre para liberar memoria
        if fig:
            plt.close(fig)

def plot_confusion_matrix_func(fig, cm, classes, title='Matriz de Confusión'):
    """Dibuja una matriz de confusión en una figura matplotlib dada."""
    try:
        ax = fig.add_subplot(111) # Añadir ejes a la figura
        cm_array = np.array(cm) # Asegurar que es un array numpy
        sns.heatmap(cm_array, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=True, # Mostrar barra de color
                    xticklabels=classes, yticklabels=classes, annot_kws={"size": 12}) # Ajustar tamaño de números
        ax.set_xlabel('Etiqueta Predicha', fontsize=12)
        ax.set_ylabel('Etiqueta Verdadera', fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')
        plt.xticks(rotation=45, ha='right') # Rotar etiquetas eje X si son largas
        plt.yticks(rotation=0)
        plt.tight_layout() # Ajustar layout
    except Exception as e:
        print(f"Error en plot_confusion_matrix_func: {e}\n{traceback.format_exc()}")
        # Opcional: Añadir texto de error a la figura si falla
        fig.text(0.5, 0.5, f'Error al generar matriz:\n{e}', ha='center', va='center', color='red')

def plot_feature_distribution_func(fig, df, feature_name):
    """Dibuja la distribución de una característica (feature) en una figura."""
    try:
        ax = fig.add_subplot(111)
        if pd.api.types.is_numeric_dtype(df[feature_name]):
            sns.histplot(df[feature_name], kde=True, ax=ax)
            ax.set_title(f'Distribución de {feature_name}', fontsize=14, fontweight='bold')
        else: # Asumir categórica/objeto
            # Limitar número de categorías a mostrar si son muchas
            top_categories = df[feature_name].value_counts().nlargest(15).index
            sns.countplot(y=feature_name, data=df, order=top_categories, ax=ax, palette='viridis')
            ax.set_title(f'Conteo de {feature_name} (Top 15)', fontsize=14, fontweight='bold')
        ax.set_xlabel('Valor' if pd.api.types.is_numeric_dtype(df[feature_name]) else 'Conteo', fontsize=12)
        ax.set_ylabel(feature_name, fontsize=12)
        plt.tight_layout()
    except KeyError:
        print(f"Error: La característica '{feature_name}' no existe en el DataFrame.")
        fig.text(0.5, 0.5, f"Error: Característica\n'{feature_name}'\nno encontrada.", ha='center', va='center', color='red')
    except Exception as e:
        print(f"Error en plot_feature_distribution_func para {feature_name}: {e}\n{traceback.format_exc()}")
        fig.text(0.5, 0.5, f'Error al generar gráfico\npara {feature_name}:\n{e}', ha='center', va='center', color='red')

# --- Funciones para Generar Reportes ---
def generate_detection_report_pdf(report_data, output_filename):
    """Genera un reporte PDF con los resultados de la detección."""
    doc = SimpleDocTemplate(output_filename, pagesize=landscape(letter)) # Usar landscape para más espacio
    styles = getSampleStyleSheet()
    story = []

    # --- Título ---
    title = "Reporte de Detección de Amenazas"
    story.append(Paragraph(title, styles['h1']))
    story.append(Spacer(1, 0.2*inch))

    # --- Información General ---
    story.append(Paragraph("Información General", styles['h2']))
    info_data = [
        ['Timestamp:', report_data.get('timestamp', 'N/A')],
        ['Fuente de Datos:', report_data.get('source_info', 'N/A')],
        ['Filas Analizadas:', str(report_data.get('rows_analyzed', 'N/A'))],
        ['Modelo Utilizado:', report_data.get('model_info', 'N/A')],
        ['Umbral de Detección:', str(report_data.get('model_threshold', 'N/A'))]
    ]
    info_table = Table(info_data, colWidths=[1.5*inch, 6*inch])
    info_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'), # Columna de etiquetas en negrita
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.2*inch))

    # --- Resumen de Detecciones ---
    summary = report_data.get('detection_summary', {})
    if summary:
        story.append(Paragraph("Resumen de Detecciones", styles['h2']))
        summary_data = [['Etiqueta', 'Cantidad']]
        for label, count in summary.items():
            summary_data.append([label, str(count)])

        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey), # Encabezado gris
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'), # Encabezado en negrita
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige), # Filas de datos con fondo
            ('GRID', (0,0), (-1,-1), 1, colors.black) # Rejilla
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))

    # --- Métricas de Evaluación ---
    metrics = report_data.get('metrics', {})
    if metrics:
        story.append(Paragraph("Métricas de Evaluación del Modelo", styles['h2']))
        metrics_data = [['Métrica', 'Valor']]
        # Añadir métricas principales si existen
        for m_name in ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']:
            if m_name in metrics:
                # Formatear a 4 decimales si es float
                value = metrics[m_name]
                metrics_data.append([m_name.replace('_', ' ').title(), f"{value:.4f}" if isinstance(value, float) else str(value)])

        metrics_table = Table(metrics_data, colWidths=[2*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 0.1*inch))

        # --- Matriz de Confusión (si existe y es un plot base64) ---
        cm_plot_b64 = metrics.get('confusion_matrix_plot')
        if cm_plot_b64 and cm_plot_b64.startswith('data:image/png;base64,'):
            try:
                cm_img_data = base64.b64decode(cm_plot_b64.split(',')[1])
                cm_img = Image(io.BytesIO(cm_img_data), width=4*inch, height=3*inch) # Ajustar tamaño según necesidad
                story.append(cm_img)
                story.append(Spacer(1, 0.2*inch))
            except Exception as e_img:
                print(f"Error al añadir imagen de matriz de confusión al PDF: {e_img}")
                story.append(Paragraph(f"Error al mostrar Matriz de Confusión: {e_img}", styles['Italic']))

        # --- Reporte de Clasificación (si existe) ---
        class_report = metrics.get('report', {})
        if class_report and isinstance(class_report, dict):
            story.append(Paragraph("Reporte de Clasificación Detallado", styles['h3']))
             # Convertir el dict a formato tabla para ReportLab
             # Asume que las claves son nombres de clases y los valores son dicts de métricas
            report_list = [['Clase', 'Precision', 'Recall', 'F1-Score', 'Support']]
            for class_name, class_metrics in class_report.items():
                 if isinstance(class_metrics, dict): # Asegurar que es un dict
                      # Formatear métricas a 3 decimales
                      p = f"{class_metrics.get('precision', 'N/A'):.3f}" if isinstance(class_metrics.get('precision'), float) else str(class_metrics.get('precision', 'N/A'))
                      r = f"{class_metrics.get('recall', 'N/A'):.3f}" if isinstance(class_metrics.get('recall'), float) else str(class_metrics.get('recall', 'N/A'))
                      f1 = f"{class_metrics.get('f1-score', 'N/A'):.3f}" if isinstance(class_metrics.get('f1-score'), float) else str(class_metrics.get('f1-score', 'N/A'))
                      s = str(class_metrics.get('support', 'N/A'))
                      report_list.append([class_name, p, r, f1, s])

            report_table = Table(report_list, colWidths=[1.5*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch])
            report_table.setStyle(TableStyle([
                 ('BACKGROUND', (0,0), (-1,0), colors.teal),
                 ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                 ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                 ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                 ('BOTTOMPADDING', (0,0), (-1,0), 10),
                 ('GRID', (0,0), (-1,-1), 1, colors.black)
            ]))
            story.append(report_table)
            story.append(Spacer(1, 0.2*inch))

    # --- Vista Previa de Datos (Primeras filas con predicción) ---
    data_head = report_data.get('data_head', [])
    if data_head:
        story.append(PageBreak()) # Nueva página para la tabla de datos
        story.append(Paragraph("Vista Previa de Datos Detectados (Primeras Filas)", styles['h2']))
        # Convertir lista de dicts a lista de listas para ReportLab Table
        if isinstance(data_head, list) and len(data_head) > 0 and isinstance(data_head[0], dict):
            headers = list(data_head[0].keys())
            data_list = [headers] + [[str(row.get(h, '')) for h in headers] for row in data_head]

            # Ajustar anchos de columna (esto es aproximado, puede requerir ajuste)
            num_cols = len(headers)
            available_width = 9.5 * inch # Ancho aprox en landscape letter menos márgenes
            col_width = available_width / num_cols
            col_widths = [col_width] * num_cols

            data_table = Table(data_list, colWidths=col_widths)
            data_table.setStyle(TableStyle([
                 ('BACKGROUND', (0,0), (-1,0), colors.darkgrey),
                 ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                 ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                 ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                 ('FONTSIZE', (0,0), (-1,-1), 8), # Tamaño de fuente más pequeño para tablas grandes
                 ('BOTTOMPADDING', (0,0), (-1,0), 8),
                 ('TOPPADDING', (0,1), (-1,-1), 4),
                 ('BOTTOMPADDING', (0,1), (-1,-1), 4),
                 ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey)
            ]))
            story.append(data_table)
        else:
             story.append(Paragraph("Formato de datos de vista previa no válido.", styles['Italic']))

    # --- Construir el PDF ---
    try:
        doc.build(story)
        print(f"Reporte PDF generado: {output_filename}")
        return True
    except Exception as e:
        print(f"Error al construir el PDF: {e}\n{traceback.format_exc()}")
        return False

def generate_detection_report_csv(report_data):
    """Genera el contenido CSV para los resultados de la detección."""
    if not report_data: return None
    output = io.StringIO()

    # Escribir metadatos
    output.write(f"Reporte de Detección de Amenazas\n")
    output.write(f"Timestamp,{report_data.get('timestamp', 'N/A')}\n")
    output.write(f"Fuente de Datos,{report_data.get('source_info', 'N/A')}\n")
    output.write(f"Filas Analizadas,{report_data.get('rows_analyzed', 'N/A')}\n")
    output.write(f"Modelo Utilizado,{report_data.get('model_info', 'N/A')}\n")
    output.write(f"Umbral de Detección,{report_data.get('model_threshold', 'N/A')}\n\n")

    # Escribir resumen
    summary = report_data.get('detection_summary', {})
    if summary:
        output.write("Resumen de Detecciones\n")
        output.write("Etiqueta,Cantidad\n")
        for label, count in summary.items():
            output.write(f"{label},{count}\n")
        output.write("\n")

    # Escribir métricas
    metrics = report_data.get('metrics', {})
    if metrics:
        output.write("Métricas de Evaluación\n")
        output.write("Métrica,Valor\n")
        for m_name in ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']:
             if m_name in metrics:
                 value = metrics[m_name]
                 output.write(f"{m_name.replace('_', ' ').title()},{value:.4f}" if isinstance(value, float) else f"{m_name.replace('_', ' ').title()},{value}\n")

        # Reporte de clasificación si existe
        class_report = metrics.get('report', {})
        if class_report and isinstance(class_report, dict):
             output.write("\nReporte de Clasificación Detallado\n")
             try:
                 # Usar Pandas para convertir el dict a CSV fácilmente
                 report_df = pd.DataFrame(class_report).transpose()
                 report_df.index.name = 'Clase' # Nombrar la columna del índice
                 report_df.to_csv(output, mode='a', header=True, index=True) # mode='a' para añadir al StringIO
             except Exception as e_rep:
                 output.write(f"Error al formatear reporte de clasificación,{e_rep}\n")
        output.write("\n")

    # Escribir vista previa de datos
    data_head = report_data.get('data_head', [])
    if data_head:
        output.write("Vista Previa de Datos Detectados (Primeras Filas)\n")
        if isinstance(data_head, list) and len(data_head) > 0 and isinstance(data_head[0], dict):
            try:
                df_head = pd.DataFrame(data_head)
                df_head.to_csv(output, mode='a', header=True, index=False) # Añadir al StringIO sin índice de pandas
            except Exception as e_data:
                output.write(f"Error al formatear vista previa de datos,{e_data}\n")
        else:
             output.write("Formato de datos de vista previa no válido.\n")

    output.seek(0) # Rebobinar para leer desde el principio
    return output.getvalue() # Devolver como string

# --- Context Processor (Variables globales para plantillas Jinja2) ---
@app.context_processor
def inject_global_vars():
    """Injecta variables globales en el contexto de las plantillas."""
    return {
        'current_year': datetime.datetime.now().year,
        'app_name': "Sistema de Detección de Amenazas", # Nombre de tu aplicación
        'is_admin': current_user.is_authenticated and current_user.is_admin # Flag para mostrar/ocultar elementos de admin
    }

# --- Filtro Jinja2 para Fechas ---
@app.template_filter('format_datetime')
def format_datetime_filter(dt_obj, format='%Y-%m-%d %H:%M:%S'):
    """Formatea un objeto datetime en Jinja2. Maneja None."""
    if isinstance(dt_obj, datetime.datetime):
        return dt_obj.strftime(format)
    elif isinstance(dt_obj, str): # Intentar parsear si es string ISO
        try:
            # Usar parse para manejar diferentes formatos ISO, o fromisoformat si sabes que es exacto
            dt_obj_parsed = datetime.datetime.fromisoformat(dt_obj)
            return dt_obj_parsed.strftime(format)
        except (ValueError, TypeError):
             # Si no es ISO, intenta otros formatos comunes o devuelve original
             try:
                 # Ejemplo: intentar formato con zona horaria Z
                 dt_obj_parsed = datetime.datetime.strptime(dt_obj, '%Y-%m-%dT%H:%M:%S.%fZ')
                 return dt_obj_parsed.strftime(format)
             except (ValueError, TypeError):
                 return dt_obj # Devolver string original si no se puede parsear
    return "N/A" # Devolver N/A si es None u otro tipo

# --- RUTAS DE FLASK ---
print("DEBUG: Definiendo rutas Flask...")

# --- Rutas de Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Maneja el inicio de sesión del usuario."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Si ya está logueado, ir al dashboard

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            # Actualizar last_login
            user.last_login = datetime.datetime.utcnow()
            try:
                db.session.commit()
            except Exception as e_commit:
                db.session.rollback()
                print(f"Error al actualizar last_login para {user.username}: {e_commit}")
                # No es crítico, continuar con el login

            flash(f'Inicio de sesión exitoso. ¡Bienvenido, {user.username}!', 'success')
            # Redirección segura
            next_page = request.args.get('next')
            # CORREGIDO: Usar url_parse importado
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('dashboard') # Redirigir al dashboard por defecto
            return redirect(next_page)
        else:
            flash('Credenciales inválidas. Por favor, verifica tu usuario y contraseña.', 'danger')
    return render_template('login.html', title='Iniciar Sesión', form=form)

@app.route('/logout')
@login_required # Solo usuarios logueados pueden desloguearse
def logout():
    """Cierra la sesión del usuario."""
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    session.clear() # Limpiar toda la sesión al cerrar sesión
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Maneja el registro de nuevos usuarios."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # No permitir registro si ya está logueado

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            new_user = User(username=form.username.data, email=form.email.data)
            new_user.set_password(form.password.data) # Hashear contraseña

            # El primer usuario registrado será administrador
            if User.query.count() == 0:
                new_user.is_admin = True
                print(f"INFO: Registrando primer usuario '{new_user.username}' como administrador.")

            db.session.add(new_user)
            db.session.commit()
            flash(f'¡Cuenta creada exitosamente para {new_user.username}! Ahora puedes iniciar sesión.', 'success')
            # Loguear automáticamente al nuevo usuario (opcional)
            # login_user(new_user)
            # return redirect(url_for('dashboard'))
            return redirect(url_for('login')) # Redirigir a login tras registro exitoso
        except Exception as e:
            db.session.rollback() # Revertir cambios en caso de error
            print(f"Error durante el registro: {e}\n{traceback.format_exc()}")
            flash('Ocurrió un error durante el registro. Por favor, inténtalo de nuevo.', 'danger')
    return render_template('register.html', title='Registrarse', form=form)

# --- Rutas Principales de la Aplicación ---
@app.route('/')
@app.route('/dashboard')
@login_required # Requiere que el usuario esté logueado
def dashboard():
    """Página principal (Dashboard) después de iniciar sesión."""
    # Recuperar datos de la última sesión si existen
    last_analysis = session.get('last_analysis', {})
    data_info = last_analysis.get('data_info')
    detection_results = last_analysis.get('detection_results')
    simulation_results = last_analysis.get('simulation_results')

    # Obtener alertas recientes
    recent_alerts = alert_manager.get_recent_alerts(limit=5) # Asume que AlertManager tiene este método

    # Preparar datos para la plantilla
    context = {
        'title': 'Dashboard',
        'data_info': data_info,
        'detection_results': detection_results,
        'simulation_results': simulation_results,
        'recent_alerts': recent_alerts,
        'model_loaded': detector.is_model_loaded() if hasattr(detector, 'is_model_loaded') else False, # Verificar método
        'scaler_loaded': detector.is_scaler_loaded() if hasattr(detector, 'is_scaler_loaded') else False # Verificar método
    }
    return render_template('dashboard.html', **context)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_data():
    """Maneja la carga de archivos CSV para análisis."""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No se seleccionó ningún archivo.', 'warning')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo.', 'warning')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Usar secure_filename para evitar nombres de archivo maliciosos
            filename = secure_filename(file.filename)
            # Crear un nombre de archivo único para evitar sobreescrituras (opcional pero recomendado)
            # unique_id = uuid.uuid4().hex
            # unique_filename = f"{os.path.splitext(filename)[0]}_{unique_id}{os.path.splitext(filename)[1]}"
            # filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename) # Versión simple

            try:
                file.save(filepath)
                flash(f'Archivo "{filename}" cargado exitosamente.', 'success')

                # Procesar el archivo usando DataManager
                # CORREGIDO: Llamar a load_csv_data
                # Asume que load_csv_data devuelve un resumen o None/Exception en error
                print(f"DEBUG: Llamando a data_manager.load_csv_data con filepath: {filepath}")
                data_summary = data_manager.load_csv_data(filepath)

                if data_summary and isinstance(data_summary, dict):
                     # Asegurarse de que el filepath se guarda en el resumen
                     if 'filepath' not in data_summary:
                         data_summary['filepath'] = filepath
                     if 'filename' not in data_summary:
                         data_summary['filename'] = filename

                     # Guardar información del archivo cargado en la sesión
                     # Limpiar resultados previos antes de guardar los nuevos
                     session['last_analysis'] = {'data_info': data_summary}
                     session.modified = True # Marcar sesión como modificada
                     print(f"DEBUG: Data summary guardado en sesión: {data_summary}")
                     flash('Archivo procesado. Información básica disponible.', 'info')
                     # Redirigir al dashboard o a una página de visualización/detección
                     return redirect(url_for('view_data'))
                else:
                    # Si data_manager.load_csv_data devuelve None o False en error
                    print(f"ERROR: data_manager.load_csv_data devolvió: {data_summary}")
                    flash(f'Error al procesar el archivo "{filename}" con DataManager. Verifique el formato del CSV y los logs.', 'danger')
                    # Opcional: eliminar archivo si falla el procesamiento inicial
                    if os.path.exists(filepath):
                       try:
                           os.remove(filepath)
                           print(f"DEBUG: Archivo {filepath} eliminado por fallo en procesamiento.")
                       except OSError as e_rm:
                           print(f"WARN: No se pudo eliminar {filepath} tras fallo: {e_rm}")
                    # Limpiar info de sesión si falla
                    session.pop('last_analysis', None)


            except Exception as e:
                flash(f'Error crítico al guardar o procesar el archivo: {e}', 'danger')
                print(f"Error en upload_data: {e}\n{traceback.format_exc()}")
                # Limpiar info de sesión si falla
                session.pop('last_analysis', None)
                # Redirigir de vuelta a upload en caso de error POST
                return redirect(request.url) # Redirige a la misma página (upload)

        else:
            flash('Tipo de archivo no permitido. Solo se aceptan archivos .csv', 'warning')
            return redirect(request.url)

    # Método GET: Mostrar el formulario de carga
    # Considerar si limpiar el análisis previo aquí es deseado
    # session.pop('last_analysis', None) # Quitado para permitir ver resultados previos si se navega de vuelta
    return render_template('upload.html', title='Cargar Datos')


@app.route('/view_data')
@login_required
def view_data():
    """Muestra información y visualizaciones básicas del último archivo cargado."""
    last_analysis = session.get('last_analysis', {})
    data_info = last_analysis.get('data_info')

    if not data_info or 'dataframe_head' not in data_info: # Revisar la clave exacta que guarda DataManager
        flash('No hay datos cargados o información de cabecera disponible para visualizar. Por favor, carga un archivo CSV primero.', 'warning')
        return redirect(url_for('upload_data'))

    # Convertir la representación de 'dataframe_head' (lista de dicts) de nuevo a DataFrame para plots
    try:
        # Asegurarse de que 'dataframe_head' existe y es una lista
        df_head_list = data_info.get('dataframe_head', [])
        if not isinstance(df_head_list, list):
             raise ValueError("Formato de 'dataframe_head' no es una lista.")
        if not df_head_list:
             print("WARN: 'dataframe_head' está vacío en data_info.")
             df_head = pd.DataFrame() # Crear DataFrame vacío
        else:
             df_head = pd.DataFrame(df_head_list)

    except Exception as e:
        flash(f"Error al reconstruir DataFrame para visualización: {e}", "danger")
        print(f"Error reconstruyendo df_head: {e}")
        df_head = pd.DataFrame() # Crear DataFrame vacío si falla

    # Generar gráficos (ejemplo: distribución de una característica numérica y una categórica)
    plots = {}
    if not df_head.empty:
        # Intentar encontrar una columna numérica y una categórica para ejemplo
        numeric_cols = df_head.select_dtypes(include=np.number).columns
        category_cols = df_head.select_dtypes(include='object').columns

        if len(numeric_cols) > 0:
            num_feature = numeric_cols[0] # Tomar la primera numérica
            try:
                plots['numeric_dist'] = generate_plot_base64(plot_feature_distribution_func, df=df_head, feature_name=num_feature)
            except Exception as e_plot_num:
                 print(f"Error generando plot numérico para {num_feature}: {e_plot_num}")
        else:
             print("WARN: No se encontraron columnas numéricas en df_head para graficar.")


        if len(category_cols) > 0:
            cat_feature = category_cols[0] # Tomar la primera categórica
            try:
                plots['category_dist'] = generate_plot_base64(plot_feature_distribution_func, df=df_head, feature_name=cat_feature)
            except Exception as e_plot_cat:
                 print(f"Error generando plot categórico para {cat_feature}: {e_plot_cat}")
        else:
            print("WARN: No se encontraron columnas categóricas en df_head para graficar.")


    context = {
        'title': 'Visualización de Datos Cargados',
        'data_info': data_info,
        'plots': plots
    }
    return render_template('view_data.html', **context)


@app.route('/detect', methods=['GET', 'POST']) # Permitir POST si hay configuración futura
@login_required
def detect_threats_route():
    """Ejecuta la detección de amenazas sobre los datos cargados."""
    last_analysis = session.get('last_analysis', {})
    data_info = last_analysis.get('data_info')

    if not data_info or 'filepath' not in data_info:
        flash('No hay datos cargados para analizar. Por favor, carga un archivo CSV primero.', 'warning')
        print("DEBUG detect_threats_route: No data_info or filepath found in session.")
        return redirect(url_for('upload_data'))

    filepath = data_info['filepath']
    filename = data_info.get('filename', os.path.basename(filepath)) # Obtener nombre original

    # ANTES de verificar modelo/scaler, verificar si el archivo existe
    if not os.path.exists(filepath):
         flash(f'El archivo de datos "{filename}" no se encuentra en el servidor ({filepath}). Por favor, vuelve a cargarlo.', 'danger')
         session.pop('last_analysis', None) # Limpiar info de sesión si el archivo no existe
         print(f"DEBUG detect_threats_route: Filepath not found: {filepath}")
         return redirect(url_for('upload_data'))

    # Verificar si el modelo Y el scaler están cargados
    model_is_loaded = detector.is_model_loaded() if hasattr(detector, 'is_model_loaded') else False
    scaler_is_loaded = detector.is_scaler_loaded() if hasattr(detector, 'is_scaler_loaded') else False
    print(f"DEBUG detect_threats_route: Check - Model Loaded: {model_is_loaded}, Scaler Loaded: {scaler_is_loaded}")

    if not (model_is_loaded and scaler_is_loaded):
         msg = 'El modelo de detección y/o el scaler no están cargados. No se pueden realizar predicciones.'
         print(f"ERROR detect_threats_route: {msg}")
         flash(msg, 'danger')
         # Redirigir al admin_model_config para ver el estado o re-entrenar si es admin
         if current_user.is_authenticated and current_user.is_admin:
             return redirect(url_for('admin_model_config'))
         else:
             # Para usuarios no admin, redirigir al dashboard con el mensaje
             return redirect(url_for('dashboard'))

    # Si todo está listo, proceder con la detección
    try:
        print(f"DEBUG: Iniciando detección en archivo: {filepath}")
        # Asume que detect_threats devuelve un diccionario con resultados
        # Podría necesitar el DataFrame o la ruta al archivo
        detection_results = detector.detect_threats(filepath_or_df=filepath)

        if detection_results and isinstance(detection_results, dict):
            flash('Detección de amenazas completada.', 'success')

            # --- Generar Gráfico de Matriz de Confusión si está disponible ---
            metrics = detection_results.get('metrics', {})
            cm = metrics.get('confusion_matrix')
            labels = metrics.get('labels', ['BENIGN', 'ATTACK']) # Obtener etiquetas si están en las métricas

            if cm is not None:
                 try:
                     # Asegurarse que cm es una lista de listas o numpy array 2x2
                     if isinstance(cm, np.ndarray) and cm.shape == (2, 2):
                         cm_list = cm.tolist() # Convertir a lista para JSON
                     elif isinstance(cm, list) and len(cm) == 2 and all(isinstance(row, list) and len(row) == 2 for row in cm):
                         cm_list = cm
                     else:
                         print(f"WARN: Formato de matriz de confusión no esperado: {type(cm)}. No se generará gráfico.")
                         cm_list = None

                     if cm_list:
                         plot_base64 = generate_plot_base64(
                             plot_confusion_matrix_func,
                             cm=cm_list,
                             classes=labels,
                             figsize=(5,4) # Tamaño más pequeño para el dashboard
                         )
                         if plot_base64:
                              metrics['confusion_matrix_plot'] = plot_base64
                              # Guardar la matriz como lista en los resultados también (si no estaba ya)
                              metrics['confusion_matrix_data'] = cm_list
                              print("DEBUG: Gráfico de matriz de confusión generado.")
                         else:
                              print("ERROR: Falló la generación del gráfico de matriz de confusión (generate_plot_base64 devolvió None).")

                 except Exception as e_cm_plot:
                     print(f"Error generando gráfico de matriz de confusión: {e_cm_plot}\n{traceback.format_exc()}")


            # Actualizar la sesión con los resultados de detección
            # Mantener data_info, añadir/actualizar detection_results
            last_analysis['detection_results'] = detection_results
            session['last_analysis'] = last_analysis
            session.modified = True
            print("DEBUG: Resultados de detección guardados en sesión.")

            # Opcional: Añadir al historial (considerar persistencia en BD)
            # detection_history.append(detection_results)

            # Opcional: Generar alertas basadas en resultados
            alerts = alert_manager.generate_alerts(detection_results) # Asume que AlertManager tiene este método
            if alerts:
                flash(f"Se generaron {len(alerts)} alertas nuevas.", "warning")
                # Podrías guardar las alertas en BD o mostrarlas

            return redirect(url_for('view_detection_results')) # Redirigir a la vista de resultados
        else:
            flash('La detección de amenazas no produjo resultados válidos o falló.', 'warning')
            print(f"WARN detect_threats_route: detector.detect_threats devolvió: {detection_results}")
            # Limpiar resultados de detección si falló
            if 'detection_results' in last_analysis: del last_analysis['detection_results']
            session['last_analysis'] = last_analysis
            session.modified = True
            return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'Error durante la detección de amenazas: {e}', 'danger')
        print(f"Error en detect_threats_route: {e}\n{traceback.format_exc()}")
        # Limpiar resultados de detección si falló
        if 'detection_results' in last_analysis: del last_analysis['detection_results']
        session['last_analysis'] = last_analysis
        session.modified = True
        return redirect(url_for('dashboard'))


@app.route('/view_detection_results')
@login_required
def view_detection_results():
    """Muestra los resultados detallados de la última detección."""
    last_analysis = session.get('last_analysis', {})
    detection_results = last_analysis.get('detection_results')

    if not detection_results:
        flash('No hay resultados de detección disponibles. Por favor, ejecuta la detección primero.', 'warning')
        # Decidir si redirigir a upload o detect
        if 'data_info' in last_analysis:
            return redirect(url_for('detect_threats_route')) # Si hay datos, intentar detectar
        else:
            return redirect(url_for('upload_data')) # Si no hay datos, ir a cargar

    context = {
        'title': 'Resultados de Detección',
        'results': detection_results
    }
    return render_template('results.html', **context)


@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate_threats_route():
    """Configura e inicia la simulación de amenazas."""
    form = SimulationForm()

    if form.validate_on_submit():
        try:
            attack_type = form.attack_type.data
            target_ip = form.target_ip.data
            duration = form.duration.data
            intensity = form.intensity.data
            print(f"DEBUG: Iniciando simulación: Tipo={attack_type}, Target={target_ip}, Dur={duration}, Int={intensity}")

            # Asume que run_simulation devuelve un dict con resultados o None/Exception
            simulation_results = simulator.run_simulation(
                attack_type=attack_type,
                target=target_ip,
                duration=duration,
                intensity=intensity
            )

            if simulation_results and isinstance(simulation_results, dict):
                flash(f'Simulación de ataque "{attack_type}" completada.', 'success')
                # Guardar resultados en sesión
                last_analysis = session.get('last_analysis', {})
                last_analysis['simulation_results'] = simulation_results
                session['last_analysis'] = last_analysis
                session.modified = True
                print("DEBUG: Resultados de simulación guardados en sesión.")

                # Opcional: Analizar los datos simulados con el detector
                sim_data_path = simulation_results.get('output_filepath')
                if sim_data_path and os.path.exists(sim_data_path):
                     flash('Analizando datos generados por la simulación...', 'info')
                     # Actualizar data_info en sesión para que la detección use el archivo simulado
                     # Crear un resumen básico del archivo simulado
                     sim_data_info = {
                         'filepath': sim_data_path,
                         'filename': os.path.basename(sim_data_path),
                         'source': 'Simulation',
                         'rows': simulation_results.get('rows_generated', 'N/A'), # Asumiendo que el simulador lo devuelve
                         # Podrías añadir más info si el simulador la provee
                         # 'dataframe_head': [...] # Podrías leer las primeras líneas si es necesario
                     }
                     last_analysis['data_info'] = sim_data_info
                     # Limpiar resultados de detección anteriores si los hubiera
                     if 'detection_results' in last_analysis:
                         del last_analysis['detection_results']
                     session['last_analysis'] = last_analysis
                     session.modified = True
                     print(f"DEBUG: Data_info actualizado con datos de simulación: {sim_data_info}")
                     return redirect(url_for('detect_threats_route')) # Ir a detectar sobre los datos simulados
                else:
                     print("WARN: Simulación completada pero no se encontró archivo de salida o no se reportó.")
                     return redirect(url_for('dashboard')) # Volver al dashboard si no hay datos para analizar
            else:
                flash('La simulación no produjo resultados válidos o falló.', 'warning')
                print(f"WARN simulate_threats_route: simulator.run_simulation devolvió: {simulation_results}")
                return redirect(request.url) # Recargar página de simulación
        except Exception as e:
            flash(f'Error durante la simulación: {e}', 'danger')
            print(f"Error en simulate_threats_route: {e}\n{traceback.format_exc()}")
            return redirect(request.url) # Recargar página de simulación

    # Método GET: Mostrar formulario de simulación
    # CORREGIDO: Pasar simulation_results=None para evitar UndefinedError en plantilla
    last_analysis = session.get('last_analysis', {})
    current_simulation_results = last_analysis.get('simulation_results') # Mostrar resultados si existen en sesión
    # Limpiar resultados de simulación previos si se recarga el form? Depende del flujo deseado.
    # if 'simulation_results' in last_analysis: del last_analysis['simulation_results']
    # session['last_analysis'] = last_analysis
    # session.modified = True

    return render_template('simulate.html',
                           title='Simular Amenazas',
                           form=form,
                           simulation_results=current_simulation_results) # Pasar None o resultados existentes


@app.route('/alerts')
@login_required
def view_alerts():
    """Muestra el historial de alertas."""
    # Asume que AlertManager tiene un método para obtener todas las alertas (o paginadas)
    all_alerts = alert_manager.get_all_alerts()
    context = {
        'title': 'Historial de Alertas',
        'alerts': all_alerts
    }
    return render_template('alerts.html', **context)

# --- Rutas de Administración ---
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Redirige al panel principal de administración (ej. usuarios)."""
    return redirect(url_for('admin_users'))


@app.route('/admin/users')
@login_required
@admin_required # Solo admins
def admin_users():
    """Página de administración de usuarios."""
    try:
        # Usar directamente User.query es más simple aquí
        users = User.query.order_by(User.username).all()
        delete_form = DeleteUserForm() # Formulario para el botón de eliminar en cada fila
    except Exception as e:
        flash(f"Error al obtener la lista de usuarios: {e}", "danger")
        users = []
        delete_form = None # No mostrar botones de borrar si falla la carga
        print(f"Error en admin_users: {e}\n{traceback.format_exc()}")
    return render_template('admin_users.html', title='Administrar Usuarios', users=users, delete_form=delete_form)


@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_new_user():
    """Crea un nuevo usuario desde el panel de administración."""
    form = UserAdminForm() # Usar el mismo form para crear/editar

    if form.validate_on_submit():
        try:
            # La contraseña es requerida al crear
            if not form.password.data:
                 # Añadir error al campo de contraseña en el formulario
                 form.password.errors.append("La contraseña es obligatoria al crear un usuario.")
                 # Renderizar de nuevo con el error
                 return render_template('admin_edit_user.html', title='Crear Nuevo Usuario', form=form, user=None)

            # Crear instancia User
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                is_admin=form.is_admin.data
            )
            new_user.set_password(form.password.data) # Hashear contraseña

            db.session.add(new_user)
            db.session.commit()
            flash(f'Usuario "{new_user.username}" creado exitosamente.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el usuario: {e}', 'danger')
            print(f"Error en admin_new_user: {e}\n{traceback.format_exc()}")
            # Renderizar de nuevo el formulario en caso de error de BD u otro
            return render_template('admin_edit_user.html', title='Crear Nuevo Usuario', form=form, user=None)

    # Método GET o si el form no es válido
    return render_template('admin_edit_user.html', title='Crear Nuevo Usuario', form=form, user=None) # Pasar user=None para indicar creación


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    """Edita un usuario existente."""
    user = User.query.get_or_404(user_id) # Obtener usuario o 404 si no existe
    # Pasar el username/email originales al form para validación correcta
    form = UserAdminForm(original_username=user.username, original_email=user.email, obj=user) # Cargar datos del usuario en el form

    if form.validate_on_submit():
        try:
            # Actualizar datos del usuario desde el form
            user.username = form.username.data
            user.email = form.email.data
            user.is_admin = form.is_admin.data
            # Actualizar contraseña SOLO si se proporcionó una nueva
            if form.password.data:
                user.set_password(form.password.data)

            db.session.commit()
            flash(f'Usuario "{user.username}" actualizado exitosamente.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar el usuario: {e}', 'danger')
            print(f"Error en admin_edit_user (ID: {user_id}): {e}\n{traceback.format_exc()}")
            # Renderizar de nuevo el form con los datos actuales (antes del error)
            return render_template('admin_edit_user.html', title=f'Editar Usuario: {user.username}', form=form, user=user)

    # Método GET: Mostrar formulario con datos cargados (WTForms-Alchemy lo hace con obj=user)
    return render_template('admin_edit_user.html', title=f'Editar Usuario: {user.username}', form=form, user=user)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST']) # Solo POST para eliminar
@login_required
@admin_required
def admin_delete_user(user_id):
    """Elimina un usuario."""
    # Evitar que el admin se elimine a sí mismo
    if current_user.id == user_id:
        flash('No puedes eliminar tu propia cuenta de administrador.', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    # Usar un formulario de confirmación (aunque aquí se valida directamente)
    form = DeleteUserForm() # Crear instancia para validación CSRF si está habilitada

    if form.validate_on_submit(): # Valida el token CSRF
        try:
            username = user.username # Guardar nombre para mensaje flash
            db.session.delete(user)
            db.session.commit()
            flash(f'Usuario "{username}" eliminado exitosamente.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al eliminar el usuario: {e}', 'danger')
            print(f"Error en admin_delete_user (ID: {user_id}): {e}\n{traceback.format_exc()}")
    else:
        # Si falla la validación CSRF (si está activa)
        flash('Error de validación al intentar eliminar el usuario. Intenta de nuevo.', 'danger')

    return redirect(url_for('admin_users'))


@app.route('/admin/model', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_model_config():
    """Página para configurar y re-entrenar el modelo."""
    config_form = ModelConfigForm()
    current_config = {} # Inicializar como dict vacío

    # Cargar configuración actual del detector si existe un método para ello
    try:
         if hasattr(detector, 'get_config'):
              current_config = detector.get_config()
              if not isinstance(current_config, dict): # Asegurar que sea un dict
                   print(f"WARN: detector.get_config() no devolvió un dict, sino {type(current_config)}. Usando dict vacío.")
                   current_config = {}
         else:
              print("WARN: ThreatDetector no tiene el método get_config().")
    except Exception as e_get_cfg:
         print(f"Error llamando a detector.get_config(): {e_get_cfg}")
         # Mantener current_config como dict vacío

    if config_form.validate_on_submit():
        try:
            new_threshold = config_form.detection_threshold.data
            # Asume que el detector tiene un método para actualizar su config
            if hasattr(detector, 'update_config'):
                 # Pasar un diccionario con la configuración a actualizar
                 update_success = detector.update_config({'detection_threshold': new_threshold})
                 if update_success: # Asumiendo que update_config devuelve True/False
                     flash(f'Umbral de detección actualizado a {new_threshold}.', 'success')
                     # Volver a obtener la config actualizada para mostrarla
                     if hasattr(detector, 'get_config'):
                          current_config = detector.get_config()
                          if not isinstance(current_config, dict): current_config = {}
                 else:
                     flash('Falló la actualización de la configuración en ThreatDetector.', 'warning')
            else:
                 flash('Funcionalidad para actualizar configuración no implementada en ThreatDetector.', 'warning')

        except Exception as e_update_cfg:
            flash(f'Error al actualizar la configuración del modelo: {e_update_cfg}', 'danger')
            print(f"Error en admin_model_config (POST - update_config): {e_update_cfg}\n{traceback.format_exc()}")

        # Redirigir a la misma página (GET) después de procesar POST para evitar reenvío de form
        return redirect(url_for('admin_model_config'))

    # Método GET o si el form no es válido: Llenar el form con valores actuales
    # Usar .get() con default por si la clave no existe en current_config
    config_form.detection_threshold.data = current_config.get('detection_threshold', 0.5)

    # Obtener información adicional del detector
    model_loaded = detector.is_model_loaded() if hasattr(detector, 'is_model_loaded') else False
    scaler_loaded = detector.is_scaler_loaded() if hasattr(detector, 'is_scaler_loaded') else False
    model_info = "N/A"
    try:
        if hasattr(detector, 'get_model_info'):
            model_info = detector.get_model_info()
        else:
             print("WARN: ThreatDetector no tiene el método get_model_info().")
    except Exception as e_get_info:
        print(f"Error llamando a detector.get_model_info(): {e_get_info}")


    context = {
        'title': 'Configuración del Modelo',
        'config_form': config_form,
        'current_config': current_config,
        'model_loaded': model_loaded,
        'scaler_loaded': scaler_loaded, # Mostrar estado del scaler también
        'model_info': model_info # Info del modelo cargado
    }
    return render_template('admin_model.html', **context)


@app.route('/admin/retrain', methods=['POST']) # Solo POST para iniciar acción
@login_required
@admin_required
def admin_retrain_model():
    """Inicia el proceso de re-entrenamiento del modelo."""
    print("DEBUG: Solicitud de re-entrenamiento recibida.")
    try:
        # Asume que AdminManager tiene un método para iniciar el re-entrenamiento
        # Este proceso debería ser ASÍNCRONO en una aplicación real (ej. con Celery)
        # Aquí se llama de forma síncrona como placeholder
        if not hasattr(admin_manager, 'retrain_model'):
             flash("Funcionalidad de re-entrenamiento no implementada en AdminManager.", 'danger')
             return redirect(url_for('admin_model_config'))

        print("DEBUG: Llamando a admin_manager.retrain_model()...")
        result = admin_manager.retrain_model() # Podría necesitar parámetros (ej. dataset a usar)
        print(f"DEBUG: admin_manager.retrain_model() devolvió: {result}")

        if result and isinstance(result, dict) and result.get('success'):
            flash(f"Re-entrenamiento iniciado/completado. {result.get('message', '')}", 'success')

            # Forzar la recarga del modelo Y scaler en el detector después de reentrenar
            new_model_path = result.get('new_model_path')
            new_scaler_path = result.get('new_scaler_path') # Asumo que retrain_model devuelve la ruta del nuevo scaler también

            reloaded_model = False
            reloaded_scaler = False

            # Intentar cargar el NUEVO modelo si se especificó ruta
            if new_model_path and os.path.exists(new_model_path):
                 if hasattr(detector, 'load_model'):
                     try:
                         detector.load_model(new_model_path)
                         flash(f"Nuevo modelo cargado en el detector desde: {os.path.basename(new_model_path)}.", "info")
                         reloaded_model = True
                     except Exception as e_load_m:
                          flash(f"Error al cargar el nuevo modelo: {e_load_m}", "danger")
                          print(f"Error en detector.load_model({new_model_path}): {e_load_m}")
                 else:
                     flash("Detector no tiene método load_model. Reinicia la aplicación para usar el nuevo modelo.", "warning")
            # Si no hay ruta nueva O falló, intentar recargar el modelo por defecto (si el método lo permite)
            elif hasattr(detector, 'load_model') and not reloaded_model:
                 try:
                     detector.load_model() # Asume que load_model sin args recarga el configurado por defecto
                     flash("Intentando recargar modelo por defecto en el detector.", "info")
                     reloaded_model = True
                 except Exception as e_load_def_m:
                     flash(f"Error al recargar modelo por defecto: {e_load_def_m}", "warning")
                     print(f"Error en detector.load_model() por defecto: {e_load_def_m}")


            # Intentar cargar el NUEVO scaler si se especificó ruta
            if new_scaler_path and os.path.exists(new_scaler_path):
                 if hasattr(detector, 'load_scaler'):
                     try:
                         detector.load_scaler(new_scaler_path)
                         flash(f"Nuevo scaler cargado en el detector desde: {os.path.basename(new_scaler_path)}.", "info")
                         reloaded_scaler = True
                     except Exception as e_load_s:
                          flash(f"Error al cargar el nuevo scaler: {e_load_s}", "danger")
                          print(f"Error en detector.load_scaler({new_scaler_path}): {e_load_s}")
                 else:
                     flash("Detector no tiene método load_scaler. Reinicia la aplicación para usar el nuevo scaler.", "warning")
             # Si no hay ruta nueva O falló, intentar recargar el scaler por defecto (si el método lo permite)
            elif hasattr(detector, 'load_scaler') and not reloaded_scaler:
                 try:
                     detector.load_scaler() # Asume que load_scaler sin args recarga el configurado por defecto
                     flash("Intentando recargar scaler por defecto en el detector.", "info")
                     reloaded_scaler = True
                 except Exception as e_load_def_s:
                      flash(f"Error al recargar scaler por defecto: {e_load_def_s}", "warning")
                      print(f"Error en detector.load_scaler() por defecto: {e_load_def_s}")


            if not reloaded_model or not reloaded_scaler:
                 flash("Advertencia: No se pudieron cargar/recargar correctamente el modelo y/o scaler después del re-entrenamiento. Puede ser necesario reiniciar la aplicación.", "warning")

        else:
            error_msg = result.get('message', 'Error desconocido') if isinstance(result, dict) else str(result)
            flash(f"Falló el re-entrenamiento: {error_msg}", 'danger')
            print(f"ERROR: Re-entrenamiento fallido. Mensaje: {error_msg}")

    except Exception as e:
        flash(f'Error crítico al intentar re-entrenar: {e}', 'danger')
        print(f"Error CRITICO en admin_retrain_model: {e}\n{traceback.format_exc()}")

    return redirect(url_for('admin_model_config'))


# --- Rutas para Descargar Reportes ---
@app.route('/download_report/<report_format>')
@login_required
def download_report(report_format):
    """Genera y descarga el reporte de la última detección en PDF o CSV."""
    last_analysis = session.get('last_analysis', {})
    detection_results = last_analysis.get('detection_results')

    if not detection_results:
        flash('No hay resultados de detección para generar un reporte.', 'warning')
        return redirect(url_for('dashboard')) # O view_detection_results si prefieres

    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Usar nombre de archivo original si está disponible, sino genérico
    source_filename = last_analysis.get('data_info', {}).get('filename', 'data')
    safe_source_filename = secure_filename(source_filename).replace('.csv', '') # Limpiar nombre
    base_filename = f"detection_report_{safe_source_filename}_{timestamp_str}"

    if report_format == 'pdf':
        pdf_filename_full = os.path.join(app.config['REPORT_FOLDER'], f"{base_filename}.pdf")
        print(f"DEBUG: Generando reporte PDF en: {pdf_filename_full}")
        success = generate_detection_report_pdf(detection_results, pdf_filename_full)
        if success:
            try:
                # Enviar archivo para descarga
                return send_file(pdf_filename_full,
                                 as_attachment=True,
                                 download_name=f"{base_filename}.pdf", # Nombre que verá el usuario
                                 mimetype='application/pdf')
            except Exception as e_send:
                 flash(f"Error al enviar el archivo PDF: {e_send}", "danger")
                 print(f"Error enviando PDF {pdf_filename_full}: {e_send}")
                 return redirect(url_for('view_detection_results'))
            # finally:
                 # Opcional: eliminar archivo después de enviar? O dejarlo en /reports
                 # if os.path.exists(pdf_filename_full): os.remove(pdf_filename_full)
                 # pass # Dejar el archivo en /reports por defecto
        else:
            flash('Error al generar el reporte PDF.', 'danger')
            return redirect(url_for('view_detection_results'))

    elif report_format == 'csv':
        print(f"DEBUG: Generando contenido de reporte CSV...")
        csv_content = generate_detection_report_csv(detection_results)
        if csv_content:
            # Crear respuesta CSV
            response = make_response(csv_content)
            response.headers['Content-Disposition'] = f'attachment; filename={base_filename}.csv'
            response.headers['Content-Type'] = 'text/csv; charset=utf-8' # Especificar charset
            print(f"DEBUG: Enviando reporte CSV: {base_filename}.csv")
            return response
        else:
            flash('Error al generar el reporte CSV.', 'danger')
            return redirect(url_for('view_detection_results'))

    else:
        flash('Formato de reporte no válido. Use "pdf" o "csv".', 'danger')
        return redirect(url_for('view_detection_results'))


# --- Manejadores de Errores HTTP ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html', title='Página no Encontrada'), 404

@app.errorhandler(500)
def internal_error(error):
    # Revertir sesión de BD por si acaso hubo un error a mitad de una transacción
    try:
        db.session.rollback()
    except Exception as e_rollback:
        print(f"WARN: Error durante rollback en errorhandler 500: {e_rollback}")

    # Loggear el error completo
    print(f"INTERNAL SERVER ERROR: {error}\n{traceback.format_exc()}")
    return render_template('errors/500.html', title='Error Interno del Servidor'), 500

@app.errorhandler(403)
def forbidden_error(error):
    # Error común si admin_required falla
    return render_template('errors/403.html', title='Acceso Prohibido'), 403

@app.errorhandler(401)
def unauthorized_error(error):
     # Para errores 401 (no autorizado) que no maneja Flask-Login, redirigir a login
     flash("Debes iniciar sesión para acceder a esta página.", "warning")
     return redirect(url_for('login', next=request.url))


# --- Inicialización y Ejecución ---
if __name__ == '__main__':
    # Crear tablas de la BD si no existen y el usuario admin inicial
    # Usar app.app_context() para asegurar que las operaciones de BD tienen el contexto de la app
    with app.app_context():
        print("DEBUG: Entrando en app_context para inicializar BD...")
        try:
            # Crear todas las tablas definidas en los modelos (ej. User)
            db.create_all()
            print("INFO: Tablas de la base de datos verificadas/creadas.")

            # Crear usuario admin inicial si no existe ninguno
            if User.query.count() == 0:
                print("INFO: No existen usuarios. Creando usuario admin inicial...")
                try:
                    # ¡¡¡CAMBIAR ESTA CONTRASEÑA POR DEFECTO INMEDIATAMENTE!!!
                    admin_password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "password")
                    admin_user = User(username='admin', email='admin@example.com', is_admin=True)
                    admin_user.set_password(admin_password)
                    db.session.add(admin_user)
                    db.session.commit()
                    print(f"INFO: Usuario 'admin' creado con contraseña por defecto ('{admin_password}'). ¡POR FAVOR CAMBIARLA!")
                except Exception as e_admin:
                    db.session.rollback() # Revertir si falla la creación del admin
                    print(f"ERROR: No se pudo crear usuario admin inicial: {e_admin}")
                    print(traceback.format_exc())
            else:
                 print("INFO: Ya existen usuarios en la base de datos.")

        except Exception as e_db:
            print(f"ERROR CRÍTICO: No se pudo conectar o inicializar la base de datos: {e_db}")
            print("Verifica la configuración deSQLALCHEMY_DATABASE_URI, que el servidor MySQL/MariaDB")
            print("esté corriendo, y que la base de datos especificada ('cyber_db') exista.")
            print(traceback.format_exc())
            exit() # Salir si no se puede inicializar la BD

        print("DEBUG: Saliendo de app_context.")

    # Iniciar el servidor Flask
    # host='0.0.0.0' permite conexiones desde otras máquinas en la red
    # debug=True es útil para desarrollo (recarga automática, debugger), ¡DESACTIVAR en producción!
    print("INFO: Iniciando servidor Flask...")
    # Obtener puerto de variable de entorno o usar 5000 por defecto
    port = int(os.environ.get("PORT", 5000))
    # debug=True generalmente no se recomienda para producción directamente
    # Se puede controlar con una variable de entorno
    debug_mode = os.environ.get("FLASK_DEBUG", "True").lower() in ['true', '1', 't']
    print(f"INFO: Ejecutando en http://0.0.0.0:{port}/ | Modo Debug: {debug_mode}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)