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
import uuid # Para generar nombres de archivo únicos

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename

# Importa tus clases
try:
    from data_manager import DataManager
    from threat_simulator import ThreatSimulator
    from threat_detector import ThreatDetector
    from alert_manager import AlertManager
    from admin_manager import AdminManager
except ImportError as e:
    print(f"FATAL ERROR: No se pudo importar una clase de módulo: {e}")
    print("Asegúrate de que los archivos .py (data_manager.py, threat_simulator.py, etc.) existan en el mismo directorio que app.py y no tengan errores.")
    exit() # Salir si las importaciones básicas fallan

# --- Configuración de la App ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3") # Cambiar para producción

# Carpetas
UPLOAD_FOLDER = 'uploads'
TEMP_SIM_FOLDER = 'temp_sim_data' # Carpeta para simulaciones temporales
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER # Guardar en config
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

# Asegurar que las carpetas existan
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_SIM_FOLDER'], exist_ok=True) # Crear carpeta temporal

# --- Instancias Globales ---
try:
    data_manager = DataManager()
    simulator = ThreatSimulator()
    alert_manager = AlertManager()
    model_file_path = None # Poner ruta real si tienes modelo
    detector = ThreatDetector(model_path=model_file_path)
    admin_manager = AdminManager(detector_instance=detector)
except Exception as e:
    print(f"FATAL ERROR: No se pudo inicializar una clase manager: {e}")
    print(traceback.format_exc())
    exit()

# Almacenamiento simple en memoria para historial (se pierde al reiniciar)
detection_history = []

# --- Context Processor ---
@app.context_processor
def inject_current_year():
    """Hace que 'current_year' esté disponible en todas las plantillas."""
    return {'current_year': datetime.datetime.now().year}

# --- Filtro Jinja2 para Fechas ---
@app.template_filter('format_datetime')
def format_datetime_filter(iso_string, format='%Y-%m-%d %H:%M:%S'):
    """Filtro Jinja2: Formatea un string ISO de fecha/hora."""
    if not iso_string: return "N/A"
    try:
        dt = datetime.datetime.fromisoformat(iso_string)
        return dt.strftime(format)
    except: return iso_string

# --- Helper para Gráficos ---
def generate_plot_base64(plot_function, *args, **kwargs):
    """Ejecuta una función de ploteo y devuelve la imagen como base64."""
    img = io.BytesIO()
    fig = None
    try:
        fig = plt.figure(figsize=kwargs.pop('figsize', (5, 4)))
        plot_function(fig=fig, *args, **kwargs)
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        return f"data:image/png;base64,{plot_url}"
    except Exception as e:
        print(f"Error generando gráfico: {e}\n{traceback.format_exc()}")
        return None
    finally:
        if fig: plt.close(fig)

def plot_confusion_matrix_func(cm_data, labels=['BENIGN', 'ATTACK'], fig=None):
    """Dibuja la matriz de confusión en una figura matplotlib existente."""
    if cm_data is None or fig is None: return
    try:
        cm_array = np.array(cm_data)
        ax = fig.subplots()
        sns.heatmap(cm_array, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels, ax=ax, cbar=False)
        ax.set_ylabel('Valor Real'); ax.set_xlabel('Predicción')
        fig.tight_layout()
    except Exception as e:
        print(f"Error dibujando matriz de confusión: {e}\n{traceback.format_exc()}")

# --- Helper para Archivos ---
def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Rutas de Flask ---

@app.route('/')
def dashboard():
    """Muestra el panel principal."""
    try:
        active_alerts = [a for a in alert_manager.alerts if not a.get('reviewed')]
        last_detection_entry = detection_history[-1] if detection_history else None
        model_status = "Operacional (Real)" if detector.model else "Operacional (Simulado)"
        all_alerts_sorted = alert_manager.get_alerts(show_all=True)
        recent_alerts = all_alerts_sorted[:5]
    except Exception as e:
        print(f"ERROR en ruta dashboard: {e}\n{traceback.format_exc()}"); flash("Error crítico cargando dashboard.", "error")
        active_alerts, last_detection_entry, model_status, recent_alerts = [], None, "Error", []
    return render_template('dashboard.html', active_alerts_count=len(active_alerts), last_detection=last_detection_entry, model_status=model_status, recent_alerts=recent_alerts)

@app.route('/data', methods=['GET', 'POST'])
def manage_data():
    """Gestiona la carga y preprocesamiento de datos CSV."""
    if request.method == 'POST':
        action = request.form.get('action'); redirect_url = url_for('manage_data')
        try:
            if action == 'upload':
                if 'file' not in request.files: flash('No se encontró archivo.', 'error'); return redirect(redirect_url)
                file = request.files['file']; filename = file.filename
                if filename == '': flash('No se seleccionó archivo.', 'warning'); return redirect(redirect_url)
                if file and allowed_file(filename):
                    filename = secure_filename(filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename); file.save(filepath)
                    success, message = data_manager.load_csv_data(filepath)
                    if success: flash(message, 'success'); session['loaded_filepath'] = filepath; session.pop('processed_data_info', None)
                    else: flash(message, 'error'); session.pop('loaded_filepath', None)
                elif file: flash(f"Tipo archivo no permitido. Solo: {', '.join(app.config['ALLOWED_EXTENSIONS'])}", 'error')
            elif action == 'preprocess':
                if data_manager.loaded_data is not None:
                    success, message = data_manager.preprocess_data()
                    if success:
                        flash(message, 'success')
                        session['processed_data_info'] = {'rows': len(data_manager.processed_data), 'cols': len(data_manager.processed_data.columns), 'timestamp': datetime.datetime.now().isoformat(timespec='seconds')}
                    else: flash(message, 'error'); session.pop('processed_data_info', None)
                else: flash('Primero carga archivo CSV.', 'warning')
            else: flash('Acción desconocida.', 'warning')
        except Exception as e: flash(f"Error inesperado: {e}", "error"); print(f"ERROR manage_data POST: {e}\n{traceback.format_exc()}")
        return redirect(redirect_url)
    # GET Request
    try:
        loaded_head_html = data_manager.get_loaded_data_head_html()
        processed_head_html = data_manager.get_processed_data_head_html()
        processed_info = session.get('processed_data_info')
        loaded_filepath = session.get('loaded_filepath')
        loaded_filename = os.path.basename(loaded_filepath) if loaded_filepath and os.path.exists(loaded_filepath) else None
    except Exception as e: print(f"ERROR manage_data GET: {e}\n{traceback.format_exc()}"); flash("Error vistas previas.", "error"); loaded_head_html, processed_head_html, processed_info, loaded_filename = "<p>Err</p>", "<p>Err</p>", None, None
    return render_template('data_management.html', loaded_head_html=loaded_head_html, processed_head_html=processed_head_html, loaded_filename=loaded_filename, processed_info=processed_info)

@app.route('/simulate', methods=['GET', 'POST'])
def simulate():
    """Maneja la configuración y ejecución de simulaciones."""
    if request.method == 'POST':
        try:
            duration = int(request.form.get('duration', '60')); intensity = int(request.form.get('intensity', '5'))
            attacks_list = request.form.getlist('attacks')
            if duration <= 0: raise ValueError("Duración debe ser > 0")
            if not (1 <= intensity <= 10): raise ValueError("Intensidad 1-10")
            attacks = [a.strip() for a in attacks_list if a.strip()] or ['Attack']
            config = {"duration": duration, "intensity": intensity, "attacks": attacks}
            print(f"INFO: Solicitud simulación: {config}")
            sim_result_df = simulator.run_simulation(config)
            if sim_result_df is not None and not sim_result_df.empty:
                sim_id = str(uuid.uuid4()); temp_filename = f"sim_data_{sim_id}.pkl"
                temp_filepath = os.path.join(app.config['TEMP_SIM_FOLDER'], temp_filename)
                try:
                    sim_result_df.to_pickle(temp_filepath); print(f"INFO: Simulación guardada: {temp_filepath}")
                    session.pop('last_simulation_data', None)
                    session['simulation_ran'] = True; session['last_simulation_filepath'] = temp_filepath
                    session['simulation_info'] = {'rows_generated': len(sim_result_df), 'config': config, 'timestamp': datetime.datetime.now().isoformat(timespec='seconds'), 'filepath': temp_filepath}
                    flash(f'Simulación completada ({len(sim_result_df)} registros).', 'success')
                except Exception as e_save: flash(f"Error guardando simulación: {e_save}", "error"); print(f"ERROR guardando pickle: {e_save}\n{traceback.format_exc()}"); session.clear()
            else: flash('Simulación no generó datos.', 'warning'); session.pop('simulation_ran', None); session.pop('last_simulation_filepath', None); session.pop('simulation_info', None)
        except ValueError as ve: flash(f'Entrada inválida: {ve}', 'error')
        except Exception as e: flash(f'Error inesperado simulación: {e}', 'error'); print(f"ERROR simulate POST: {e}\n{traceback.format_exc()}"); session.pop('simulation_ran', None); session.pop('last_simulation_filepath', None); session.pop('simulation_info', None)
        return redirect(url_for('simulate'))
    # GET Request
    try: last_sim_info = session.get('simulation_info'); last_sim_preview_df = None; sim_history = simulator.get_history()
    except Exception as e: print(f"ERROR simulate GET: {e}\n{traceback.format_exc()}"); flash("Error cargando datos simulación.", "error"); last_sim_info, last_sim_preview_df, sim_history = None, None, []
    return render_template('simulator.html', simulation_history=sim_history, last_simulation_info=last_sim_info, last_simulation_preview_df=last_sim_preview_df)

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    """Maneja la selección de datos y ejecución de la detección."""
    if request.method == 'POST':
        source = request.form.get('datasource'); df_to_detect = None; data_info = "Ninguna"; sim_filepath_used = None
        try:
            if source == 'processed':
                df_processed = data_manager.get_processed_data()
                if df_processed is not None and not df_processed.empty: df_to_detect = df_processed; data_info = f"Datos preprocesados ({len(df_to_detect)} filas)"
                else: flash("No hay datos preprocesados disponibles.", "warning")
            elif source == 'simulation':
                sim_filepath = session.get('last_simulation_filepath')
                if sim_filepath and os.path.exists(sim_filepath):
                    try:
                        print(f"INFO: Cargando simulación desde {sim_filepath}"); sim_df = pd.read_pickle(sim_filepath); sim_filepath_used = sim_filepath
                        print(f"INFO: Datos cargados ({len(sim_df)} filas). Preprocesando..."); temp_dm = DataManager(); temp_dm.loaded_data = sim_df
                        success_preprocess, msg_preprocess = temp_dm.preprocess_data()
                        if success_preprocess:
                            df_to_detect = temp_dm.get_processed_data()
                            if df_to_detect is None or df_to_detect.empty: flash("Preproc. simulación resultó 0 filas.", "warning"); df_to_detect = None
                            else: data_info = f"Datos simulación preproc. ({len(df_to_detect)} filas)"
                        else: flash(f"Error preproc. simulación: {msg_preprocess}", "error")
                    except Exception as e_load: flash(f"Error al cargar archivo simulación: {e_load}", "error"); print(f"ERROR cargando pickle: {e_load}\n{traceback.format_exc()}")
                else: flash("Archivo simulación no encontrado. Ejecuta simulación.", "warning")
            else: flash("Fuente de datos no válida.", "warning")

            if df_to_detect is not None and not df_to_detect.empty:
                print(f"INFO: Iniciando detección: {data_info}..."); detection_output = detector.run_detection(df_to_detect)
                if detection_output:
                    max_rows_head = 100; detection_data_df = detection_output.get('data')
                    if isinstance(detection_data_df, pd.DataFrame): data_head_records = detection_data_df.head(max_rows_head).to_dict('records'); detection_summary_dict = detection_data_df['prediction_label'].value_counts().to_dict()
                    else: data_head_records, detection_summary_dict = [], {'Error': 'No data'}
                    detection_timestamp = datetime.datetime.now().isoformat(timespec='seconds')
                    results_for_session_and_history = { 'metrics': detection_output.get('metrics', {}), 'data_head': data_head_records, 'timestamp': detection_timestamp, 'source_info': data_info, 'rows_analyzed': len(df_to_detect), 'detection_summary': detection_summary_dict, 'model_threshold': detector.threshold }
                    session['last_detection_results'] = results_for_session_and_history

                    # Generar alertas y flashes
                    new_alerts_count, new_alerts_list = alert_manager.generate_alerts(detection_data_df)
                    high_critical_alerts = []; medium_alerts = []
                    if new_alerts_list:
                        for alert in new_alerts_list:
                            severity = alert.get('severity', '').lower()
                            if severity in ['alta', 'crítica']: high_critical_alerts.append(alert)
                            elif severity == 'media': medium_alerts.append(alert)
                        for alert in high_critical_alerts[:3]: flash(f"🚨 ALERTA CRÍTICA/ALTA: {alert.get('type', '')} - {alert.get('details', '')}", 'error')
                        if len(high_critical_alerts) > 3: flash(f"🚨 ... y {len(high_critical_alerts) - 3} alertas críticas/altas más. Revisa /alerts.", 'error')
                        for alert in medium_alerts[:2]: flash(f"⚠️ ALERTA MEDIA: {alert.get('type', '')} - {alert.get('details', '')}", 'warning')
                        if len(medium_alerts) > 2: flash(f"⚠️ ... y {len(medium_alerts) - 2} alertas medias más. Revisa /alerts.", 'warning')
                    flash(f"Detección completada ({data_info}). {new_alerts_count} nuevas alertas generadas.", 'success')

                    global detection_history; detection_history.append(results_for_session_and_history)
                else: flash("Detección falló.", 'warning'); session.pop('last_detection_results', None)
            elif source: flash("No hubo datos válidos para detección.", "info"); session.pop('last_detection_results', None)

            if sim_filepath_used and os.path.exists(sim_filepath_used):
                 try: os.remove(sim_filepath_used); print(f"INFO: Archivo temporal simulación eliminado: {sim_filepath_used}")
                 except Exception as e_del: print(f"WARN: No se pudo eliminar {sim_filepath_used}: {e_del}")
        except Exception as e: flash(f"Error inesperado detección: {e}", "error"); print(f"ERROR detect POST: {e}\n{traceback.format_exc()}"); session.pop('last_detection_results', None)
        return redirect(url_for('detect'))

    # GET Request
    try:
        last_results = session.get('last_detection_results'); cm_plot_url, report_df = None, None
        if last_results and isinstance(last_results.get('metrics'), dict):
            metrics = last_results['metrics']
            if metrics.get('confusion_matrix'): cm_plot_url = generate_plot_base64(plot_confusion_matrix_func, metrics['confusion_matrix'])
            if metrics.get('report'):
                 try: report_df = pd.DataFrame(metrics['report']).transpose()
                 except Exception as e: print(f"WARN: Convertir reporte a DF falló: {e}"); report_df = None
        sim_filepath = session.get('last_simulation_filepath'); has_simulation_file = sim_filepath and os.path.exists(sim_filepath)
        has_processed = data_manager.get_processed_data() is not None and not data_manager.get_processed_data().empty
    except Exception as e: print(f"ERROR detect GET: {e}\n{traceback.format_exc()}"); flash("Error preparando página detección.", "error"); last_results, cm_plot_url, report_df, has_processed, has_simulation_file = None, None, None, False, False
    return render_template('detection.html', has_processed_data=has_processed, has_simulation_data=has_simulation_file, last_results=last_results, report_df=report_df, cm_plot_url=cm_plot_url, detection_history=detection_history, detector=detector)

@app.route('/alerts', methods=['GET', 'POST'])
def alerts():
    """Muestra y permite gestionar alertas."""
    if request.method == 'POST':
        alert_id_str = request.form.get('alert_id')
        try:
            if alert_id_str:
                alert_id = int(alert_id_str); success = alert_manager.mark_alert_reviewed(alert_id)
                flash(f"Alerta {alert_id} marcada.", 'success') if success else flash(f"No se pudo marcar alerta {alert_id}.", 'warning')
            else: flash("No ID alerta.", 'warning')
        except ValueError: flash("ID inválido.", 'error')
        except Exception as e: flash(f"Error: {e}", 'error'); print(f"ERROR alerts POST: {e}\n{traceback.format_exc()}")
        return redirect(url_for('alerts', show_all=request.args.get('show_all', 'false')))
    # GET Request
    try: show_all = request.args.get('show_all', 'false').lower() == 'true'; current_alerts = alert_manager.get_alerts(show_all)
    except Exception as e: print(f"ERROR alerts GET: {e}\n{traceback.format_exc()}"); flash("Error obtener alertas.", "error"); current_alerts, show_all = [], False
    return render_template('alerts.html', alerts=current_alerts, show_all=show_all)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    """Maneja la configuración y tareas administrativas."""
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'update_threshold':
                new_threshold = float(request.form.get('glm_threshold')); success, message = admin_manager.update_glm_threshold(new_threshold); flash(message, 'success' if success else 'error')
            elif action == 'update_alert_config':
                 severity = request.form.get('alert_severity_threshold'); notify = 'notify_email' in request.form; success = alert_manager.update_config(severity_threshold=severity, notify_email=notify); flash("Config. alertas actualizada.", "success") if success else flash("No se pudo actualizar config. alertas.", "warning")
            elif action == 'retrain': retrain_msg = admin_manager.trigger_retraining(); flash(retrain_msg, 'info')
            else: flash(f"Acción '{action}' desconocida.", 'warning')
        except ValueError: flash("Valor numérico inválido.", 'error')
        except Exception as e: flash(f"Error acción admin: {e}", "error"); print(f"ERROR admin POST: {e}\n{traceback.format_exc()}")
        return redirect(url_for('admin'))
    # GET Request
    try: system_config = admin_manager.get_config(); alert_config = alert_manager.config; system_logs = admin_manager.get_system_logs()
    except Exception as e: print(f"ERROR admin GET: {e}\n{traceback.format_exc()}"); flash("Error cargar datos admin.", "error"); system_config, alert_config, system_logs = {}, {}, "Err logs."
    alert_severity_levels = ['Baja', 'Media', 'Alta', 'Crítica']
    return render_template('admin.html', system_config=system_config, alert_config=alert_config, alert_severity_levels=alert_severity_levels, system_logs=system_logs)


# --- NUEVA RUTA PLACEHOLDER --- <<<--- CORRECCIÓN AQUÍ
@app.route('/users/manage')
def manage_users_placeholder():
    """Página placeholder para gestión de usuarios."""
    flash("La gestión de usuarios aún no está implementada.", "info")
    # --- CAMBIO: Usar render_template ---
    return render_template('users_placeholder.html')
    # --- FIN CAMBIO ---


# --- Ejecución ---
if __name__ == '__main__':
    print("INFO: Iniciando servidor Flask...")
    # Cambiar debug=False para producción
    app.run(host='0.0.0.0', port=5000, debug=True)