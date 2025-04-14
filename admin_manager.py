# admin_manager.py
import datetime

# Nota: Esta clase no usa persistencia para la configuración en esta versión.
# Los cambios se perderán al reiniciar la aplicación, excepto el umbral del
# detector si ese objeto persiste de alguna manera.

class AdminManager:
    """
    Gestiona la configuración del sistema y tareas administrativas (algunas como placeholders).
    """

    def __init__(self, detector_instance):
        """
        Inicializa el gestor de administración.

        Args:
            detector_instance (ThreatDetector): Una instancia del ThreatDetector
                                                para poder interactuar con él (ej: cambiar umbral).
        """
        if detector_instance is None:
            # Considera lanzar un error si el detector es esencial
            # raise ValueError("AdminManager requiere una instancia válida de ThreatDetector.")
            print("WARNING: AdminManager inicializado sin instancia de ThreatDetector. Funcionalidad limitada.")
            self.detector_ref = None
             # Configuración por defecto si no hay detector
            self.system_config = {'glm_threshold': 0.7}
        else:
            self.detector_ref = detector_instance
            # Inicializar la configuración del sistema reflejando el estado actual del detector
            self.system_config = {
                'glm_threshold': self.detector_ref.threshold
                # Puedes añadir más configuraciones aquí si las necesitas
            }
        print("INFO: AdminManager inicializado.")
        print(f"INFO: Configuración inicial del sistema: {self.system_config}")

    def update_glm_threshold(self, new_threshold):
        """
        Intenta actualizar el umbral de decisión del modelo GLM.

        Args:
            new_threshold (float): El nuevo valor del umbral (entre 0 y 1).

        Returns:
            tuple: (bool, str) indicando éxito/fracaso y un mensaje.
        """
        if self.detector_ref is None:
            return False, "Error: No hay referencia al detector para actualizar el umbral."

        # Llama al método del detector para validarlo y aplicarlo
        success = self.detector_ref.set_threshold(new_threshold)
        if success:
            # Si el detector lo aceptó, actualiza nuestra copia en config
            self.system_config['glm_threshold'] = self.detector_ref.threshold # Leer valor actualizado del detector
            msg = f"Umbral de decisión GLM actualizado a {self.detector_ref.threshold:.3f}"
            print(f"INFO: {msg}")
            return True, msg
        else:
            # El detector ya imprimió un error, solo devolvemos fallo
            msg = f"No se pudo actualizar el umbral a {new_threshold}. Revisa los logs para detalles."
            return False, msg

    def get_system_logs(self, max_lines=50):
        """
        Obtiene registros simulados del sistema.
        (Placeholder - Debería leer de un archivo de log real).

        Args:
            max_lines (int): Número máximo de líneas a devolver (no implementado aquí).

        Returns:
            str: Un string multi-línea con los logs simulados.
        """
        print("INFO: Obteniendo registros simulados del sistema (Placeholder).")
        # En una implementación real, aquí leerías las últimas N líneas de un archivo
        # de log configurado con el módulo 'logging' de Python.
        # También podrías obtener el número de alertas del alert_manager si tienes acceso a él.
        log_ejemplo = f"""
[{(datetime.datetime.now() - datetime.timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Flask app inicializada. Modo Debug: True.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: DataManager inicializado.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: ThreatSimulator inicializado.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: ThreatDetector inicializado. Umbral: {self.system_config.get('glm_threshold', 'N/A'):.2f}
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: AlertManager inicializado.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: AdminManager inicializado.
[{(datetime.datetime.now() - datetime.timedelta(minutes=8)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Ruta '/' accedida desde 127.0.0.1. Código de estado: 200.
[{(datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Archivo 'sample_traffic.csv' cargado exitosamente.
[{(datetime.datetime.now() - datetime.timedelta(minutes=4)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Preprocesamiento completado. Filas resultantes: 48500.
[{(datetime.datetime.now() - datetime.timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Ejecutando detección en 48500 registros...
[{(datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Detección completada. Métricas calculadas (Accuracy: 0.975).
[{(datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Analizando 1120 detecciones de posibles ataques...
[{(datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: 45 nuevas alertas generadas (cumpliendo umbral 'Media').
        """
        return log_ejemplo.strip() # Elimina espacios extra al inicio/final


    def trigger_retraining(self):
        """
        Inicia un proceso de reentrenamiento simulado (Placeholder).

        Returns:
            str: Un mensaje indicando el inicio simulado del proceso.
        """
        msg = "Iniciando proceso de reentrenamiento... (Simulado)"
        print(f"WARNING: {msg}")
        # Aquí iría la lógica real para:
        # 1. Lanzar un script de entrenamiento (posiblemente en segundo plano).
        # 2. Monitorear su progreso.
        # 3. Cargar el nuevo modelo en el ThreatDetector si el entrenamiento es exitoso.
        #    (ej: if self.detector_ref: self.detector_ref.load_model('ruta/al/nuevo/modelo.pkl'))
        return msg # Devolver mensaje para mostrar con flash()

    def manage_users(self):
        """
        Gestiona usuarios y roles (Placeholder).

        Returns:
            str: Un mensaje indicando que la funcionalidad no está implementada.
        """
        msg = "Funcionalidad de gestión de usuarios no implementada en este prototipo."
        print(f"INFO: {msg}")
        return msg

    def get_config(self):
        """
        Devuelve la configuración actual del sistema gestionada por AdminManager.

        Returns:
            dict: El diccionario self.system_config.
        """
        # Asegurarse que el umbral esté sincronizado con el detector por si acaso
        if self.detector_ref:
            self.system_config['glm_threshold'] = self.detector_ref.threshold
        return self.system_config