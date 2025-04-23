# admin_manager.py
import datetime
import traceback # Añadir para logging si es necesario
import os # Importar os para manejar rutas si model_folder se usa aquí

# Nota: Esta clase no usa persistencia para la configuración en esta versión.
# Los cambios se perderán al reiniciar la aplicación, excepto el umbral del
# detector si ese objeto persiste de alguna manera.

class AdminManager:
    """
    Gestiona la configuración del sistema y tareas administrativas (algunas como placeholders).
    """

    # --- MODIFICADO: Ahora acepta 'model_folder' como argumento ---
    def __init__(self, detector_instance, model_folder):
        """
        Inicializa el gestor de administración.

        Args:
            detector_instance (ThreatDetector): Una instancia del ThreatDetector
                                                para poder interactuar con él (ej: cambiar umbral).
            model_folder (str): La ruta a la carpeta donde se guardan/cargan los modelos.
        """
        print("DEBUG: Inicializando AdminManager...")
        self.detector_ref = detector_instance
        self.model_folder = model_folder # <-- Almacena la ruta de la carpeta del modelo
        self.system_config = {'glm_threshold': 0.7} # Default inicial

        if self.detector_ref is None:
            print("WARN: AdminManager inicializado sin instancia de ThreatDetector. Funcionalidad limitada.")
            # Mantenemos el umbral por defecto en system_config
        else:
            # Intentar obtener el umbral actual del detector
            try:
                # --- CORRECCIÓN: Usar prediction_threshold del detector ---
                current_threshold = getattr(self.detector_ref, 'prediction_threshold', None)
                if current_threshold is not None:
                    self.system_config['glm_threshold'] = current_threshold
                    print(f"DEBUG: AdminManager obtuvo umbral inicial del detector: {current_threshold}")
                else:
                    # Si el detector no tiene el atributo (o es None), mantener el default y advertir
                    print(f"WARN: AdminManager no pudo obtener 'prediction_threshold' del detector. Usando default: {self.system_config['glm_threshold']}")
            except Exception as e:
                # Capturar otros posibles errores al acceder al atributo
                print(f"ERROR: Obteniendo umbral inicial del detector para AdminManager: {e}")
                print(f"WARN: Usando umbral por defecto en AdminManager: {self.system_config['glm_threshold']}")

        print("INFO: AdminManager inicializado.")
        print(f"INFO: Configuración inicial del sistema en AdminManager: {self.system_config}")


    def update_glm_threshold(self, new_threshold):
        """
        Intenta actualizar el umbral de decisión del modelo GLM llamando al método del detector.

        Args:
            new_threshold (float): El nuevo valor del umbral (debería ser validado por el detector).

        Returns:
            tuple: (bool, str) indicando éxito/fracaso y un mensaje.
        """
        if self.detector_ref is None:
            msg = "Error: No hay referencia al detector para actualizar el umbral."
            print(f"ERROR: {msg}")
            return False, msg

        # Verificar si el detector tiene el método esperado
        # --- CORRECCIÓN: Usar set_prediction_threshold ---
        if not hasattr(self.detector_ref, 'set_prediction_threshold'):
            msg = "Error: La instancia del detector no tiene el método 'set_prediction_threshold'."
            print(f"ERROR: {msg}")
            return False, msg

        try:
            # Llama al método del detector para validarlo y aplicarlo
            # --- CORRECCIÓN: Usar set_prediction_threshold ---
            success = self.detector_ref.set_prediction_threshold(new_threshold)

            if success:
                # Si el detector lo aceptó, actualiza nuestra copia en config leyendo el valor actualizado del detector
                # --- CORRECCIÓN: Leer prediction_threshold actualizado del detector ---
                updated_threshold = getattr(self.detector_ref, 'prediction_threshold', self.system_config.get('glm_threshold')) # Leer valor actualizado
                self.system_config['glm_threshold'] = updated_threshold
                msg = f"Umbral de decisión actualizado exitosamente a {updated_threshold:.4f}" # Formato para consistencia
                print(f"INFO: {msg}")
                return True, msg
            else:
                # El método set_prediction_threshold del detector debería haber indicado por qué falló (logs/excepción)
                # O podría devolver False si la validación interna falla.
                # Intentar obtener un mensaje de error más específico del detector si es posible
                detector_error_msg = getattr(self.detector_ref, 'last_error_message', None) # Suponiendo que el detector guarda un error
                if detector_error_msg:
                    msg = f"No se pudo actualizar el umbral: {detector_error_msg}"
                else:
                    msg = f"No se pudo actualizar el umbral a {new_threshold}. El detector rechazó el valor (¿fuera de rango?)."
                print(f"WARN: {msg}")
                # No actualizamos self.system_config['glm_threshold'] si falló
                return False, msg
        except Exception as e:
            # Capturar errores inesperados al llamar al método del detector
            msg = f"Error inesperado al intentar actualizar el umbral en el detector: {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")
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
        # --- CORRECCIÓN: Usar prediction_threshold para mostrar el valor actual ---
        current_threshold_display = self.system_config.get('glm_threshold', 'N/A')
        threshold_str = f"{current_threshold_display:.4f}" if isinstance(current_threshold_display, float) else str(current_threshold_display) # Formato para consistencia

        # Placeholder de logs (sin cambios en la estructura, solo usa el umbral corregido)
        log_ejemplo = f"""
[{(datetime.datetime.now() - datetime.timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Flask app inicializada. Modo Debug: True.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: DataManager inicializado.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: ThreatSimulator inicializado.
[{(datetime.datetime.now() - datetime.timedelta(minutes=9)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: ThreatDetector inicializado. Umbral: {threshold_str}
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


    # --- Método retrain_model para iniciar el reentrenamiento ---
    # Este método necesita la lógica para ejecutar el script data_model.py
    # o el código de reentrenamiento directamente.
    def retrain_model(self):
         """
         Inicia el proceso de reentrenamiento del modelo.
         Retorna un dict con 'success' y 'message', y opcionalmente paths a los nuevos archivos.
         """
         print("INFO: AdminManager iniciando re-entrenamiento del modelo...")
         if self.detector_ref is None:
              msg = "Error: No hay referencia al detector para el re-entrenamiento."
              print(f"ERROR: {msg}")
              return {'success': False, 'message': msg}

         # --- Implementación PLACEHOLDER ---
         # En una aplicación real:
         # 1. Necesitarías acceso al script data_model.py o a una función de reentrenamiento.
         # 2. Necesitarías el dataset de entrenamiento.
         # 3. Esto probablemente debería ser una tarea asíncrona para no bloquear la web app.
         # 4. Después de reentrenar, se DEBEN guardar el NUEVO modelo y scaler en self.model_folder.
         # 5. Se DEBEN retornar las rutas de los nuevos archivos para que app.py pueda cargarlos en el detector.

         msg = "Proceso de re-entrenamiento iniciado (Placeholder Síncrono). Esto no reentrena realmente."
         print(f"WARNING: {msg}")

         # Simulación de rutas de nuevos archivos después del reentrenamiento
         # En tu lógica de reentrenamiento real, esto serían las rutas DONDE se guardaron los nuevos archivos.
         new_model_path = os.path.join(self.model_folder, "modelo_glm.joblib") # Asume que se sobrescribe el archivo por defecto
         new_scaler_path = os.path.join(self.model_folder, "scaler.joblib") # Asume que se sobrescribe el archivo por defecto


         # Aquí iría la llamada a la lógica real de reentrenamiento
         # try:
         #     # Ejemplo: llamar a una función que ejecuta data_model.py o su lógica interna
         #     success_retrain = run_training_script(dataset_path, output_folder=self.model_folder)
         #     if not success_retrain:
         #         raise Exception("El script de entrenamiento reportó un fallo.")

         #     msg_result = "Re-entrenamiento completado. Nuevos archivos guardados."
         #     success = True
         # except Exception as e_retrain:
         #     msg_result = f"Error durante el re-entrenamiento: {e_retrain}"
         #     print(f"ERROR: {msg_result}\n{traceback.format_exc()}")
         #     success = False
         #     # Si falla, las rutas podrían no existir o ser incorrectas
         #     new_model_path = None
         #     new_scaler_path = None

         # --- Retornar resultado simulado/placeholder ---
         # Retornamos True y las rutas para que app.py intente cargarlos
         print("INFO: Placeholder de re-entrenamiento completado. Retornando rutas de archivos esperados.")
         return {
             'success': True, # Simular éxito
             'message': msg,
             'new_model_path': new_model_path, # Retornar la ruta donde se guardaría el nuevo modelo
             'new_scaler_path': new_scaler_path # Retornar la ruta donde se guardaría el nuevo scaler
         }


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
        # Asegurarse que el umbral en nuestra config esté sincronizado con el detector
        if self.detector_ref:
            try:
                # --- CORRECCIÓN: Usar prediction_threshold ---
                current_detector_config = self.detector_ref.get_config() # Llamar al método del detector
                if 'prediction_threshold' in current_detector_config:
                     self.system_config['glm_threshold'] = current_detector_config['prediction_threshold']
                # Si el detector tiene otros parámetros que gestiona AdminManager, sincronizarlos aquí
                # ej: if 'some_param' in current_detector_config: self.system_config['some_param'] = current_detector_config['some_param']

            except Exception as e:
                print(f"WARN: No se pudo sincronizar umbral con detector en get_config: {e}")

        return self.system_config