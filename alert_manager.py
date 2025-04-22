import datetime
import json
import os
import pandas as pd # Necesario si se inspecciona el DataFrame directamente
import traceback

ALERTS_FILE = "alerts_data.json" # Archivo para guardar/cargar las alertas
DETECTION_HISTORY_FILE = "detection_history.json" # Archivo para guardar/cargar el historial de detecciones

class AlertManager:
    """
    Gestiona la generación, visualización, estado y persistencia de las alertas
    y el historial de detecciones.
    """

    def __init__(self, config_defaults=None):
        """
        Inicializa el gestor de alertas y historial, cargando datos existentes si los hay.

        Args:
            config_defaults (dict, optional): Valores por defecto para la configuración.
                                            Defaults to {'severity_threshold': 'Media', 'notify_email': False}.
        """
        self.alerts = [] # Para las alertas específicas
        self.detection_history = [] # <-- NUEVA LISTA PARA EL HISTORIAL DE DETECCIONES
        self.config = config_defaults if config_defaults else {
            'severity_threshold': 'Media',
            'notify_email': False
        }
        self._next_id = 1 # Para asignar IDs únicos a las alertas
        self._load_alerts() # Cargar alertas al iniciar
        self._load_detection_history() # <-- NUEVO: Cargar historial de detecciones al iniciar

        print("INFO: AlertManager inicializado.")
        print(f"INFO: Configuración inicial de alertas: {self.config}")
        # Evitar imprimir miles de alertas si el archivo es grande
        print(f"INFO: {len(self.alerts)} alertas cargadas. Próximo ID: {self._next_id}")
        print(f"INFO: {len(self.detection_history)} entradas de historial de detección cargadas.")


    def _load_alerts(self):
        """Carga las alertas desde el archivo JSON si existe."""
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, 'r', encoding='utf-8') as f: # Añadir encoding
                    self.alerts = json.load(f)
                # Asegurarse que el ID siguiente sea mayor que cualquier ID existente
                if self.alerts:
                    # Filtrar posibles None o entradas sin 'id' antes de calcular max
                    valid_ids = [alert.get('id', 0) for alert in self.alerts if isinstance(alert.get('id'), int)]
                    max_id = max(valid_ids) if valid_ids else 0
                    self._next_id = max_id + 1
                else:
                    self._next_id = 1
                # No imprimir el número si son muchas
                # print(f"INFO: Cargadas {len(self.alerts)} alertas desde {ALERTS_FILE}")
            except json.JSONDecodeError:
                print(f"ERROR: El archivo de alertas '{ALERTS_FILE}' está corrupto o vacío. Empezando con lista vacía.")
                self.alerts = []
                self._next_id = 1
            except Exception as e:
                print(f"ERROR: No se pudo cargar el archivo de alertas '{ALERTS_FILE}': {e}")
                print(traceback.format_exc())
                self.alerts = []
                self._next_id = 1
        else:
            print(f"INFO: No se encontró archivo de alertas '{ALERTS_FILE}'. Empezando con lista vacía.")
            self.alerts = []
            self._next_id = 1

    # --- NUEVOS MÉTODOS PARA EL HISTORIAL DE DETECCIONES ---

    def _load_detection_history(self):
        """Carga el historial de detecciones desde el archivo JSON si existe."""
        if os.path.exists(DETECTION_HISTORY_FILE):
            try:
                with open(DETECTION_HISTORY_FILE, 'r', encoding='utf-8') as f:
                    self.detection_history = json.load(f)
                # Convertir timestamps de vuelta a objetos datetime si es necesario para ordenación,
                # aunque para display en templates el string ISO es suficiente.
                # Jinja filter | format_datetime en base.html maneja el string ISO.
                # print(f"INFO: Cargadas {len(self.detection_history)} entradas de historial desde {DETECTION_HISTORY_FILE}") # Descomentar para depurar
            except json.JSONDecodeError:
                print(f"ERROR: El archivo de historial '{DETECTION_HISTORY_FILE}' está corrupto o vacío. Empezando con lista vacía.")
                self.detection_history = []
            except Exception as e:
                print(f"ERROR: No se pudo cargar el archivo de historial '{DETECTION_HISTORY_FILE}': {e}")
                print(traceback.format_exc())
                self.detection_history = []
        else:
            print(f"INFO: No se encontró archivo de historial '{DETECTION_HISTORY_FILE}'. Empezando con lista vacía.")
            self.detection_history = []

    def _save_detection_history(self):
        """Guarda la lista actual del historial de detecciones en el archivo JSON."""
        try:
            # Asegurar que los objetos datetime se conviertan a string ISO si no lo están ya
            # (aunque en la función detect ya los guardamos como ISO, doble chequeo)
            def serialize_datetime(obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                raise TypeError("Type not serializable")

            with open(DETECTION_HISTORY_FILE, 'w', encoding='utf-8') as f:
                # Usamos default=serialize_datetime por si acaso hay algún objeto datetime que no se convirtió
                json.dump(self.detection_history, f, indent=4, ensure_ascii=False, default=serialize_datetime)
            # print(f"DEBUG: Historial de detecciones guardado en {DETECTION_HISTORY_FILE}") # Descomentar para depurar
        except IOError as e:
            print(f"ERROR: No se pudo guardar el archivo de historial '{DETECTION_HISTORY_FILE}': {e}")
        except Exception as e:
            print(f"ERROR: Error inesperado al guardar historial: {e}")
            print(traceback.format_exc())

    # --- MÉTODO MODIFICADO ---
    def add_detection_to_history(self, history_entry):
        """
        Añade una entrada de resumen de detección al historial, evitando duplicados exactos.
        La entrada debe ser un diccionario serializable (sin DataFrames o objetos complejos).
        """
        print("DEBUG: -> Dentro add_detection_to_history")
        if isinstance(history_entry, dict):
            print("DEBUG: -> history_entry es un diccionario")

            # --- COMPROBACIÓN ANTI-DUPLICADOS ---
            # Comprueba si una entrada EXACTAMENTE IGUAL ya existe en las últimas N entradas
            # (Revisar las últimas 10, por ejemplo, para eficiencia)
            already_exists = False
            check_range = min(10, len(self.detection_history)) # Revisa las últimas 10 o menos
            # Itera desde la penúltima hasta N entradas atrás
            for i in range(1, check_range + 1):
                 # Compara la entrada nueva con una entrada existente del historial
                 if self.detection_history[-i] == history_entry: # Comparación directa de diccionarios
                     already_exists = True
                     print(f"DEBUG: -> Entrada duplicada detectada. No se añadirá: {history_entry}")
                     break # Sale del bucle for si encuentra duplicado

            # Si no es duplicado, procede a añadir y guardar
            if not already_exists:
                # Opcional: Limitar el tamaño del historial si crece demasiado
                max_history_entries = 100 # Por ejemplo, guardar solo las últimas 100 entradas
                if len(self.detection_history) >= max_history_entries:
                    print("DEBUG: -> Límite tamaño historial alcanzado, eliminando más antiguo.")
                    self.detection_history.pop(0) # Eliminar la entrada más antigua
                    print("DEBUG: <- Eliminado entrada más antigua.")

                print("DEBUG: -> Añadiendo history_entry a self.detection_history")
                self.detection_history.append(history_entry) # <-- Aquí se añade al historial en memoria
                print(f"DEBUG: <- Añadido history_entry. Tamaño actual del historial: {len(self.detection_history)}")

                print("DEBUG: -> Llamando a _save_detection_history()")
                self._save_detection_history() # Guardar la lista actualizada en el archivo JSON
                print("DEBUG: <- _save_detection_history() retornó.")

                print("INFO: Resumen de detección añadido al historial.")
            # --- FIN COMPROBACIÓN ANTI-DUPLICADOS ---

        else:
            print(f"ERROR: Intento de añadir al historial con un formato incorrecto: {type(history_entry)}")
        print("DEBUG: <- Saliendo de add_detection_to_history")


    def get_detection_history(self):
        """Devuelve la lista del historial de detecciones (ordenadas, más recientes primero)."""
        # El historial ya se añade en orden cronológico, pero lo ordenamos por si acaso
        # Ordenar por timestamp descendente
        history_to_sort = self.detection_history
        try:
             return sorted(
                 history_to_sort,
                 key=lambda x: x.get('timestamp', '1970-01-01T00:00:00'), # Usar un timestamp por defecto para evitar errores
                 reverse=True
             )
        except Exception as e:
             print(f"ERROR ordenando historial de detecciones: {e}")
             return history_to_sort # Devolver sin ordenar si falla

    # --- FIN NUEVOS MÉTODOS PARA EL HISTORIAL DE DETECCIONES ---


    def generate_alerts(self, detection_results_df):
        """
        Genera alertas basadas en los resultados de detección proporcionados.

        Args:
            detection_results_df (pd.DataFrame): DataFrame con los resultados de la detección,
                                                 debe incluir 'prediction_label' y otras
                                                 columnas relevantes (src_ip, dst_ip, label, etc.).

        Returns:
            tuple: (int, list) El número de nuevas alertas generadas y la lista
                   de los diccionarios de esas nuevas alertas.
        """
        if detection_results_df is None or detection_results_df.empty:
            print("INFO: No hay resultados de detección para generar alertas.")
            return 0, [] # Devolver tupla con lista vacía

        # Asegurarse de que la columna 'prediction_label' existe antes de filtrar
        if 'prediction_label' not in detection_results_df.columns:
             print("WARN: Columna 'prediction_label' no encontrada en los resultados para generar alertas.")
             return 0, []

        potential_attacks = detection_results_df[detection_results_df['prediction_label'] == 'ATTACK']
        new_alerts_list = [] # Lista para guardar solo las nuevas de esta ejecución
        print(f"INFO: Analizando {len(potential_attacks)} detecciones de posibles ataques...")

        # Mapeo de etiquetas a severidad - Asegúrate de que todas tus posibles etiquetas de ataque estén aquí
        # Si una etiqueta de ataque del modelo no está en este mapa, por defecto será 'Media'
        severity_map = {
            'DDoS': 'Alta',
            'Scan': 'Media',
            'Malware': 'Crítica',
            'PortScan':'Media',
            'Infiltration': 'Alta',
            'BENIGN': 'Baja', # Aunque filtramos por 'ATTACK', es bueno tener BENIGN mapeado
            'ATTACK': 'Media' # Valor por defecto si la etiqueta de ataque no está mapeada específicamente
        }
        severity_levels = {'Baja': 1, 'Media': 2, 'Alta': 3, 'Crítica': 4}
        # Usar .get con valor por defecto para evitar KeyError si 'severity_threshold' no está en config
        threshold_level = severity_levels.get(self.config.get('severity_threshold', 'Media'), 2) # Por defecto 'Media' (nivel 2) si no se puede obtener de config o mapear

        for index, row in potential_attacks.iterrows():
            # Intentar obtener la etiqueta original si existe, de lo contrario usar 'ATTACK'
            attack_type_detected = row.get('label', 'ATTACK')

            # Determinar la severidad basada en la etiqueta detectada
            # Usar .get con un valor por defecto si la etiqueta no está en severity_map
            severity = severity_map.get(attack_type_detected, severity_map.get('ATTACK', 'Media')) # Por defecto 'Media' if ni siquiera ATTACK está mapeado

            current_severity_level = severity_levels.get(severity, 1)

            if current_severity_level >= threshold_level:
                alert = {
                    "id": self._next_id,
                    "timestamp": datetime.datetime.now().isoformat(timespec='seconds'),
                    "type": f"Amenaza Detectada ({attack_type_detected})", # Usar la etiqueta detectada en el tipo
                    "severity": severity,
                    "details": f"SRC: {row.get('src_ip', 'N/A')}, DST: {row.get('dst_ip', 'N/A')}, Proto: {row.get('protocol', 'N/A')}",
                    "reviewed": False
                }
                self.alerts.append(alert) # Añadir a la lista principal
                new_alerts_list.append(alert) # Añadir a la lista de nuevas
                self._next_id += 1

                # Simulación de notificación por correo electrónico
                if self.config.get('notify_email', False): # Usar .get con valor por defecto
                    print(f"SIMULACION EMAIL [{severity.upper()}]: {alert['type']} - {alert['details']}")

        new_alerts_count = len(new_alerts_list)
        if new_alerts_count > 0:
            print(f"INFO: {new_alerts_count} nuevas alertas generadas (cumpliendo umbral '{self.config.get('severity_threshold', 'Media')}').")
            self._save_alerts() # <-- Aquí se llama a _save_alerts()
            return new_alerts_count, new_alerts_list # Devolver conteo y lista
        else:
            print(f"INFO: No se generaron nuevas alertas que cumplan el umbral '{self.config.get('severity_threshold', 'Media')}'.")
            return 0, [] # Devolver 0 y lista vacía

    # --- MÉTODO get_alerts (PARA MOSTRAR ALERTAS EN EL DASHBOARD/ALERTS PAGE) ---
    def get_alerts(self, show_all=False):
        """Devuelve la lista de alertas (ordenadas, más recientes primero)."""
        alerts_to_sort = self.alerts
        if not show_all:
            alerts_to_sort = [a for a in self.alerts if not a.get('reviewed', False)]
        # Ordenar por timestamp descendente (más reciente primero)
        # Manejar casos donde timestamp podría faltar o ser inválido
        try:
            return sorted(
                alerts_to_sort,
                key=lambda x: x.get('timestamp', '1970-01-01T00:00:00'), # Use a default timestamp string to avoid errors
                reverse=True
            )
        except Exception as e:
            print(f"ERROR sorting alerts: {e}")
            return alerts_to_sort # Return unsorted list on error


    # --- MÉTODO _save_alerts (PARA GUARDAR ALERTAS EN EL ARCHIVO JSON) ---
    def _save_alerts(self): # <-- ¡¡¡Este método debe estar en tu clase!!!
        """Guarda la lista actual de alertas en el archivo JSON."""
        try:
            with open(ALERTS_FILE, 'w', encoding='utf-8') as f: # Añadir encoding
                json.dump(self.alerts, f, indent=4, ensure_ascii=False) # ensure_ascii=False por si hay caracteres especiales
            # print(f"DEBUG: Alertas guardadas en {ALERTS_FILE}") # Descomentar para depurar
        except IOError as e:
            print(f"ERROR: No se pudo guardar el archivo de alertas '{ALERTS_FILE}': {e}")
        except Exception as e:
             print(f"ERROR: Error inesperado al guardar alertas: {e}")
             print(traceback.format_exc())


    # --- MÉTODO mark_alert_reviewed ---
    def mark_alert_reviewed(self, alert_id):
        """Marca una alerta específica como revisada por su ID."""
        alert_updated = False
        found = False
        # Asegurarse de que alert_id es int para la comparación
        if not isinstance(alert_id, int):
            try:
                alert_id = int(alert_id)
            except (ValueError, TypeError):
                print(f"ERROR: ID de alerta inválido recibido: {alert_id}")
                return False # Devolver False si el ID no es válido

        for alert in self.alerts:
            # Usar .get() para acceder al ID de forma segura
            if alert.get('id') == alert_id:
                found = True
                # Usar .get() para acceder al estado 'reviewed' de forma segura
                if not alert.get('reviewed', False): # Usar False como valor por defecto
                    alert['reviewed'] = True
                    alert_updated = True
                    print(f"INFO: Alerta ID {alert_id} marcada como revisada.")
                # else: print(f"INFO: Alerta ID {alert_id} ya estaba revisada.") # Opcional
                break # Salir del bucle una vez encontrada la alerta

        if not found:
            print(f"ERROR: No se encontró alerta con ID {alert_id}.")

        if alert_updated:
            self._save_alerts() # Guardar después de actualizar
            return True
        # Si no se encontró la alerta O ya estaba revisada
        return False


    # --- MÉTODO update_config ---
    def update_config(self, severity_threshold=None, notify_email=None):
        """Actualiza la configuración de alertas."""
        updated = False
        valid_severities = ['Baja', 'Media', 'Alta', 'Crítica']
        if severity_threshold is not None and severity_threshold in valid_severities:
            # Usar .get() para comparar de forma segura
            if self.config.get('severity_threshold') != severity_threshold:
                self.config['severity_threshold'] = severity_threshold
                print(f"INFO: Umbral severidad actualizado a '{severity_threshold}'"); updated = True
        # Manejar caso donde severity_threshold es None o inválido, pero notify_email sí se envió
        elif severity_threshold is not None: # Si se envió pero es inválido
             print(f"ERROR: Umbral severidad inválido recibido para actualizar: {severity_threshold}"); return False

        if notify_email is not None and isinstance(notify_email, bool):
             # Usar .get() para comparar de forma segura
             if self.config.get('notify_email') != notify_email:
                 self.config['notify_email'] = notify_email
                 print(f"INFO: Notificación Email {'Activada' if notify_email else 'Desactivada'}."); updated = True
        # Manejar caso donde notify_email es None o inválido, pero severity_threshold sí se envió
        elif notify_email is not None: # Si se envió pero es inválido
             print("ERROR: Valor inválido recibido para notify_email (debe ser True/False)"); return False

        # Nota: Configuración no se guarda persistentemente aquí por defecto.
        # Si quisieras persistirla (ej. en un archivo o BD), deberías añadir
        # una llamada a un método _save_config() aquí o manejarlo externamente.
        # Por ahora, solo actualizamos la instancia en memoria.

        # Devuelve True si al menos una configuración se actualizó
        return updated


    # --- MÉTODO delete_all_alerts ---
    def delete_all_alerts(self): # <-- ¡¡¡Este método debe estar en tu clase!!!
        """
        Borra TODAS las alertas almacenadas.
        Retorna (bool: success, str: message)
        """
        try:
            count = len(self.alerts)
            self.alerts = [] # La forma más simple si es una lista en memoria

            # Si usaras una base de datos, aquí ejecutarías: DELETE FROM alerts;

            self._save_alerts() # Save the changes after deleting - Llama al método _save_alerts que acabamos de asegurar que esté.

            # También, si quieres borrar el archivo físico:
            # if os.path.exists(ALERTS_FILE):
            #     os.remove(ALERTS_FILE)
            #     print(f"INFO: Archivo de alertas '{ALERTS_FILE}' eliminado.")

            print(f"INFO: {count} alertas borradas exitosamente.")
            return True, f"Se borraron exitosamente {count} alertas."
        except Exception as e:
            # Loggear el error es importante
            print(f"ERROR al borrar todas las alertas: {e}\n{traceback.format_exc()}")
            return False, f"Ocurrió un error al intentar borrar las alertas: {e}"


    # --- MÉTODO manage_rules (Placeholder) ---
    def manage_rules(self): # Placeholder method
        """Gestiona reglas de seguridad (Placeholder)."""
        print("INFO: Accediendo a gestión de reglas (Placeholder).")
        return "Funcionalidad de gestión de reglas no implementada."