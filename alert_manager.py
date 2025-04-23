# alert_manager.py
import datetime
import json
import os
import pandas as pd
import traceback # Añadir para tracebacks detallados

# Asegurarse de que la carpeta para los archivos de datos exista
# Esto es importante si los archivos no están en el mismo directorio que el script.
# Podrías definir una constante para la carpeta de datos o usar una pasada en __init__
DATA_FOLDER = '.' # Carpeta actual por defecto. Considera usar una ruta absoluta o configurable.
ALERTS_FILE = os.path.join(DATA_FOLDER, "alerts_data.json") # Archivo para guardar/cargar las alertas
DETECTION_HISTORY_FILE = os.path.join(DATA_FOLDER, "detection_history.json") # Archivo para guardar/cargar el historial de detecciones

class AlertManager:
    """
    Gestiona la generación, visualización, estado y persistencia de las alertas
    y el historial de detecciones. Usa archivos JSON para persistencia.
    """

    def __init__(self, config_defaults=None):
        """
        Inicializa el gestor de alertas y historial, cargando datos existentes si los hay.

        Args:
            config_defaults (dict, optional): Valores por defecto para la configuración.
                                            Defaults to {'severity_threshold': 'Media', 'notify_email': False}.
        """
        print("DEBUG: Inicializando AlertManager...")
        self.alerts = [] # Para las alertas específicas
        self.detection_history = [] # Para el historial de detecciones
        self.config = config_defaults if config_defaults else {
            'severity_threshold': 'Media',
            'notify_email': False
        }
        self._next_id = 1 # Para asignar IDs únicos a las alertas

        # Asegurarse de que la carpeta de datos exista
        os.makedirs(DATA_FOLDER, exist_ok=True)

        self._load_alerts() # Cargar alertas al iniciar
        self._load_detection_history() # Cargar historial de detecciones al iniciar

        print("INFO: AlertManager inicializado.")
        print(f"INFO: Configuración inicial de alertas: {self.config}")
        # Evitar imprimir miles de alertas si el archivo es grande, solo el conteo
        print(f"INFO: {len(self.alerts)} alertas cargadas. Próximo ID: {self._next_id}")
        print(f"INFO: {len(self.detection_history)} entradas de historial de detección cargadas.")


    def _load_alerts(self):
        """Carga las alertas desde el archivo JSON si existe."""
        print(f"DEBUG: Intentando cargar alertas desde {ALERTS_FILE}...")
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                    # Asegurarse de que lo cargado es una lista
                    if isinstance(loaded_data, list):
                        self.alerts = loaded_data
                    else:
                        print(f"WARNING: El contenido del archivo '{ALERTS_FILE}' no es una lista. Empezando con lista vacía.")
                        self.alerts = []

                # Asegurarse que el ID siguiente sea mayor que cualquier ID existente
                if self.alerts:
                    # Filtrar posibles None o entradas sin 'id' antes de calcular max
                    valid_ids = [alert.get('id', 0) for alert in self.alerts if isinstance(alert, dict) and isinstance(alert.get('id'), int)]
                    max_id = max(valid_ids) if valid_ids else 0
                    self._next_id = max_id + 1
                else:
                    self._next_id = 1

                print(f"SUCCESS: Cargadas {len(self.alerts)} alertas desde {ALERTS_FILE}")

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
        print(f"DEBUG: Intentando cargar historial desde {DETECTION_HISTORY_FILE}...")
        if os.path.exists(DETECTION_HISTORY_FILE):
            try:
                with open(DETECTION_HISTORY_FILE, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                    # Asegurarse de que lo cargado es una lista
                    if isinstance(loaded_data, list):
                        self.detection_history = loaded_data
                    else:
                        print(f"WARNING: El contenido del archivo '{DETECTION_HISTORY_FILE}' no es una lista. Empezando con lista vacía.")
                        self.detection_history = []

                # Los timestamps ya deberían estar en formato ISO string al guardar
                print(f"SUCCESS: Cargadas {len(self.detection_history)} entradas de historial desde {DETECTION_HISTORY_FILE}")

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
        print(f"DEBUG: Guardando historial en {DETECTION_HISTORY_FILE}...")
        try:
            # Asegurar que los objetos datetime se conviertan a string ISO si no lo están ya
            # (la lógica en ThreatDetector.detect_threats debería hacerlo, pero este es un fallback)
            def serialize_datetime(obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                # Añadir manejo para objetos específicos que puedan estar en el historial si no son nativos JSON
                # elif isinstance(obj, np.int64): return int(obj) # Ejemplo para numpy ints si no se convirtieron
                # elif isinstance(obj, np.float64): return float(obj) # Ejemplo para numpy floats
                # ... otros tipos no nativos si es necesario ...
                # Si el tipo no se puede serializar, lanzará un TypeError por defecto
                raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

            with open(DETECTION_HISTORY_FILE, 'w', encoding='utf-8') as f:
                # Usamos default=serialize_datetime para manejar objetos datetime o numpy que no se hayan convertido
                json.dump(self.detection_history, f, indent=4, ensure_ascii=False, default=serialize_datetime)
            print(f"SUCCESS: Historial de detecciones guardado en {DETECTION_HISTORY_FILE}")
        except IOError as e:
            print(f"ERROR: No se pudo guardar el archivo de historial '{DETECTION_HISTORY_FILE}': {e}")
        except Exception as e:
            print(f"ERROR: Error inesperado al guardar historial: {e}")
            print(traceback.format_exc())

    # --- MÉTODO MODIFICADO ---
    # Este método es llamado por app.py después de una detección exitosa
    def add_detection_to_history(self, history_entry):
        """
        Añade una entrada de resumen de detección al historial.
        La entrada debe ser un diccionario serializable (sin DataFrames o objetos complejos).
        """
        print("DEBUG: -> Dentro add_detection_to_history")
        if isinstance(history_entry, dict):
            print(f"DEBUG: -> Recibida entrada de historial (dict): {history_entry.get('timestamp', 'N/A')} - {history_entry.get('source_info', 'N/A')}")

            # --- Eliminada la comprobación anti-duplicados poco fiable ---
            # Simplemente añadir la nueva entrada al final
            # Asegurarse de que la entrada no contenga DataFrames u objetos no serializables
            # ThreatDetector ya debería retornar un dict serializable.
            # Si contiene np.int/float, el default serializador en _save_detection_history los manejará.

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

        else:
            print(f"ERROR: Intento de añadir al historial con un formato incorrecto: {type(history_entry)}. Se esperaba un diccionario.")
        print("DEBUG: <- Saliendo de add_detection_to_history")


    # --- MÉTODO get_detection_history (PARA MOSTRAR HISTORIAL EN ALGUNA PÁGINA) ---
    # Este método es llamado por app.py en la ruta /dashboard o /history (si existe)
    def get_detection_history(self, limit=None):
        """Devuelve la lista del historial de detecciones (ordenadas, más recientes primero), opcionalmente limitada."""
        # El historial ya se añade en orden cronológico, pero lo ordenamos explícitamente por si acaso
        # Ordenar por timestamp descendente (más reciente primero)
        history_to_sort = self.detection_history
        try:
            sorted_history = sorted(
                history_to_sort,
                key=lambda x: x.get('timestamp', '1970-01-01T00:00:00'), # Usar un timestamp por defecto seguro
                reverse=True
            )
        except Exception as e:
            print(f"ERROR ordenando historial de detecciones: {e}")
            sorted_history = history_to_sort # Devolver sin ordenar si falla

        # Aplicar límite si se especifica
        if limit is not None and isinstance(limit, int) and limit > 0:
             print(f"DEBUG: Retornando las últimas {limit} entradas del historial de detección.")
             return sorted_history[:limit]
        else:
             print(f"DEBUG: Retornando todo el historial de detección ({len(sorted_history)} entradas).")
             return sorted_history


    # --- FIN MÉTODOS PARA EL HISTORIAL DE DETECCIONES ---


    # --- MÉTODO MODIFICADO: generate_alerts (Recibe el dict de resultados del detector) ---
    # Este método es llamado por app.py después de una detección exitosa
    def generate_alerts(self, detection_results):
        """
        Genera y almacena alertas basadas en los resultados de detección proporcionados.
        Añade las alertas generadas a la lista interna y las guarda en el archivo.

        Args:
            detection_results (dict): Diccionario con los resultados de la detección,
                                      tal como lo retorna ThreatDetector.detect_threats().
                                      Debe contener 'data' (DataFrame), 'model_threshold',
                                      y potencialmente 'source_info', 'metrics', etc.

        Returns:
            list: La lista de los diccionarios de las NUEVAS alertas que fueron generadas
                  y almacenadas en esta llamada. Retorna una lista vacía si no se generaron alertas
                  o si hubo un error.
        """
        print("INFO: Generando alertas a partir de resultados de detección...")
        # Verificar si detection_results es un diccionario válido y contiene la clave 'data' (DataFrame)
        if not isinstance(detection_results, dict) or 'data' not in detection_results or not isinstance(detection_results['data'], pd.DataFrame):
             print("ERROR: Resultados de detección inválidos recibidos para generar alertas (falta 'data' o no es DataFrame).")
             return [] # Devolver lista vacía

        df_results = detection_results['data'] # Extraer el DataFrame de los resultados
        # Obtener el umbral del modelo usado en la detección
        model_threshold_detector = detection_results.get('model_threshold', 0.5) # Usar el umbral del detector si está disponible
        source_info = detection_results.get('source_info', 'Detección') # Información de la fuente

        if df_results.empty:
             print("INFO: DataFrame de resultados para generar alertas está vacío.")
             return [] # Devolver lista vacía si el DataFrame está vacío

        # Asegurarse de que las columnas necesarias para la generación de alertas existan
        required_cols_for_alert = ['Predicted_Label', 'Threat_Probability', 'Src IP', 'Dst IP', 'Dst Port', 'Protocol'] # AJUSTA ESTO a las columnas que usas en los detalles
        if not all(col in df_results.columns for col in required_cols_for_alert):
             missing = [col for col in required_cols_for_alert if col not in df_results.columns]
             print(f"ERROR: Faltan columnas requeridas en el DataFrame de resultados para generar alertas: {missing}")
             print(f"Columnas disponibles: {list(df_results.columns)}")
             return []


        potential_attacks = df_results[df_results['Predicted_Label'] == 'ATTACK'].copy()
        new_alerts_list = [] # Lista para guardar solo las nuevas de esta ejecución
        print(f"INFO: Analizando {len(potential_attacks)} detecciones predichas como ATTACK...")

        # Mapeo de etiquetas a severidad - Asegúrate de que todas tus posibles etiquetas de ataque estén aquí
        # Si una etiqueta de ataque del modelo no está en este mapa, por defecto será 'Media'
        # También podrías basar la severidad puramente en la probabilidad
        severity_map = {
            'DDoS': 'Alta',
            'Scan': 'Media',
            'Malware': 'Crítica',
            'PortScan':'Media',
            'Infiltration': 'Alta',
            # Añade aquí otras etiquetas de ataque si tu modelo las predice
            'ATTACK': 'Media' # Valor por defecto si la etiqueta de ataque no está mapeada específicamente
        }
        # Definir el orden y nivel numérico de las severidades para comparar con el umbral de configuración
        severity_levels = {'Baja': 1, 'Media': 2, 'Alta': 3, 'Crítica': 4}
        # Obtener el umbral de severidad de la configuración del AlertManager
        threshold_severity_name = self.config.get('severity_threshold', 'Media')
        threshold_level = severity_levels.get(threshold_severity_name, 2) # Por defecto 'Media' (nivel 2)

        # Lógica para generar alertas por cada fila de ataque potencial
        for index, row in potential_attacks.iterrows():
            # Determinar el tipo de alerta (basado en la etiqueta original si existe, o la predicha)
            # Puedes usar la columna 'Label' original si el dataframe de resultados la mantuvo,
            # o usar la 'Predicted_Label' o una combinación.
            # Si tu modelo predice subtipos de ataque, podrías usar row.get('Predicted_Subtype', 'ATTACK')
            alert_type_detected = row.get('Label', row.get('Predicted_Label', 'ATTACK')) # Preferir Label original, si no Predicted, si no 'ATTACK'

            # Determinar la severidad: basada en probabilidad O en tipo mapeado
            severity = 'Baja' # Default
            prob = row.get('Threat_Probability')

            if prob is not None and isinstance(prob, (int, float)):
                 # Opcion 1: Basar la severidad puramente en la probabilidad
                 if prob >= 0.95: severity = 'Crítica' # Umbral de probabilidad muy alto
                 elif prob >= 0.8: severity = 'Alta' # Umbral de probabilidad alto
                 elif prob >= 0.6: severity = 'Media' # Umbral de probabilidad medio
                 else: severity = 'Baja' # Probabilidad más baja, incluso si se predijo ataque
                 # Puedes refinar estos umbrales de probabilidad

                 # Opcion 2: Basar la severidad en el mapeo de etiquetas (si priorizas el tipo de ataque)
                 # severity = severity_map.get(alert_type_detected, severity_map.get('ATTACK', 'Media'))

                 # Opcion 3: Combinar: usar mapeo, pero ajustar por probabilidad (ej. si prob es muy baja, bajar severidad)
                 # base_severity = severity_map.get(alert_type_detected, severity_map.get('ATTACK', 'Media'))
                 # base_level = severity_levels.get(base_severity, 1)
                 # if prob < 0.6 and base_level > severity_levels.get('Baja'): # Si prob es baja, bajar si no es ya 'Baja'
                 #     severity = 'Baja'
                 # elif prob > 0.9 and base_level < severity_levels.get('Crítica'): # Si prob es alta, subir si no es ya 'Crítica'
                 #     severity = 'Crítica'
                 # else:
                 #     severity = base_severity # Mantener severidad base si prob está en rango medio


            else:
                 # Si no hay probabilidad válida, usar el mapeo de etiquetas como fallback
                 severity = severity_map.get(alert_type_detected, severity_map.get('ATTACK', 'Media'))
                 print(f"DEBUG: No hay probabilidad válida para fila {index}. Usando severidad por mapeo: {severity}")


            # Verificar si la severidad calculada (como nivel numérico) cumple o supera el umbral de configuración
            current_severity_level = severity_levels.get(severity, 1)

            if current_severity_level >= threshold_level:
                # Crear el diccionario de alerta
                alert = {
                    "id": self._next_id,
                    "timestamp": datetime.datetime.utcnow().isoformat(), # Hora actual en UTC
                    "type": f"Amenaza Detectada ({alert_type_detected})", # Usar la etiqueta detectada en el tipo
                    "severity": severity,
                    # Detalles relevantes de la fila de datos
                    # Asegurarse de que los valores sean serializables (int, float, str, bool, None)
                    "details": {
                        "source": source_info, # Información de la fuente de datos
                        "row_index": index, # Índice de la fila en el DF original
                        "predicted_label": row.get('Predicted_Label', 'N/A'),
                        "probability": float(prob) if prob is not None else None, # Convertir a float nativo
                        "src_ip": str(row.get('Src IP', 'N/A')),
                        "dst_ip": str(row.get('Dst IP', 'N/A')),
                        "dst_port": str(row.get('Dst Port', 'N/A')), # Puertos pueden ser strings o int, asegurar string para detalles
                        "protocol": str(row.get('Protocol', 'N/A')),
                        # Añade aquí otras características importantes de la fila para los detalles de la alerta
                        # ej: 'flow_duration': float(row.get('Flow Duration', 0)) if row.get('Flow Duration') is not None else 0,
                        # Asegúrate de convertir tipos numpy (int64, float64) a int/float nativos si no lo hizo pandas.get
                    },
                    "reviewed": False, # Estado inicial
                    # Puedes añadir más campos (ej. assigned_to, resolution, etc.)
                }

                self.alerts.append(alert) # Añadir a la lista principal en memoria
                new_alerts_list.append(alert) # Añadir a la lista de nuevas generadas en esta corrida
                self._next_id += 1 # Incrementar contador de ID

                # Simulación de notificación por correo electrónico
                if self.config.get('notify_email', False): # Usar .get con valor por defecto
                    # Formatear el mensaje de email (simplificado)
                    email_subject = f"[Alerta {severity.upper()}] {alert['type']}"
                    email_body = f"Alerta ID: {alert['id']}\n"
                    email_body += f"Timestamp: {alert['timestamp']}\n"
                    email_body += f"Fuente: {source_info}\n"
                    email_body += f"Severidad: {severity}\n"
                    email_body += "Detalles:\n"
                    # Iterar sobre los detalles del diccionario para el email
                    for detail_key, detail_value in alert['details'].items():
                         email_body += f"- {detail_key}: {detail_value}\n"

                    print(f"SIMULACION EMAIL:\nSubject: {email_subject}\nBody:\n{email_body}\n" + "-"*20)


        count_generated = len(new_alerts_list)
        if count_generated > 0:
            print(f"INFO: {count_generated} nuevas alertas generadas (cumpliendo umbral '{threshold_severity_name}').")
            self._save_alerts() # Guardar las alertas después de generar nuevas
        else:
            print(f"INFO: No se generaron nuevas alertas que cumplan el umbral '{threshold_severity_name}'.")

        return new_alerts_list # Retorna la lista de alertas que fueron generadas en esta llamada


    # --- MÉTODO get_recent_alerts (NUEVO - llamado por app.py para dashboard) ---
    def get_recent_alerts(self, limit=5):
        """
        Obtiene las alertas más recientes, ordenadas por timestamp descendente.
        No filtra por estado de revisión por defecto.
        Args:
            limit (int): El número máximo de alertas a retornar.
        Returns:
            list: Una lista de diccionarios de alerta.
        """
        print(f"DEBUG: Obteniendo las {limit} alertas más recientes (sin filtrar por revisada)...")
        # Llama al método interno para obtener todas las alertas ordenadas y aplica el límite
        all_sorted_alerts = self._get_alerts_sorted_and_filtered(show_reviewed=True, show_unreviewed=True) # Obtener todas, ordenadas
        recent = all_sorted_alerts[:limit] # Tomar las primeras 'limit'

        print(f"DEBUG: Retornando {len(recent)} alertas recientes.")
        return recent


    # --- MÉTODO get_all_alerts (NUEVO - llamado por app.py para /alerts) ---
    def get_all_alerts(self):
        """
        Obtiene todas las alertas, ordenadas por timestamp descendente.
        Returns:
            list: Una lista de diccionarios de alerta.
        """
        print("DEBUG: Obteniendo todas las alertas (sin filtrar por revisada)...")
        # Llama al método interno para obtener todas las alertas ordenadas
        all_sorted_alerts = self._get_alerts_sorted_and_filtered(show_reviewed=True, show_unreviewed=True) # Obtener todas, ordenadas

        print(f"DEBUG: Retornando {len(all_sorted_alerts)} alertas totales.")
        return all_sorted_alerts


    # --- MÉTODO get_unreviewed_alerts (Opcional - si necesitas solo las no revisadas) ---
    def get_unreviewed_alerts(self):
        """
        Obtiene solo las alertas no revisadas, ordenadas por timestamp descendente.
        Returns:
            list: Una lista de diccionarios de alerta no revisadas.
        """
        print("DEBUG: Obteniendo solo alertas NO revisadas...")
        # Llama al método interno para obtener solo las no revisadas
        unreviewed_alerts = self._get_alerts_sorted_and_filtered(show_reviewed=False, show_unreviewed=True)
        print(f"DEBUG: Retornando {len(unreviewed_alerts)} alertas no revisadas.")
        return unreviewed_alerts


    # --- MÉTODO INTERNO _get_alerts_sorted_and_filtered (Adaptado de tu get_alerts) ---
    def _get_alerts_sorted_and_filtered(self, show_reviewed=True, show_unreviewed=True):
        """
        Devuelve la lista de alertas, opcionalmente filtradas por estado de revisión y ordenadas.
        Este es un método interno usado por los métodos públicos (get_recent_alerts, get_all_alerts, get_unreviewed_alerts).

        Args:
            show_reviewed (bool): Incluir alertas marcadas como revisadas.
            show_unreviewed (bool): Incluir alertas marcadas como no revisadas.

        Returns:
            list: Una lista de diccionarios de alerta.
        """
        alerts_to_process = self.alerts # Trabajar sobre la lista principal

        # Aplicar filtro por estado de revisión
        if not show_reviewed and show_unreviewed: # Solo no revisadas
             alerts_to_process = [a for a in self.alerts if not a.get('reviewed', False)]
        elif show_reviewed and not show_unreviewed: # Solo revisadas
             alerts_to_process = [a for a in self.alerts if a.get('reviewed', False)]
        elif not show_reviewed and not show_unreviewed: # No incluir ninguna (lista vacía)
             alerts_to_process = []
        # Si show_reviewed=True y show_unreviewed=True (por defecto), no se filtra por estado, se usan todas.


        # Ordenar por timestamp descendente (más reciente primero)
        # Manejar casos donde timestamp podría faltar o ser inválido
        try:
            # Intenta convertir a datetime para ordenar si es posible, si no, usa el string ISO
            def get_sort_key(alert):
                 timestamp_str = alert.get('timestamp')
                 if isinstance(timestamp_str, str):
                      try:
                          # Intentar parsear como ISO 8601 con manejo de zona horaria
                          return datetime.datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                      except ValueError:
                          # Si falla el parseo, usar el string directamente como fallback
                          return timestamp_str
                 # Si no es string, usar un valor mínimo seguro para que vaya al final
                 return '1970-01-01T00:00:00+00:00' # Un string ISO válido muy antiguo


            return sorted(
                alerts_to_process,
                key=get_sort_key, # Usar la función de clave que intenta parsear
                reverse=True
            )
        except Exception as e:
            print(f"ERROR ordenando alertas en _get_alerts_sorted_and_filtered: {e}")
            print(traceback.format_exc())
            return alerts_to_process # Devolver sin ordenar si falla


    # --- MÉTODO _save_alerts (PARA GUARDAR ALERTAS EN EL ARCHIVO JSON) ---
    def _save_alerts(self):
        """Guarda la lista actual de alertas en el archivo JSON."""
        print(f"DEBUG: Guardando alertas en {ALERTS_FILE}...")
        try:
            # Asegurar que los objetos datetime se conviertan a string ISO si no lo están ya
            def serialize_datetime(obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                # También convertir tipos numpy si es necesario, aunque generate_alerts debería hacerlo
                # elif isinstance(obj, (np.int64, np.int32)): return int(obj)
                # elif isinstance(obj, (np.float64, np.float32)): return float(obj)
                # ... otros tipos no nativos si es necesario ...
                raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

            with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.alerts, f, indent=4, ensure_ascii=False, default=serialize_datetime) # ensure_ascii=False por si hay caracteres especiales
            print(f"SUCCESS: Alertas guardadas en {ALERTS_FILE}")
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
        # Asegurarse de que alert_id es int para la comparación segura
        try:
            alert_id_int = int(alert_id)
        except (ValueError, TypeError):
            print(f"ERROR: ID de alerta inválido recibido para marcar como revisada: {alert_id}")
            return False # Devolver False si el ID no es válido

        # Iterar y encontrar la alerta por ID
        for alert in self.alerts:
            # Usar .get('id') para acceder al ID de forma segura y comparar con el ID entero
            if isinstance(alert, dict) and alert.get('id') == alert_id_int:
                found = True
                # Usar .get('reviewed', False) para acceder al estado de forma segura
                if not alert.get('reviewed', False): # Si no está ya revisada
                    alert['reviewed'] = True
                    alert_updated = True
                    print(f"INFO: Alerta ID {alert_id_int} marcada como revisada.")
                # else: print(f"INFO: Alerta ID {alert_id_int} ya estaba revisada.") # Opcional
                break # Salir del bucle una vez encontrada la alerta

        if not found:
            print(f"ERROR: No se encontró alerta con ID {alert_id_int} para marcar como revisada.")

        if alert_updated:
            self._save_alerts() # Guardar después de actualizar
            return True
        # Si no se encontró la alerta O ya estaba revisada
        return False


    # --- MÉTODO update_config ---
    def update_config(self, severity_threshold=None, notify_email=None):
        """Actualiza la configuración de alertas."""
        print("INFO: Actualizando configuración de alertas...")
        updated = False
        valid_severities = ['Baja', 'Media', 'Alta', 'Crítica'] # Definir niveles válidos

        # Validar y actualizar severity_threshold
        if severity_threshold is not None:
            if severity_threshold in valid_severities:
                 # Usar .get() para comparar de forma segura
                 if self.config.get('severity_threshold') != severity_threshold:
                     self.config['severity_threshold'] = severity_threshold
                     print(f"SUCCESS: Umbral severidad actualizado a '{severity_threshold}'"); updated = True
            else:
                 print(f"ERROR: Umbral severidad inválido recibido para actualizar: {severity_threshold}. Debe ser uno de: {valid_severities}"); return False # Fallar si es inválido

        # Validar y actualizar notify_email
        if notify_email is not None:
             if isinstance(notify_email, bool):
                 # Usar .get() para comparar de forma segura
                 if self.config.get('notify_email') != notify_email:
                      self.config['notify_email'] = notify_email
                      print(f"SUCCESS: Notificación Email {'Activada' if notify_email else 'Desactivada'}."); updated = True
             else:
                  print(f"ERROR: Valor inválido recibido para notify_email ({notify_email}). Debe ser True o False."); return False # Fallar si es inválido

        # Nota: Configuración no se guarda persistentemente aquí por defecto.
        # Si quisieras persistirla (ej. en un archivo o BD), deberías añadir
        # una llamada a un método _save_config() aquí o manejarlo externamente.
        # Por ahora, solo actualizamos la instancia en memoria.

        if not updated:
            print("INFO: No se realizó ninguna actualización de configuración válida.")

        # Devuelve True si al menos una configuración se actualizó exitosamente
        return updated


    # --- MÉTODO delete_all_alerts ---
    def delete_all_alerts(self):
        """
        Borra TODAS las alertas almacenadas.
        Retorna (bool: success, str: message)
        """
        print("INFO: Borrando TODAS las alertas...")
        try:
            count = len(self.alerts)
            self.alerts = [] # La forma más simple si es una lista en memoria
            self._next_id = 1 # Reiniciar el contador de ID

            # Si usaras una base de datos, aquí ejecutarías: DELETE FROM alerts; y resetear la secuencia de IDs

            self._save_alerts() # Guarda los cambios (lista vacía) en el archivo

            # Opcional: borrar el archivo físico si quieres:
            # if os.path.exists(ALERTS_FILE):
            #     os.remove(ALERTS_FILE)
            #     print(f"INFO: Archivo de alertas '{ALERTS_FILE}' eliminado.")

            print(f"SUCCESS: {count} alertas borradas exitosamente.")
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

# Sección para pruebas directas (opcional)
if __name__ == '__main__':
    print("--- Probando AlertManager ---")
    # Limpiar archivos de prueba si existen de una ejecución anterior
    if os.path.exists(ALERTS_FILE): os.remove(ALERTS_FILE)
    if os.path.exists(DETECTION_HISTORY_FILE): os.remove(DETECTION_HISTORY_FILE)
    os.makedirs(DATA_FOLDER, exist_ok=True) # Asegurar que la carpeta exista

    # Inicializar AlertManager
    alert_manager = AlertManager()

    # --- Prueba de Historial de Detección ---
    print("\n--- Prueba de Historial de Detección ---")
    # Simular entradas de historial (diccionarios serializables)
    history_entry_1 = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "source_info": "Prueba Carga 1",
        "rows_analyzed": 100,
        "model_info": "Modelo Fake v1.0",
        "model_threshold": 0.6,
        "detection_summary": {"BENIGN": 90, "ATTACK": 10},
        "metrics": {"accuracy": 0.95, "report": {"ATTACK": {"precision": 0.8}}},
        "data_head": [{"col1": 1, "col2": "a", "Predicted_Label": "ATTACK"}] # Ejemplo de data_head
    }
    history_entry_2 = {
        "timestamp": (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat(),
        "source_info": "Prueba Sim 1",
        "rows_analyzed": 50,
        "model_info": "Modelo Fake v1.0",
        "model_threshold": 0.6,
        "detection_summary": {"BENIGN": 30, "ATTACK": 20},
        "metrics": {"accuracy": 0.80, "report": {"ATTACK": {"precision": 0.7}}},
         "data_head": [{"col1": 10, "col2": "b", "Predicted_Label": "BENIGN"}]
    }
    history_entry_3 = {
        "timestamp": (datetime.datetime.utcnow() - datetime.timedelta(minutes=2)).isoformat(),
        "source_info": "Prueba Carga 2",
        "rows_analyzed": 200,
        "model_info": "Modelo Fake v1.0",
        "model_threshold": 0.7, # Umbral diferente
        "detection_summary": {"BENIGN": 180, "ATTACK": 20},
        "metrics": {"accuracy": 0.90, "report": {"ATTACK": {"precision": 0.9}}},
         "data_head": [{"col1": 5, "col2": "c", "Predicted_Label": "ATTACK"}]
    }


    alert_manager.add_detection_to_history(history_entry_1)
    alert_manager.add_detection_to_history(history_entry_2)
    alert_manager.add_detection_to_history(history_entry_3)
    # Intentar añadir una entrada duplicada (no debería añadirse si la lógica anti-duplicado funcionara, pero la hemos quitado)
    # alert_manager.add_detection_to_history(history_entry_3) # Esto se añadirá ahora

    print("\nHistorial completo después de añadir:")
    full_history = alert_manager.get_detection_history()
    for entry in full_history:
         print(f"- {entry.get('timestamp', 'N/A')} | {entry.get('source_info', 'N/A')} | Filas: {entry.get('rows_analyzed', 'N/A')} | Ataques: {entry.get('detection_summary', {}).get('ATTACK', 0)}")

    print("\nÚltimas 2 entradas del historial:")
    recent_history = alert_manager.get_detection_history(limit=2)
    for entry in recent_history:
         print(f"- {entry.get('timestamp', 'N/A')} | {entry.get('source_info', 'N/A')}")


    # --- Prueba de Generación y Gestión de Alertas ---
    print("\n--- Prueba de Generación de Alertas ---")

    # Simular un DataFrame de resultados de detección
    simulated_df_results = pd.DataFrame({
        # Asegurarse que las columnas esperadas por generate_alerts existan
        'Src IP': ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6'],
        'Dst IP': ['10.0.0.1', '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.1', '10.0.0.4'],
        'Dst Port': [80, 443, 22, 53, 80, 25],
        'Protocol': ['TCP', 'TCP', 'TCP', 'UDP', 'TCP', 'TCP'],
        'Predicted_Threat_Code': [0, 1, 1, 0, 1, 1],
        'Predicted_Label': ['BENIGN', 'ATTACK', 'ATTACK', 'BENIGN', 'ATTACK', 'ATTACK'], # Etiqueta predicha textual
        'Threat_Probability': [0.1, 0.85, 0.95, 0.2, 0.75, 0.55], # Probabilidad de ataque
        'Label': ['BENIGN', 'ATTACK', 'BENIGN', 'BENIGN', 'ATTACK', 'ATTACK'] # Etiqueta real (si está disponible)
    })

    # Simular el dict de resultados completo que viene de ThreatDetector
    simulated_detector_output = {
        'data': simulated_df_results,
        'model_threshold': 0.7, # Umbral que usó el detector
        'source_info': 'Prueba Simulación de Alertas',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'rows_analyzed': len(simulated_df_results),
        'model_info': 'Dummy Model',
        'detection_summary': simulated_df_results['Predicted_Label'].value_counts().to_dict(),
        'metrics': {'accuracy': 0.8, 'report': {}}, # Métricas de ejemplo
        'data_head': [] # Vista previa vacía para la prueba
    }


    # Generar alertas (con umbral por defecto 'Media')
    print("\nGenerando alertas con umbral de severidad 'Media':")
    new_alert_list_media = alert_manager.generate_alerts(simulated_detector_output)
    print(f"Total de alertas en la lista después de generar: {len(alert_manager.alerts)}")


    # Cambiar umbral de severidad y generar de nuevo (debería generar menos si el umbral sube)
    print("\nCambiando umbral a 'Alta' y generando de nuevo:")
    alert_manager.update_config(severity_threshold='Alta')
    # Nota: generate_alerts no elimina las alertas existentes, solo añade nuevas
    # Aquí simularíamos otra corrida de detección
    simulated_detector_output_2 = simulated_detector_output.copy()
    simulated_detector_output_2['timestamp'] = datetime.datetime.utcnow().isoformat() # Nuevo timestamp
    simulated_detector_output_2['source_info'] = 'Prueba Umbral Alto'
    new_alert_list_high = alert_manager.generate_alerts(simulated_detector_output_2)
    print(f"Total de alertas en la lista después de cambiar umbral: {len(alert_manager.alerts)}")


    print("\n--- Alertas Recientes (Prueba) ---")
    # Obtener las 3 alertas más recientes
    recent_alerts_test = alert_manager.get_recent_alerts(limit=3)
    print(f"Obtenidas {len(recent_alerts_test)} alertas recientes:")
    for alert in recent_alerts_test:
        print(alert)

    print("\n--- Todas las Alertas (Prueba) ---")
    # Obtener todas las alertas
    all_alerts_test = alert_manager.get_all_alerts()
    print(f"Obtenidas {len(all_alerts_test)} alertas totales:")
    for alert in all_alerts_test:
        print(alert)

    print("\n--- Marcar Alerta como Revisada (Prueba) ---")
    # Asumiendo que hay al menos una alerta con ID 1
    if alert_manager.alerts and alert_manager.alerts[0].get('id') == 1:
         success_mark = alert_manager.mark_alert_reviewed(1)
         print(f"Intentando marcar alerta ID 1 como revisada: {'Éxito' if success_mark else 'Falló o ya estaba revisada'}")
         # Verificar en la lista
         alert_id_1_status = next((a.get('reviewed', False) for a in alert_manager.alerts if a.get('id') == 1), False)
         print(f"Estado de revisión de alerta ID 1 después de intentar marcar: {'Revisada' if alert_id_1_status else 'No revisada'}")

    print("\n--- Obtener Alertas No Revisadas (Prueba Opcional) ---")
    unreviewed_alerts_test = alert_manager.get_unreviewed_alerts()
    print(f"Obtenidas {len(unreviewed_alerts_test)} alertas NO revisadas:")
    for alert in unreviewed_alerts_test:
        print(alert)


    print("\n--- Borrar Todas las Alertas (Prueba) ---")
    # Eliminar todas las alertas
    success_delete, delete_msg = alert_manager.delete_all_alerts()
    print(f"Intentando borrar todas las alertas: {'Éxito' if success_delete else 'Falló'}. Mensaje: {delete_msg}")
    print(f"Total de alertas después de borrar: {len(alert_manager.alerts)}")

    print("\n--- Fin de Pruebas de AlertManager ---")