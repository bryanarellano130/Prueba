# alert_manager.py
import datetime
import json
import os
import pandas as pd # Necesario si se inspecciona el DataFrame directamente
import traceback

ALERTS_FILE = "alerts_data.json" # Archivo para guardar/cargar las alertas

class AlertManager:
    """
    Gestiona la generación, visualización, estado y persistencia de las alertas.
    """

    def __init__(self, config_defaults=None):
        """
        Inicializa el gestor de alertas, cargando alertas existentes si las hay.

        Args:
            config_defaults (dict, optional): Valores por defecto para la configuración.
                                             Defaults to {'severity_threshold': 'Media', 'notify_email': False}.
        """
        self.alerts = []
        self.config = config_defaults if config_defaults else {
            'severity_threshold': 'Media',
            'notify_email': False
        }
        self._next_id = 1 # Para asignar IDs únicos a las alertas
        self._load_alerts() # Cargar alertas al iniciar
        print("INFO: AlertManager inicializado.")
        print(f"INFO: Configuración inicial de alertas: {self.config}")
        # Evitar imprimir miles de alertas si el archivo es grande
        print(f"INFO: {len(self.alerts)} alertas cargadas. Próximo ID: {self._next_id}")


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

    def _save_alerts(self):
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

        potential_attacks = detection_results_df[detection_results_df['prediction_label'] == 'ATTACK']
        new_alerts_list = [] # Lista para guardar solo las nuevas de esta ejecución
        print(f"INFO: Analizando {len(potential_attacks)} detecciones de posibles ataques...")

        severity_map = {'DDoS': 'Alta', 'Scan': 'Media', 'Malware': 'Crítica', 'PortScan':'Media', 'ATTACK': 'Media', 'Infiltration': 'Alta'} # Añadido Infiltration
        severity_levels = {'Baja': 1, 'Media': 2, 'Alta': 3, 'Crítica': 4}
        threshold_level = severity_levels.get(self.config['severity_threshold'], 1)

        for index, row in potential_attacks.iterrows():
            attack_type_detected = row.get('label', 'ATTACK')
            if attack_type_detected == 'BENIGN':
                attack_type_display = "Unknown (ML Trigger)"
                severity = severity_map.get('ATTACK', 'Media')
            else:
                 attack_type_display = attack_type_detected
                 severity = severity_map.get(attack_type_display, 'Media')

            current_severity_level = severity_levels.get(severity, 1)

            if current_severity_level >= threshold_level:
                alert = {
                    "id": self._next_id,
                    "timestamp": datetime.datetime.now().isoformat(timespec='seconds'),
                    "type": f"Amenaza Detectada ({attack_type_display})",
                    "severity": severity,
                    "details": f"SRC: {row.get('src_ip', 'N/A')}, DST: {row.get('dst_ip', 'N/A')}, Proto: {row.get('protocol', 'N/A')}",
                    "reviewed": False
                }
                self.alerts.append(alert) # Añadir a la lista principal
                new_alerts_list.append(alert) # Añadir a la lista de nuevas
                self._next_id += 1

                if self.config['notify_email']:
                    print(f"SIMULACION EMAIL [{severity.upper()}]: {alert['type']} - {alert['details']}")

        new_alerts_count = len(new_alerts_list)
        if new_alerts_count > 0:
            print(f"INFO: {new_alerts_count} nuevas alertas generadas (cumpliendo umbral '{self.config['severity_threshold']}').")
            self._save_alerts()
            return new_alerts_count, new_alerts_list # Devolver conteo y lista
        else:
            print(f"INFO: No se generaron nuevas alertas que cumplan el umbral '{self.config['severity_threshold']}'.")
            return 0, [] # Devolver 0 y lista vacía

    def get_alerts(self, show_all=False):
        """Devuelve la lista de alertas (ordenadas, más recientes primero)."""
        alerts_to_sort = self.alerts
        if not show_all:
            alerts_to_sort = [a for a in self.alerts if not a.get('reviewed', False)]
        # Ordenar por timestamp descendente (más reciente primero)
        # Manejar casos donde timestamp podría faltar o ser inválido
        return sorted(
            alerts_to_sort,
            key=lambda x: x.get('timestamp', '1970-01-01T00:00:00'),
            reverse=True
        )

    def mark_alert_reviewed(self, alert_id):
        """Marca una alerta específica como revisada por su ID."""
        alert_updated = False
        found = False
        for alert in self.alerts:
            if alert.get('id') == alert_id:
                found = True
                if not alert.get('reviewed', False):
                    alert['reviewed'] = True
                    alert_updated = True
                    print(f"INFO: Alerta ID {alert_id} marcada como revisada.")
                # else: print(f"INFO: Alerta ID {alert_id} ya estaba revisada.") # Opcional
                break
        if not found: print(f"ERROR: No se encontró alerta con ID {alert_id}.")
        if alert_updated: self._save_alerts(); return True
        return False

    def update_config(self, severity_threshold=None, notify_email=None):
        """Actualiza la configuración de alertas."""
        updated = False
        valid_severities = ['Baja', 'Media', 'Alta', 'Crítica']
        if severity_threshold is not None and severity_threshold in valid_severities:
            if self.config['severity_threshold'] != severity_threshold:
                self.config['severity_threshold'] = severity_threshold
                print(f"INFO: Umbral severidad actualizado a '{severity_threshold}'"); updated = True
        elif severity_threshold is not None: print(f"ERROR: Umbral severidad inválido: {severity_threshold}"); return False

        if notify_email is not None and isinstance(notify_email, bool):
             if self.config['notify_email'] != notify_email:
                self.config['notify_email'] = notify_email
                print(f"INFO: Notificación Email {'Activada' if notify_email else 'Desactivada'}."); updated = True
        elif notify_email is not None: print("ERROR: Valor inválido para notify_email (debe ser true/false)"); return False

        # Nota: Configuración no se guarda persistentemente aquí.
        return updated

    def manage_rules(self):
        """Gestiona reglas de seguridad (Placeholder)."""
        print("INFO: Accediendo a gestión de reglas (Placeholder).")
        return "Funcionalidad de gestión de reglas no implementada."