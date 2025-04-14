# threat_detector.py
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
# import joblib # Descomenta si vas a cargar un modelo real

class ThreatDetector:
    """Detecta amenazas usando un modelo de ML (simulado o real)."""

    def __init__(self, model_path=None, threshold=0.7):
        """
        Inicializa el detector.

        Args:
            model_path (str, optional): Ruta al archivo del modelo entrenado (.pkl).
                                        Si es None, se usarán predicciones simuladas.
            threshold (float, optional): Umbral de probabilidad para clasificar como ataque. Defaults to 0.7.
        """
        self.model_path = model_path
        self.model = self._load_model(self.model_path)
        self.threshold = threshold
        self.last_detection_results = None
        self.required_features = None # Opcional: lista de features que el modelo espera
        print(f"INFO: ThreatDetector inicializado. Umbral: {self.threshold}")
        if self.model:
            print(f"INFO: Modelo cargado desde {self.model_path}")
            # Si cargas un modelo real, DEBES saber qué features necesita
            # self.required_features = [...] # Define la lista exacta de columnas/features
        else:
            print("WARNING: No se cargó un modelo real. Se usarán predicciones simuladas.")

    def _load_model(self, model_path):
        """Carga el modelo entrenado (placeholder)."""
        if model_path:
            try:
                # >>> DESCOMENTA Y USA TU LIBRERÍA PARA CARGAR EL MODELO <<<
                # import joblib
                # loaded_model = joblib.load(model_path)
                loaded_model = "MODELO_CARGADO_SIMULADO" # Placeholder
                # <<< FIN SECCIÓN MODELO REAL >>>
                print(f"PLACEHOLDER: Simulación de carga de modelo desde {model_path}")
                return loaded_model
            except FileNotFoundError:
                 print(f"ERROR: Archivo de modelo no encontrado en '{model_path}'")
                 return None
            except Exception as e:
                print(f"ERROR: No se pudo cargar el modelo desde {model_path}: {e}")
                return None
        return None

    def set_threshold(self, new_threshold):
         """Actualiza el umbral de decisión."""
         try:
             threshold_float = float(new_threshold)
             if 0.0 < threshold_float < 1.0:
                 self.threshold = threshold_float
                 print(f"INFO: Umbral de decisión actualizado a {self.threshold:.3f}")
                 return True
             else:
                 print("ERROR: El umbral debe estar entre 0 y 1.")
                 return False
         except (ValueError, TypeError):
              print(f"ERROR: Umbral inválido '{new_threshold}'. Debe ser un número.")
              return False

    def run_detection(self, df_input):
        """
        Ejecuta la detección en el DataFrame de entrada preprocesado.

        Args:
            df_input (pd.DataFrame): DataFrame con los datos ya preprocesados.

        Returns:
            dict: Un diccionario con {'data': df_resultado, 'metrics': metrics_dict}
                  o None si ocurre un error grave.
        """
        if df_input is None or df_input.empty:
            print("ERROR: DataFrame de entrada para detección está vacío o no es válido.")
            return None

        print(f"INFO: Ejecutando detección en {len(df_input)} registros...")
        df_detection = df_input.copy() # Trabajar sobre una copia

        # --- Preparación de Features para el Modelo ---
        # DEBES asegurarte de que df_detection contenga EXACTAMENTE las features
        # que tu modelo espera, en el orden correcto si es necesario.
        features_for_model = df_detection.copy()

        # Intentar eliminar la columna 'label' si existe y no es una feature del modelo
        if 'label' in features_for_model.columns:
             try:
                 # Guarda la etiqueta real para calcular métricas
                 y_true_real = (features_for_model['label'].astype(str).str.upper() != 'BENIGN').astype(int)
                 print("INFO: Etiquetas reales 'label' encontradas para cálculo de métricas.")
                 # Elimina 'label' SOLO si NO es una de las features que necesita el modelo
                 # Si 'label' ES una feature, comenta la siguiente línea
                 # features_for_model = features_for_model.drop(columns=['label'])
             except Exception as e:
                  print(f"WARNING: Error procesando columna 'label': {e}. Se intentará continuar sin ella.")
                  y_true_real = None
        else:
            print("WARNING: No se encontró columna 'label'. No se calcularán métricas de rendimiento.")
            y_true_real = None

        # Si tienes una lista definida de features requeridas:
        if self.required_features:
             missing_features = [f for f in self.required_features if f not in features_for_model.columns]
             if missing_features:
                 print(f"ERROR: Faltan features requeridas por el modelo: {missing_features}")
                 return None
             extra_features = [f for f in features_for_model.columns if f not in self.required_features]
             if extra_features:
                 print(f"INFO: Eliminando features no requeridas por el modelo: {extra_features}")
                 features_for_model = features_for_model[self.required_features] # Selecciona solo las necesarias

        # --- Predicción ---
        predicciones_clase = None
        if self.model:
            print(f"INFO: Usando modelo '{type(self.model).__name__}' cargado para predicciones...")
            # --- Lógica REAL de predicción ---
            try:
                # >>> DESCOMENTA Y AJUSTA SEGÚN TU MODELO REAL <<<
                # # Asegúrate que 'features_for_model' esté lista (escalada, etc. si es necesario)
                # if hasattr(self.model, 'predict_proba'):
                #      # Para modelos que dan probabilidad (GLM, LogReg, RandomForest, etc.)
                #      probabilidades = self.model.predict_proba(features_for_model)[:, 1] # Probabilidad de clase 1 (Ataque)
                #      predicciones_clase = (probabilidades >= self.threshold).astype(int)
                # elif hasattr(self.model, 'predict'):
                #      # Para modelos que dan predicción directa (SVM, etc.) - umbral no aplica igual
                #      predicciones_clase = self.model.predict(features_for_model)
                #      # Asegúrate que la salida sea 0 o 1, o conviértela si es necesario
                # else:
                #      print("ERROR: Modelo cargado no tiene método 'predict' o 'predict_proba'.")
                #      raise NotImplementedError("Tipo de modelo no soportado")

                # --- SIMULACIÓN TEMPORAL ---
                print("WARNING: Usando predicciones SIMULADAS porque la lógica del modelo real está comentada.")
                predicciones_clase = np.random.choice([0, 1], size=len(features_for_model), p=[0.9, 0.1])
                # --- FIN SIMULACIÓN TEMPORAL ---

                print("SUCCESS: Predicciones del modelo generadas.")

            except Exception as e:
                print(f"ERROR: Falló la predicción con el modelo: {e}")
                import traceback
                print(traceback.format_exc())
                # Fallback a simulación si el modelo real falla podría ser una opción
                # predicciones_clase = np.random.choice([0, 1], size=len(features_for_model), p=[0.95, 0.05])
                return None # O fallar si el modelo es esencial

        else:
            # --- Simulación de predicciones (si no hay modelo) ---
            print("INFO: Usando predicciones SIMULADAS porque no hay modelo cargado.")
            if y_true_real is not None:
                 # Simular algo de "inteligencia": predecir correctamente el 95% de benignos y el 85% de ataques
                 predicciones_clase_list = []
                 for true_label in y_true_real:
                      if true_label == 0: # Benigno
                           predicciones_clase_list.append(0 if np.random.rand() < 0.95 else 1)
                      else: # Ataque
                           predicciones_clase_list.append(1 if np.random.rand() < 0.85 else 0)
                 predicciones_clase = np.array(predicciones_clase_list)
            else:
                 # Simulación simple si no hay etiquetas reales
                 predicciones_clase = np.random.choice([0, 1], size=len(features_for_model), p=[0.9, 0.1])

        # --- Ensamblar Resultados y Calcular Métricas ---
        if predicciones_clase is None:
             print("ERROR: No se pudieron generar las predicciones.")
             return None

        # Usar el df original de entrada para añadir resultados, no el 'features_for_model'
        df_resultado = df_input.copy()
        df_resultado['prediction_attack'] = predicciones_clase
        df_resultado['prediction_label'] = np.where(predicciones_clase == 1, 'ATTACK', 'BENIGN')

        print("INFO: Predicciones asignadas.")
        print("Distribución de predicciones:")
        print(df_resultado['prediction_label'].value_counts())

        metrics = {"accuracy": None, "report": None, "confusion_matrix": None}
        if y_true_real is not None:
            try:
                # Calcular métricas solo si tenemos etiquetas reales y predicciones
                accuracy = accuracy_score(y_true_real, predicciones_clase)
                report = classification_report(y_true_real, predicciones_clase, target_names=['BENIGN', 'ATTACK'], output_dict=True, zero_division=0)
                cm = confusion_matrix(y_true_real, predicciones_clase)

                metrics["accuracy"] = accuracy
                metrics["report"] = report
                metrics["confusion_matrix"] = cm.tolist() # Convertir a lista para JSON/Jinja2

                print(f"SUCCESS: Métricas calculadas. Accuracy: {accuracy:.4f}")
            except Exception as e:
                print(f"WARNING: No se pudieron calcular métricas detalladas: {e}")
        else:
             print("INFO: No se calcularon métricas por falta de etiquetas reales.")

        self.last_detection_results = {"data": df_resultado, "metrics": metrics}
        return self.last_detection_results