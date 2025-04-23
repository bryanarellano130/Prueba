# threat_detector.py
import os
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.exceptions import NotFittedError
import joblib # Asegúrate de que esté importado
import traceback
import datetime # Importar datetime para timestamps

# --- Constantes (Usadas como valores por defecto o referencia si no se pasan objetos) ---
# Estas constantes se usarán si los objetos 'model'/'scaler' NO se pasan directamente
# al __init__ (aunque la lógica actual de app.py los pasa).
# Son útiles si inicializas el detector sin pasar objetos, o para la lógica de reload.
MODEL_FOLDER = 'modelo' # Carpeta donde están el modelo y el scaler por defecto
MODEL_FILENAME = 'modelo_glm.joblib' # Nombre del archivo del modelo por defecto
SCALER_FILENAME = 'scaler.joblib' # Nombre del archivo del scaler por defecto

# ¡¡IMPORTANTE!! Define aquí las features EXACTAS que tu modelo espera, en el orden correcto si es necesario.
# Deben coincidir con las usadas para entrenar el modelo y el scaler.
# AJUSTA ESTO según tus datos reales.
REQUIRED_FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Max'] # EJEMPLO: Sustituye con tus features reales
NUMERIC_FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Max'] # EJEMPLO: Sustituye con tus features numéricas reales

# Nombre de la columna objetivo en tus datos originales (para calcular métricas)
TARGET_LABEL_COLUMN = 'Label' # O 'label', 'target', etc. - AJUSTA ESTO


class ThreatDetector:
    """Detecta amenazas usando un modelo de ML y scaler cargados."""

    # --- MODIFICADO: Ahora acepta 'model' y 'scaler' como argumentos principales ---
    def __init__(self, model=None, scaler=None, prediction_threshold=0.7):
        """
        Inicializa el detector. Recibe opcionalmente los objetos modelo y scaler cargados.

        Args:
            model (object, optional): Objeto del modelo entrenado (ej. scikit-learn model).
                                      Si es None, se intentará cargar desde la ruta por defecto.
            scaler (object, optional): Objeto del scaler ajustado (ej. StandardScaler).
                                       Si es None, se intentará cargar desde la ruta por defecto.
            prediction_threshold (float, optional): Umbral de probabilidad para clasificar como ataque (solo si el modelo da probabilidades). Defaults to 0.7.
        """
        self.model = model # Almacenar el objeto modelo pasado
        self.scaler = scaler # Almacenar el objeto scaler pasado

        # Si los objetos no fueron pasados, intentar cargarlos desde las rutas por defecto
        if self.model is None or self.scaler is None:
             print("INFO: Modelo y/o Scaler no pasados al inicializar. Intentando cargar desde archivos por defecto...")
             self._load_model_and_scaler_from_default_paths()


        # Validar si el scaler cargado/pasado parece ajustado
        if self.scaler and not hasattr(self.scaler, 'scale_') and not hasattr(self.scaler, 'mean_'):
             print("ERROR: El scaler cargado/pasado no parece estar ajustado (no tiene atributos 'scale_' o 'mean_'). Invalidando scaler.")
             self.scaler = None # Invalidar si no está ajustado

        self.required_features = REQUIRED_FEATURES # Usar la constante definida arriba
        self.numeric_features = NUMERIC_FEATURES # Usar la constante definida arriba
        self.target_label_column = TARGET_LABEL_COLUMN # Usar la constante

        self.prediction_threshold = prediction_threshold
        self.last_detection_results = None

        print(f"INFO: ThreatDetector inicializado. Umbral: {self.prediction_threshold}")
        if self.model and self.scaler:
            print(f"INFO: Modelo ({type(self.model).__name__}) y Scaler ({type(self.scaler).__name__}) listos.")
        else:
            print("WARNING: Modelo y/o Scaler NO están cargados/listos después de la inicialización.")
            print("WARNING: La detección no funcionará hasta que se carguen/reentrenen y estén listos.")

    # --- MODIFICADO: Intenta cargar desde rutas por defecto si no se pasaron objetos ---
    def _load_model_and_scaler_from_default_paths(self):
        """Carga el modelo y el scaler desde las rutas por defecto si no se pasaron objetos."""
        base_dir = os.path.abspath(os.path.dirname(__file__)) # Directorio actual de threat_detector.py
        default_model_path = os.path.join(base_dir, MODEL_FOLDER, MODEL_FILENAME)
        default_scaler_path = os.path.join(base_dir, MODEL_FOLDER, SCALER_FILENAME)

        print(f"DEBUG: Intentando cargar modelo desde ruta por defecto: {default_model_path}")
        try:
            if os.path.exists(default_model_path):
                self.model = joblib.load(default_model_path)
                print(f"SUCCESS: Modelo ({type(self.model).__name__}) cargado desde {default_model_path}")
            else:
                print(f"ERROR: Archivo de modelo por defecto NO encontrado en '{default_model_path}'")
                self.model = None
        except Exception as e:
            print(f"ERROR: No se pudo cargar el modelo desde {default_model_path}: {e}")
            print(traceback.format_exc())
            self.model = None

        print(f"DEBUG: Intentando cargar scaler desde ruta por defecto: {default_scaler_path}")
        try:
            if os.path.exists(default_scaler_path):
                self.scaler = joblib.load(default_scaler_path)
                print(f"SUCCESS: Scaler ({type(self.scaler).__name__}) cargado desde {default_scaler_path}")
                # Comprobar si el scaler está ajustado (tiene atributos como 'scale_')
                if not hasattr(self.scaler, 'scale_') and not hasattr(self.scaler, 'mean_'):
                     print("ERROR: El scaler por defecto cargado no parece estar ajustado. Invalidando scaler.")
                     self.scaler = None # Invalidar si no está ajustado
            else:
                print(f"ERROR: Archivo de scaler por defecto NO encontrado en '{default_scaler_path}'")
                self.scaler = None
        except Exception as e:
            print(f"ERROR: No se pudo cargar el scaler desde {default_scaler_path}: {e}")
            print(traceback.format_exc())
            self.scaler = None

    # --- MODIFICADO: Métodos para cargar específicos, llamados por app.py después de reload ---
    def load_model(self, model_path):
         """Carga un modelo desde una ruta específica."""
         print(f"INFO: ThreatDetector cargando modelo desde {model_path}...")
         try:
             if os.path.exists(model_path):
                 self.model = joblib.load(model_path)
                 print(f"SUCCESS: Modelo ({type(self.model).__name__}) cargado.")
                 return True
             else:
                 print(f"ERROR: Archivo de modelo NO encontrado en '{model_path}'.")
                 self.model = None
                 return False
         except Exception as e:
             print(f"ERROR: No se pudo cargar el modelo desde {model_path}: {e}")
             print(traceback.format_exc())
             self.model = None
             return False

    def load_scaler(self, scaler_path):
         """Carga un scaler desde una ruta específica."""
         print(f"INFO: ThreatDetector cargando scaler desde {scaler_path}...")
         try:
             if os.path.exists(scaler_path):
                 self.scaler = joblib.load(scaler_path)
                 print(f"SUCCESS: Scaler ({type(self.scaler).__name__}) cargado.")
                 # Validar si parece ajustado
                 if not hasattr(self.scaler, 'scale_') and not hasattr(self.scaler, 'mean_'):
                      print("ERROR: El scaler cargado no parece estar ajustado. Invalidando scaler.")
                      self.scaler = None # Invalidar si no está ajustado
                      return False # Falló la carga efectiva
                 return True
             else:
                 print(f"ERROR: Archivo de scaler NO encontrado en '{scaler_path}'.")
                 self.scaler = None
                 return False
         except Exception as e:
             print(f"ERROR: No se pudo cargar el scaler desde {scaler_path}: {e}")
             print(traceback.format_exc())
             self.scaler = None
             return False

    # --- MODIFICADO: reload_model ahora solo llama a los métodos de carga específicos ---
    def reload_model(self, model_path=None, scaler_path=None):
        """
        Recarga el modelo y el scaler. Útil después de reentrenar.
        Args:
            model_path (str, optional): Nueva ruta al archivo del modelo. Si es None, usa la ruta por defecto calculada.
            scaler_path (str, optional): Nueva ruta al archivo del scaler. Si es None, usa la ruta por defecto calculada.
        """
        print("INFO: Iniciando recarga de modelo y scaler...")

        # Si no se especifican rutas, usar las rutas por defecto para la recarga
        if model_path is None:
             base_dir = os.path.abspath(os.path.dirname(__file__))
             model_path = os.path.join(base_dir, MODEL_FOLDER, MODEL_FILENAME)
        if scaler_path is None:
             base_dir = os.path.abspath(os.path.dirname(__file__))
             scaler_path = os.path.join(base_dir, MODEL_FOLDER, SCALER_FILENAME)


        model_success = self.load_model(model_path)
        scaler_success = self.load_scaler(scaler_path) # Cargar scaler desde su path específico

        if model_success and scaler_success:
            print("SUCCESS: Modelo y scaler recargados exitosamente.")
            return True
        else:
            print("ERROR: Falló la recarga del modelo y/o scaler.")
            return False


    def is_model_loaded(self):
        """Verifica si el modelo está cargado."""
        # Asegurarse que el objeto modelo existe Y parece un modelo de scikit-learn (opcional pero útil)
        return self.model is not None #and hasattr(self.model, 'predict')

    def is_scaler_loaded(self):
        """Verifica si el scaler está cargado y ajustado."""
        # Asegurarse que el objeto scaler existe Y parece un scaler ajustado
        return self.scaler is not None and (hasattr(self.scaler, 'scale_') or hasattr(self.scaler, 'mean_')) # Verificar atributos de ajuste

    def get_config(self):
         """Retorna la configuración actual del detector."""
         return {
             'prediction_threshold': self.prediction_threshold,
             'model_loaded': self.is_model_loaded(),
             'scaler_loaded': self.is_scaler_loaded(),
             'model_type': type(self.model).__name__ if self.model else "N/A",
             'scaler_type': type(self.scaler).__name__ if self.scaler else "N/A",
             # Puedes añadir aquí rutas si quieres mostrarlas, aunque la carga se base en objetos
             # 'model_path': self.model_path, # Si aún mantienes los paths internamente
             # 'scaler_path': self.scaler_path
         }

    def update_config(self, config_dict):
         """Actualiza la configuración del detector desde un diccionario."""
         print("INFO: Actualizando configuración del Detector...")
         updated = False
         if 'detection_threshold' in config_dict:
              try:
                  new_threshold = float(config_dict['detection_threshold'])
                  if 0.0 <= new_threshold <= 1.0: # Permitir 0 y 1 en la configuración
                      self.prediction_threshold = new_threshold
                      print(f"SUCCESS: Umbral de decisión actualizado a {self.prediction_threshold:.4f}")
                      updated = True
                  else:
                       print(f"WARNING: Valor de umbral fuera del rango [0, 1]: {new_threshold}")
              except (ValueError, TypeError):
                   print(f"WARNING: Valor de umbral inválido recibido: {config_dict['detection_threshold']}")

         # Puedes añadir lógica para actualizar otros parámetros si los tienes
         # ej: if 'some_param' in config_dict: self.some_param = config_dict['some_param']

         if not updated:
              print("INFO: No se realizó ninguna actualización de configuración válida.")
         return self.get_config() # Retornar la configuración actual después de intentar actualizar


    def get_model_info(self):
         """Retorna información sobre el modelo y scaler cargados."""
         model_type = type(self.model).__name__ if self.model else "No cargado"
         scaler_type = type(self.scaler).__name__ if self.scaler else "No cargado"
         scaler_fitted = "Sí" if self.is_scaler_loaded() else "No" # is_scaler_loaded ya verifica si está ajustado

         info = {
             "Model Type": model_type,
             "Scaler Type": scaler_type,
             "Scaler Fitted": scaler_fitted,
             "Prediction Threshold": f"{self.prediction_threshold:.4f}"
             # Puedes añadir más detalles aquí si son relevantes
         }
         return info

    # --- MODIFICADO: run_detection ahora recibe el DataFrame ya cargado por DataManager ---
    def detect_threats(self, filepath_or_df):
        """
        Preprocesa y ejecuta la detección en los datos. Acepta una ruta de archivo o un DataFrame.

        Args:
            filepath_or_df (str or pd.DataFrame): Ruta al archivo CSV O un DataFrame ya cargado.

        Returns:
            dict: Un diccionario con los resultados de la detección (resumen, métricas, vista previa de datos)
                  o None si ocurre un error grave.
        """
        df_original = None # Para mantener una referencia a los datos originales o cargados
        filepath = None # Para mantener la ruta si se carga desde archivo

        # --- Cargar datos si se proporciona una ruta ---
        if isinstance(filepath_or_df, str):
            filepath = filepath_or_df
            if not os.path.exists(filepath):
                 print(f"ERROR: Archivo de datos no encontrado: {filepath}")
                 return {"error": f"Archivo de datos no encontrado: {os.path.basename(filepath)}"}
            try:
                print(f"DEBUG: ThreatDetector cargando datos desde archivo: {filepath}")
                df_original = pd.read_csv(filepath, low_memory=False)
                print(f"INFO: Datos cargados: {len(df_original)} filas.")
            except Exception as e:
                print(f"ERROR: No se pudo cargar el archivo de datos '{filepath}': {e}")
                print(traceback.format_exc())
                return {"error": f"Error al cargar archivo de datos: {e}"}
        elif isinstance(filepath_or_df, pd.DataFrame):
            print("DEBUG: ThreatDetector recibiendo DataFrame directamente.")
            df_original = filepath_or_df.copy() # Trabajar en una copia para no modificar el original
        else:
            print("ERROR: Entrada inválida para detect_threats. Debe ser ruta (str) o DataFrame.")
            return {"error": "Formato de datos de entrada inválido."}

        if df_original is None or df_original.empty:
             print("ERROR: DataFrame de entrada para detección está vacío o no se pudo cargar.")
             return {"error": "No hay datos válidos para analizar."}


        # --- Comprobación Crítica: Modelo y Scaler deben estar cargados y listos ---
        if not self.is_model_loaded() or not self.is_scaler_loaded():
             print("ERROR: Modelo y/o Scaler no están cargados y ajustados. No se puede ejecutar la detección.")
             return {"error": "Modelo y/o Scaler no cargados o no ajustados. Entrene o cargue un modelo válido."}


        print(f"INFO: Ejecutando detección en {len(df_original)} registros...")
        df_detection = df_original.copy() # Trabajar sobre una copia que podremos modificar

        # --- Preprocesamiento y Preparación de Features ---
        # (Basado en la lógica de limpieza de data_model.py que corregimos antes)
        print("DEBUG: Aplicando preprocesamiento a los datos...")

        # 1. Intentar convertir columnas a numéricas y manejar errores/NaNs
        #    Asumimos que las columnas que deberían ser numéricas están en self.required_features
        #    Si hay otras columnas no numéricas que no deben ser usadas, se excluirán más adelante.
        for col in self.required_features:
            if col in df_detection.columns:
                # Intentar convertir la columna a numérica. 'errors='coerce''
                # reemplazará cualquier valor que no se pueda convertir por NaN.
                df_detection[col] = pd.to_numeric(df_detection[col], errors='coerce')

                # Si la columna es una de las numéricas requeridas, rellenar NaNs
                if col in self.numeric_features:
                     if pd.api.types.is_numeric_dtype(df_detection[col]):
                         # Calcular la media *después* de la conversión y coercing
                         mean_val = df_detection[col].mean()
                         if pd.isna(mean_val): # Si la media es NaN (columna entera era no numérica)
                             print(f"ADVERTENCIA: Columna numérica requerida '{col}' es completamente NaN después de coerción. Llenando NaN con 0.")
                             df_detection[col].fillna(0, inplace=True)
                         else:
                              # Llenar NaN con la media calculada
                             df_detection[col].fillna(mean_val, inplace=True)
                     else:
                          print(f"ERROR: Columna requerida '{col}' ({df_detection[col].dtype}) no es numérica después de coerción. No se puede escalar.")
                          # Esto es un error grave si es una columna numérica requerida.
                          return {"error": f"Columna de característica requerida '{col}' no es numérica."}
            # else: # La comprobación de features faltantes se hace más abajo


        # 2. Extraer etiquetas reales (si existen) ANTES de seleccionar/escalar X
        y_true_real = None
        if self.target_label_column in df_detection.columns:
             try:
                  # Intentar convertir la columna a string primero para manejar varios formatos
                  # Asumir que 1/ATTACK es la clase positiva, 0/BENIGN la negativa
                  # Cualquier valor que no sea 'BENIGN' (insensible a mayúsculas/minúsculas) se considera 1 (ATTACK)
                  y_true_real = (df_detection[self.target_label_column].astype(str).str.upper() != 'BENIGN').astype(int)
                  print(f"INFO: Etiquetas reales '{self.target_label_column}' encontradas para cálculo de métricas ({y_true_real.sum()} ataques).")
                  # Opcional: Eliminar la columna original de etiquetas del df_detection para no escalarla
                  df_detection = df_detection.drop(columns=[self.target_label_column])
             except Exception as e:
                  print(f"WARNING: Error procesando columna de etiquetas '{self.target_label_column}': {e}. No se calcularán métricas.")
                  print(traceback.format_exc())
                  y_true_real = None
        else:
            print(f"INFO: No se encontró columna de etiquetas '{self.target_label_column}'. No se calcularán métricas de rendimiento.")


        # 3. Seleccionar SOLO las features requeridas y en el orden correcto
        #    Esto crea el DataFrame X que se pasará al scaler y al modelo.
        try:
             # Verificar de nuevo si TODAS las REQUIRED_FEATURES están presentes después del preprocesamiento
             missing_features_final = [f for f in self.required_features if f not in df_detection.columns]
             if missing_features_final:
                 print(f"ERROR: Faltan features requeridas después del preprocesamiento: {missing_features_final}")
                 print(f"       Columnas presentes en df_detection: {list(df_detection.columns)}")
                 return {"error": f"Faltan columnas de características requeridas: {missing_features_final}"}

             X_for_model_unscaled = df_detection[self.required_features].copy()
             print(f"DEBUG: Features seleccionadas para el modelo: {list(X_for_model_unscaled.columns)}")

        except KeyError:
             print(f"ERROR: Fallo al seleccionar las features requeridas. Verifica REQUIRED_FEATURES y los datos.")
             return {"error": "Error interno al seleccionar características."}

        if X_for_model_unscaled.empty:
             print("WARN: El DataFrame de características está vacío después de la selección.")
             return {"warning": "No hay datos de características válidas para analizar."}

        # 4. Escalar las features numéricas usando el scaler CARGADO
        #    Aplicar transform SOLO a las columnas numéricas ESPECIFICADAS
        X_scaled = X_for_model_unscaled.copy() # Copia para no modificar el DataFrame original de features
        print(f"DEBUG: Aplicando scaler a columnas numéricas: {self.numeric_features}")
        try:
             # Verificar que las columnas numéricas requeridas estén presentes en X_scaled
             numeric_cols_present_in_X = [col for col in self.numeric_features if col in X_scaled.columns]
             if len(numeric_cols_present_in_X) != len(self.numeric_features):
                  missing_numeric_in_X = list(set(self.numeric_features) - set(numeric_cols_present_in_X))
                  print(f"ERROR: Faltan columnas numéricas requeridas para el escalado en el DataFrame de features: {missing_numeric_in_X}")
                  return {"error": f"Faltan columnas numéricas para el escalado: {missing_numeric_in_X}"}

             # Asegurarse que las columnas numéricas tengan tipo numérico antes de escalar
             for col in numeric_cols_present_in_X:
                 if not pd.api.types.is_numeric_dtype(X_scaled[col]):
                      print(f"ERROR: La columna numérica '{col}' no es de tipo numérico antes de escalar.")
                      return {"error": f"La columna numérica '{col}' no tiene el tipo de dato correcto."}


             # Aplicar transform SOLO a las columnas numéricas presentes en la lista NUMERIC_FEATURES
             # Esto genera un array numpy
             X_scaled_array = self.scaler.transform(X_scaled[numeric_cols_present_in_X])

             # Reemplazar solo las columnas numéricas escaladas en el DataFrame X_scaled
             # Esto es importante si tienes columnas no numéricas que no se escalan (aunque en este caso, seleccionamos solo numeric_features)
             # Una forma más simple si solo usas NUMERIC_FEATURES es simplemente usar X_scaled_array
             # Si tus REQUIRED_FEATURES incluyen no numéricas, necesitarías un ColumnTransformer
             # Asumiendo por ahora que REQUIRED_FEATURES y NUMERIC_FEATURES son lo mismo para el escalado:
             if len(self.required_features) != len(self.numeric_features) or set(self.required_features) != set(self.numeric_features):
                  print("WARNING: REQUIRED_FEATURES y NUMERIC_FEATURES son diferentes o su orden puede no coincidir.")
                  print("WARNING: El escalado se aplica SOLO a NUMERIC_FEATURES.")
                  print("WARNING: Si tu modelo espera features no escaladas o en un orden específico con no numéricas, necesitarás un ColumnTransformer.")
                  # Si tienes un ColumnTransformer, aplícalo aquí en lugar de scaler.transform
                  # X_scaled_final = self.column_transformer.transform(X_for_model_unscaled)
                  # Para este código, asumimos que el modelo espera SOLO las NUMERIC_FEATURES escaladas,
                  # por lo que pasaremos X_scaled_array directamente al modelo.
                  features_for_prediction = X_scaled_array
                  # Comprobar el número de features esperadas por el modelo si es posible
                  # if hasattr(self.model, 'n_features_in_') and self.model.n_features_in_ != features_for_prediction.shape[1]:
                  #     print(f"ERROR: El modelo espera {self.model.n_features_in_} features, pero se pasaron {features_for_prediction.shape[1]}.")
                  #     return {"error": "El número de características escaladas no coincide con lo esperado por el modelo."}

             else:
                  # Si REQUIRED_FEATURES == NUMERIC_FEATURES (para el escalado)
                  # El array escalado tiene el mismo número de columnas
                  features_for_prediction = X_scaled_array # Usar el array NumPy directo

             print("SUCCESS: Features numéricas escaladas.")


        except NotFittedError:
             print("ERROR CRÍTICO: El scaler cargado no está ajustado ('fitted'). Reentrena o carga un scaler válido.")
             return {"error": "Scaler no ajustado. Entrene el modelo."}
        except ValueError as e_transform:
             print(f"ERROR: Error de Valor al aplicar scaler.transform: {e_transform}.")
             print("       ¿Las columnas numéricas o su orden coinciden con las usadas para ajustar el scaler?")
             print(f"       Columnas pasadas al scaler.transform: {numeric_cols_present_in_X}")
             print(traceback.format_exc())
             return {"error": f"Error al escalar datos: {e_transform}. Verifica features y scaler."}
        except Exception as e_scale:
             print(f"ERROR: Error inesperado durante el escalado: {e_scale}")
             print(traceback.format_exc())
             return {"error": f"Error inesperado durante el escalado: {e_scale}"}


        # --- Predicción ---
        probabilidades = None
        predicciones_clase = None
        print(f"INFO: Usando modelo '{type(self.model).__name__}' cargado para predicciones...")
        try:
            if hasattr(self.model, 'predict_proba'):
                # Para modelos que dan probabilidad (GLM, LogReg, RandomForest, etc.)
                # Asegúrate de que el modelo da probabilidades para 2 clases
                if self.model.predict_proba(features_for_prediction).shape[1] >= 2:
                     probabilidades = self.model.predict_proba(features_for_prediction)[:, 1] # Probabilidad de clase 1 (Ataque)
                     predicciones_clase = (probabilidades >= self.prediction_threshold).astype(int)
                     print(f"SUCCESS: Predicciones generadas usando predict_proba y umbral {self.prediction_threshold:.4f}.")
                else:
                     print("ERROR: El modelo predict_proba no devuelve al menos 2 columnas de probabilidad.")
                     return {"error": "El modelo predict_proba no devuelve el formato esperado."}

            elif hasattr(self.model, 'predict'):
                # Para modelos que dan predicción directa (SVM, etc.) - umbral no aplica igual aquí
                predicciones_clase = self.model.predict(features_for_prediction)
                # Intentar asegurar que sea 0 o 1 si el modelo predice otra cosa (ej. texto)
                if not np.issubdtype(predicciones_clase.dtype, np.number):
                     print(f"WARNING: Salida de model.predict no es numérica ({predicciones_clase.dtype}). Intentando convertir.")
                     # Aquí podrías necesitar lógica específica según tu modelo si no predice 0/1
                     # Por ahora, fallaremos si no es numérico esperado
                     print("ERROR: Salida de model.predict no es numérica.")
                     return {"error": "La salida del modelo predict no es numérica."}

                # Si la salida es numérica pero no solo 0s y 1s (raro para clasificación binaria)
                if np.unique(predicciones_clase).tolist() not in ([0, 1], [0], [1]):
                     print(f"WARNING: Salida de model.predict ({np.unique(predicciones_clase)}) no es estrictamente 0 o 1. Convirtiendo a binario (>0.5).")
                     predicciones_clase = (predicciones_clase > 0.5).astype(int)


                print("SUCCESS: Predicciones generadas usando predict.")
                # No hay prob real, podrías usar un valor fijo si quieres mostrar algo
                # probabilidades = np.where(predicciones_clase == 1, 1.0, 0.0) # Pseudo-probabilidad binaria

            else:
                print("ERROR: Modelo cargado no tiene método 'predict' o 'predict_proba'.")
                return {"error": "Tipo de modelo no soportado para predicción."}

        except Exception as e:
            print(f"ERROR: Falló la predicción con el modelo: {e}")
            print(traceback.format_exc())
            return {"error": f"Error durante la predicción: {e}"} # Fallar si la predicción no funciona

        # --- Ensamblar Resultados y Calcular Métricas ---
        # Usar el df original DE ENTRADA (df_original) para añadir resultados para la vista previa
        # El df_detection se usó para preprocesamiento y selección de features, pero podría haber perdido columnas originales
        df_resultado_preview = df_original.copy() # Copia para añadir las columnas de resultado

        # Asegurarse de que el número de predicciones coincida con el número de filas originales/procesadas
        if len(predicciones_clase) != len(df_resultado_preview):
             print(f"ERROR: El número de predicciones ({len(predicciones_clase)}) no coincide con el número de filas de datos originales ({len(df_resultado_preview)}).")
             # Esto podría pasar si se eliminaron filas durante el preprocesamiento (lo cual no hicimos aquí explícitamente)
             # o si hay algún problema con el shape de la entrada al modelo.
             return {"error": "Error interno: El número de predicciones no coincide con los datos."}


        # Añadir probabilidad si está disponible
        if probabilidades is not None and len(probabilidades) == len(df_resultado_preview):
             df_resultado_preview['Threat_Probability'] = probabilidades
             # Asegurarse que la columna sea numérica, si no, la vista previa puede fallar
             df_resultado_preview['Threat_Probability'] = pd.to_numeric(df_resultado_preview['Threat_Probability'], errors='coerce')


        # Añadir la predicción binaria (0 o 1)
        df_resultado_preview['Predicted_Threat_Code'] = predicciones_clase # Columna 0 o 1
        # Asegurarse que sea numérica
        df_resultado_preview['Predicted_Threat_Code'] = pd.to_numeric(df_resultado_preview['Predicted_Threat_Code'], errors='coerce')


        # Añadir la etiqueta textual ('ATTACK' o 'BENIGN')
        # Usar np.where asegura que maneja correctamente si predicciones_clase no fuera NumPy array
        df_resultado_preview['Predicted_Label'] = np.where(df_resultado_preview['Predicted_Threat_Code'] == 1, 'ATTACK', 'BENIGN')


        print("INFO: Predicciones asignadas a los resultados.")
        detection_summary = df_resultado_preview['Predicted_Label'].value_counts().to_dict()
        print("Distribución de predicciones:")
        print(detection_summary)


        metrics = {
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1_score": None,
            "roc_auc": None,
            "report": None,
            "confusion_matrix": None,
            "labels": ['BENIGN', 'ATTACK'] # Etiquetas esperadas
        }
        if y_true_real is not None and len(y_true_real) == len(predicciones_clase):
             try:
                 print("INFO: Calculando métricas de evaluación...")
                 # Calcular métricas solo si tenemos etiquetas reales y predicciones con longitudes coincidentes
                 # Asegurarse que y_true_real y predicciones_clase son arrays numpy para las métricas
                 y_true_array = np.asarray(y_true_real)
                 pred_class_array = np.asarray(predicciones_clase)

                 metrics["accuracy"] = accuracy_score(y_true_array, pred_class_array)
                 metrics["precision"] = precision_score(y_true_array, pred_class_array, zero_division=0)
                 metrics["recall"] = recall_score(y_true_array, pred_class_array, zero_division=0)
                 metrics["f1_score"] = f1_score(y_true_array, pred_class_array, zero_division=0)

                 if probabilidades is not None and len(probabilidades) == len(y_true_array):
                      try:
                          metrics["roc_auc"] = roc_auc_score(y_true_array, np.asarray(probabilidades))
                      except ValueError:
                           # Esto ocurre si y_true_array solo contiene una clase
                           metrics["roc_auc"] = None
                           print("WARNING: ROC AUC no calculable, solo hay una clase en las etiquetas reales.")
                      except Exception as e_roc:
                           print(f"WARNING: Error al calcular ROC AUC: {e_roc}")
                           metrics["roc_auc"] = None
                 else:
                     metrics["roc_auc"] = None # No se puede calcular sin probabilidades válidas

                 cm = confusion_matrix(y_true_array, pred_class_array)
                 metrics["confusion_matrix"] = cm.tolist() # Convertir a lista para JSON serialización

                 # Reporte de clasificación detallado
                 # Usa target_names para que el reporte use las etiquetas 'BENIGN', 'ATTACK'
                 report_dict = classification_report(y_true_array, pred_class_array, target_names=['BENIGN', 'ATTACK'], output_dict=True, zero_division=0)

                 # Convertir tipos numpy dentro del reporte a nativos de Python
                 if report_dict:
                     for key, value in report_dict.items():
                         if isinstance(value, dict):
                             for sub_key, sub_value in value.items():
                                 if isinstance(sub_value, (np.float_, np.int_)):
                                     report_dict[key][sub_key] = sub_value.item() # Convertir a float/int nativo
                         elif isinstance(value, (np.float_, np.int_)):
                             report_dict[key] = value.item() # Convertir a float/int nativo

                 metrics["report"] = report_dict


                 print(f"SUCCESS: Métricas calculadas. Accuracy: {metrics['accuracy']:.4f}")

             except Exception as e:
                 print(f"WARNING: No se pudieron calcular métricas detalladas: {e}")
                 print(traceback.format_exc())
                 # Asegurarse de que las métricas sean None o un dict vacío si falla
                 metrics = {"accuracy": None, "report": None, "confusion_matrix": None, "labels": ['BENIGN', 'ATTACK'], "error": f"Error calculating metrics: {e}"}

        else:
            print("INFO: No se calcularon métricas por falta de etiquetas reales o longitud incorrecta.")
            metrics = {"accuracy": None, "report": None, "confusion_matrix": None, "labels": ['BENIGN', 'ATTACK'], "info": "Metrics not calculated (missing or mismatched true labels)"} # Indicar por qué no se calcularon


        # --- Preparar el resultado final para retornar ---
        # Solo retornar una vista previa de las primeras filas para la UI, no el DF completo
        # El DF completo (df_resultado_preview) se puede usar internamente o guardar si es necesario
        data_head_preview = df_resultado_preview.head(10).to_dict('records') # Lista de diccionarios para JSON/sesión

        final_results = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_info": f"Archivo: {os.path.basename(filepath)}" if filepath else "DataFrame directo",
            "rows_analyzed": len(df_original),
            "model_info": self.get_model_info(), # Usar el método get_model_info
            "model_threshold": self.prediction_threshold,
            "detection_summary": detection_summary,
            "metrics": metrics, # Incluye métricas, CM y reporte si se calcularon
            "data_head": data_head_preview # Vista previa de datos con predicciones
            # Puedes añadir el DF completo si lo necesitas en otro lugar, pero no en la sesión de Flask directamente por tamaño
            # "full_data_with_predictions": df_resultado_preview # ¡Cuidado con el tamaño!
        }

        self.last_detection_results = final_results # Almacenar los resultados en el objeto
        return final_results

    # --- Método get_model_info implementado para dar detalles ---
    def get_model_info(self):
         """Retorna información sobre el modelo y scaler cargados."""
         model_type = type(self.model).__name__ if self.model else "No cargado"
         scaler_type = type(self.scaler).__name__ if self.scaler else "No cargado"
         scaler_fitted = "Sí" if self.is_scaler_loaded() else "No" # is_scaler_loaded ya verifica si está ajustado

         info = {
             "Model Type": model_type,
             "Scaler Type": scaler_type,
             "Scaler Fitted": scaler_fitted,
             "Prediction Threshold": f"{self.prediction_threshold:.4f}"
             # Puedes añadir más detalles aquí si son relevantes
         }
         return info


    # Puedes añadir otros métodos según necesites...
    # Por ejemplo, un método para guardar el modelo y scaler (usado por AdminManager.retrain_model)
    # def save_model_and_scaler(self, output_folder):
    #     pass
    # O un método para obtener los resultados de la última detección
    # def get_last_detection_results(self):
    #     return self.last_detection_results