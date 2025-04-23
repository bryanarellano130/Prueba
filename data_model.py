import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression # Este es un tipo de GLM para clasificación binaria

# --- CONFIGURACIÓN ---
# Asegúrate que esta ruta COINCIDA con app.config['MODEL_FOLDER'] en tu app.py
MODEL_FOLDER = 'modelo'
MODEL_FILENAME = 'modelo_glm.joblib' # Asegúrate que el nombre COINCIDA con app.py
SCALER_FILENAME = 'scaler.joblib'  # Asegúrate que el nombre COINCIDA con app.py

MODEL_PATH = os.path.join(MODEL_FOLDER, MODEL_FILENAME)
SCALER_PATH = os.path.join(MODEL_FOLDER, SCALER_FILENAME)

# --- 1. Cargar tus datos de entrenamiento ---
print("INFO: Cargando datos de entrenamiento desde CSV...")
try:
    # Usar low_memory=False puede ayudar a Pandas a inferir mejor los tipos
    # y evitar algunas advertencias, aunque no siempre soluciona el problema
    # si hay inconsistencias reales en los datos.
    # Asegúrate de que la ruta sea correcta para tu archivo CSV
    csv_filepath = 'data/02-16-2018.csv'
    data = pd.read_csv(csv_filepath, low_memory=False)

    # Asegúrate de que 'Label' sea el nombre de tu columna objetivo
    # Verifica si 'Label' existe en el DataFrame
    target_column = 'Label' # <-- Define aquí el nombre de tu columna objetivo
    if target_column not in data.columns:
        print(f"ERROR: La columna objetivo '{target_column}' no se encontró en el archivo CSV '{csv_filepath}'. Por favor, verifica el nombre de la columna.")
        print(f"Columnas disponibles: {data.columns.tolist()}")
        exit()

    # Separar características (X) y la variable objetivo (y)
    X_df = data.drop(target_column, axis=1)
    y_series = data[target_column]

    print(f"INFO: Datos de entrenamiento cargados: {len(data)} filas.")
except FileNotFoundError:
    print(f"ERROR: ¡Archivo de entrenamiento no encontrado! Asegúrate de que la ruta '{csv_filepath}' sea correcta.")
    exit()
except Exception as e:
    print(f"ERROR: No se pudo cargar o procesar el archivo de entrenamiento: {e}")
    exit()

# --- 2. Limpiar y Preprocesar (Escalar) los datos ---
print("INFO: Limpiando y preparando datos para escalado...")

# Identificar columnas que probablemente deberían ser numéricas pero pueden tener errores
# Basado en tu error anterior y el tipo de datos de red, columnas como 'Dst Port'
# y otras que representan métricas numéricas son candidatas.
# La forma más segura es intentar convertir TODAS las columnas de características
# a numéricas y manejar las que no se puedan.
numeric_cols = []
non_numeric_cols_after_coerce = []

for col in X_df.columns:
    # Intentar convertir la columna a numérica. 'errors='coerce''
    # reemplazará cualquier valor que no se pueda convertir por NaN.
    original_dtype = X_df[col].dtype
    X_df[col] = pd.to_numeric(X_df[col], errors='coerce')

    # Si la columna es numérica después de la conversión (o se convirtió)
    if pd.api.types.is_numeric_dtype(X_df[col]):
        numeric_cols.append(col)
        # Rellenar los valores NaN resultantes de la coerción o NaNs originales
        # Usamos la media para llenar los NaNs. Si una columna entera se convirtió
        # a NaN, la media también será NaN.
        mean_val = X_df[col].mean()
        if pd.isna(mean_val):
            # Si la media es NaN (columna entera se convirtió a NaN o estaba vacía)
            print(f"ADVERTENCIA: La columna '{col}' se convirtió completamente a NaN. Llenando NaN con 0.")
            X_df[col].fillna(0, inplace=True)
        else:
             # Llenar NaN con la media calculada
            X_df[col].fillna(mean_val, inplace=True)
    else:
        # Si después de 'coerce' la columna aún no es numérica (ej: era texto puro
        # que no se puede convertir a número), no podemos escalarla directamente.
        non_numeric_cols_after_coerce.append(col)
        print(f"ADVERTENCIA: La columna '{col}' ({original_dtype} -> {X_df[col].dtype} después de coerción) sigue sin ser numérica y será excluida del escalado/modelo.")
        # Puedes decidir si quieres eliminar estas columnas o manejarlas de otra forma (ej. one-hot encoding si son categóricas)


# Excluir las columnas que no pudieron ser convertidas a numéricas
if non_numeric_cols_after_coerce:
    print(f"INFO: Excluyendo columnas no numéricas: {non_numeric_cols_after_coerce}")
    X_df = X_df.drop(columns=non_numeric_cols_after_coerce)

# Ahora, X_df solo contiene columnas numéricas (con NaNs rellenados)
print("INFO: Entrenando el StandardScaler con columnas numéricas...")
scaler = StandardScaler()
# Entrena el scaler con tus datos de características limpios y numéricos
X_scaled = scaler.fit_transform(X_df)
print("INFO: StandardScaler entrenado y datos escalados.")

# --- 3. Entrenar el Modelo GLM (Logistic Regression) ---
print("INFO: Entrenando el modelo GLM (Logistic Regression)...")
# LogisticRegression es un tipo de Modelo Lineal Generalizado para clasificación binaria.
# Utiliza una función de enlace logit y asume una distribución Bernoulli para la respuesta.
# Configura los parámetros según necesites.
# 'liblinear' es un buen solver por defecto para conjuntos de datos pequeños/medianos
model = LogisticRegression(random_state=42, solver='liblinear')
# Puedes ajustar otros parámetros como C (inverso de la fuerza de regularización), penalty, etc.

# Entrena el modelo con los datos escalados y la columna objetivo
model.fit(X_scaled, y_series)
print("INFO: Modelo GLM (Logistic Regression) entrenado.")

# --- 4. Guardar el Scaler y el Modelo ---
# Crea la carpeta 'modelo' si no existe
if not os.path.exists(MODEL_FOLDER):
    os.makedirs(MODEL_FOLDER)
    print(f"INFO: Carpeta '{MODEL_FOLDER}' creada.")

print(f"INFO: Guardando scaler en {SCALER_PATH}...")
try:
    joblib.dump(scaler, SCALER_PATH)
    print("SUCCESS: Scaler guardado correctamente.")
except Exception as e:
    print(f"ERROR: No se pudo guardar el scaler: {e}")

print(f"INFO: Guardando modelo en {MODEL_PATH}...")
try:
    joblib.dump(model, MODEL_PATH)
    print("SUCCESS: Modelo GLM (Logistic Regression) guardado correctamente.")
except Exception as e:
    print(f"ERROR: No se pudo guardar el modelo: {e}")

print("\n--- Proceso de entrenamiento y guardado completado ---")
print(f"Ahora deberías encontrar '{MODEL_FILENAME}' y '{SCALER_FILENAME}' dentro de la carpeta '{MODEL_FOLDER}'.")
print("Estos archivos serán cargados por tu app.py.")