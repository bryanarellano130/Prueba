# train_model.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression # Usado como GLM para clasificación binaria
# from statsmodels.api import GLM, families # Alternativa para modelos GLM más específicos
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_auc_score, f1_score
from sklearn.utils import resample # Para posible balanceo de clases
import joblib # Para guardar el modelo y preprocesadores
import os
import glob # Para encontrar archivos de dataset

# --- Configuración ---
# Rutas a los datasets (ajusta según tu estructura)
# Asume que los datasets están en una carpeta 'datasets' relativa al script
DATASET_DIR = 'datasets' 
# Patrón para encontrar los archivos CSV (ej. todos los CSV en la carpeta)
DATASET_PATTERN = os.path.join(DATASET_DIR, '*.csv') 
# Carpeta para guardar el modelo y objetos de preprocesamiento
MODEL_DIR = 'model' 
# Nombre base para los archivos guardados
MODEL_BASE_NAME = 'glm_model'
# Variable objetivo (ajusta según tu dataset, ej. 'Label' o 'Class')
TARGET_COLUMN = 'Label' 
# Proporción para dividir en entrenamiento y prueba
TEST_SIZE = 0.3 
# Semilla para reproducibilidad
RANDOM_STATE = 42 
# Si se debe balancear las clases (puede ser útil si hay desbalance)
BALANCE_CLASSES = False 

# --- Funciones ---

def load_datasets(pattern):
    """Carga y combina múltiples archivos CSV según un patrón."""
    all_files = glob.glob(pattern)
    if not all_files:
        raise FileNotFoundError(f"No se encontraron archivos CSV en '{pattern}'. Asegúrate de que los datasets estén en la carpeta correcta.")
    
    df_list = []
    print(f"Archivos encontrados: {all_files}")
    for f in all_files:
        try:
            # Leer en chunks si los archivos son muy grandes
            # df_chunk_list = []
            # for chunk in pd.read_csv(f, chunksize=50000, low_memory=False):
            #      df_chunk_list.append(chunk)
            # df = pd.concat(df_chunk_list, ignore_index=True)
            
            # Lectura normal (puede consumir mucha memoria para archivos grandes)
            df = pd.read_csv(f, low_memory=False) 
            print(f"Cargado: {f}, Filas: {len(df)}, Columnas: {len(df.columns)}")
            df_list.append(df)
        except Exception as e:
            print(f"Error al cargar {f}: {e}")
            continue # Saltar archivo si hay error
            
    if not df_list:
         raise ValueError("No se pudo cargar ningún dataset correctamente.")
         
    # Combinar todos los dataframes
    combined_df = pd.concat(df_list, ignore_index=True)
    print(f"Datasets combinados. Total Filas: {len(combined_df)}, Total Columnas: {len(combined_df.columns)}")
    return combined_df

def clean_and_preprocess(df, target_column):
    """Limpia y preprocesa el dataframe."""
    print("Iniciando limpieza y preprocesamiento...")
    
    # 1. Manejar valores infinitos (comunes en datos de red)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # 2. Eliminar filas con NaN en la columna objetivo
    df.dropna(subset=[target_column], inplace=True)
    print(f"Filas después de eliminar NaNs en '{target_column}': {len(df)}")

    # 3. Identificar características numéricas y categóricas (excluyendo el target)
    features = df.drop(columns=[target_column])
    numeric_features = features.select_dtypes(include=np.number).columns.tolist()
    categorical_features = features.select_dtypes(include='object').columns.tolist()
    
    print(f"Características numéricas ({len(numeric_features)}): {numeric_features}")
    print(f"Características categóricas ({len(categorical_features)}): {categorical_features}")

    # 4. Crear transformadores para preprocesamiento
    #    - Numéricas: Imputar NaNs (ej. con la media) y escalar (StandardScaler)
    #    - Categóricas: Imputar NaNs (ej. con 'missing') y codificar (OneHotEncoder)
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='mean')), # O 'median'
        ('scaler', StandardScaler())
    ])

    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
        ('onehot', OneHotEncoder(handle_unknown='ignore')) # Ignorar categorías no vistas en entrenamiento
    ])

    # 5. Combinar transformadores usando ColumnTransformer
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_features),
            ('cat', categorical_transformer, categorical_features)
        ], 
        remainder='passthrough' # Mantener otras columnas si las hubiera (aunque aquí no debería haber)
    ) 
    
    # 6. Separar características (X) y objetivo (y)
    X = df.drop(columns=[target_column])
    y = df[target_column]

    # Opcional: Convertir etiquetas del target a 0/1 si son strings (ej. 'BENIGN', 'ATTACK')
    # Asume que la clase "positiva" (ataque) debe ser 1. ¡AJUSTA ESTO!
    positive_class_label = 'ATTACK' # O 'malicious', etc. ¡Verifica tus datos!
    if y.dtype == 'object':
        print(f"Convirtiendo target a numérico (1 si es '{positive_class_label}', 0 si no).")
        y = y.apply(lambda x: 1 if positive_class_label in str(x).upper() else 0) 
        # Verifica las clases resultantes
        print("Distribución de clases en y (después de conversión):")
        print(y.value_counts(normalize=True))


    print("Preprocesamiento definido.")
    return X, y, preprocessor, numeric_features, categorical_features

def balance_data(X_train, y_train):
    """Balancea los datos de entrenamiento usando oversampling de la clase minoritaria."""
    print("Balanceando datos de entrenamiento...")
    data = pd.concat([X_train, y_train], axis=1)
    
    # Separar clases
    majority_class = data[y_train.value_counts().idxmax()]
    minority_class = data[y_train.value_counts().idxmin()]
    
    print(f"Clase mayoritaria: {y_train.value_counts().idxmax()}, tamaño: {len(majority_class)}")
    print(f"Clase minoritaria: {y_train.value_counts().idxmin()}, tamaño: {len(minority_class)}")

    # Oversample clase minoritaria
    minority_upsampled = resample(minority_class, 
                                  replace=True,     # sample with replacement
                                  n_samples=len(majority_class), # to match majority class
                                  random_state=RANDOM_STATE) 
                                  
    # Combinar clase mayoritaria con minoritaria upsampled
    balanced_data = pd.concat([majority_class, minority_upsampled])
    
    print(f"Tamaño del dataset balanceado: {len(balanced_data)}")
    
    X_train_balanced = balanced_data.drop(columns=[y_train.name]) # Usa y_train.name para obtener el nombre de la columna
    y_train_balanced = balanced_data[y_train.name]
    
    print("Distribución de clases después del balanceo:")
    print(y_train_balanced.value_counts(normalize=True))
    
    return X_train_balanced, y_train_balanced


# --- Flujo Principal ---
if __name__ == "__main__":
    try:
        # 1. Cargar Datos
        print("--- 1. Cargando Datasets ---")
        df_combined = load_datasets(DATASET_PATTERN)
        
        # Verificar si la columna objetivo existe
        if TARGET_COLUMN not in df_combined.columns:
             raise ValueError(f"La columna objetivo '{TARGET_COLUMN}' no se encontró en los datos cargados. Columnas disponibles: {df_combined.columns.tolist()}")

        # 2. Limpiar y Preprocesar (Definir preprocesador)
        print("\n--- 2. Definiendo Preprocesamiento ---")
        # Importar SimpleImputer aquí para evitar dependencia global si no se usa
        from sklearn.impute import SimpleImputer 
        X, y, preprocessor, numeric_cols, cat_cols = clean_and_preprocess(df_combined, TARGET_COLUMN)
        
        # Guardar las columnas usadas para la predicción (después del preprocesamiento)
        # Esto es crucial para la app Flask
        # Nota: OneHotEncoder cambia los nombres de las columnas categóricas
        # Es mejor guardar el 'preprocessor' completo.

        # 3. Dividir Datos
        print("\n--- 3. Dividiendo Datos (Entrenamiento/Prueba) ---")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y # Stratify es importante para mantener proporción de clases
        )
        print(f"Tamaño Entrenamiento: {X_train.shape}, Tamaño Prueba: {X_test.shape}")
        print("Distribución de clases en Entrenamiento:")
        print(y_train.value_counts(normalize=True))
        print("Distribución de clases en Prueba:")
        print(y_test.value_counts(normalize=True))

        # 4. Balancear Datos de Entrenamiento (Opcional)
        if BALANCE_CLASSES:
             print("\n--- 4. Balanceando Datos de Entrenamiento ---")
             # Solo balancear el conjunto de entrenamiento
             X_train, y_train = balance_data(X_train, y_train)

        # 5. Definir y Entrenar el Modelo GLM (Regresión Logística)
        print("\n--- 5. Entrenando Modelo GLM (Regresión Logística) ---")
        # Crear el pipeline completo: Preprocesador + Modelo
        # Usar LogisticRegression como un GLM para clasificación binaria.
        # Puedes ajustar parámetros como 'C' (regularización), 'solver', 'max_iter'.
        # class_weight='balanced' es una alternativa al resampling manual.
        model_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', LogisticRegression(random_state=RANDOM_STATE, 
                                             solver='saga', # Bueno para datasets grandes
                                             max_iter=1000, # Aumentar si no converge
                                             C=1.0, # Parámetro de regularización
                                             # class_weight='balanced' # Alternativa a resample
                                             n_jobs=-1 # Usar todos los cores disponibles
                                             )) 
        ])
        
        # Entrenar el pipeline completo
        model_pipeline.fit(X_train, y_train)
        print("Modelo entrenado exitosamente.")

        # 6. Evaluar el Modelo
        print("\n--- 6. Evaluando Modelo ---")
        y_pred = model_pipeline.predict(X_test)
        y_pred_proba = model_pipeline.predict_proba(X_test)[:, 1] # Probabilidad de la clase 1

        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred) # F1-score (bueno para clases desbalanceadas)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred)

        print(f"Accuracy: {accuracy:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"ROC AUC Score: {roc_auc:.4f}")
        print("\nMatriz de Confusión:")
        print(conf_matrix)
        print("\nReporte de Clasificación:")
        print(class_report)

        # 7. Guardar el Modelo y Preprocesador
        print("\n--- 7. Guardando Modelo y Preprocesador ---")
        os.makedirs(MODEL_DIR, exist_ok=True) # Asegurar que el directorio exista
        
        model_filename = os.path.join(MODEL_DIR, f"{MODEL_BASE_NAME}.pkl")
        joblib.dump(model_pipeline, model_filename) 
        print(f"Pipeline completo (preprocesador + modelo) guardado en: {model_filename}")
        
        # Opcional: Guardar objetos individuales si es necesario para la app
        # scaler_filename = os.path.join(MODEL_DIR, 'scaler.pkl')
        # encoder_filename = os.path.join(MODEL_DIR, 'encoder.pkl')
        # joblib.dump(model_pipeline.named_steps['preprocessor'].transformers_[0][1].named_steps['scaler'], scaler_filename)
        # joblib.dump(model_pipeline.named_steps['preprocessor'].transformers_[1][1].named_steps['onehot'], encoder_filename)
        # print(f"Scaler guardado en: {scaler_filename}")
        # print(f"Encoder guardado en: {encoder_filename}")

        # Guardar nombres de columnas originales (útil para referencia)
        # columns_filename = os.path.join(MODEL_DIR, 'feature_columns.pkl')
        # original_features = numeric_cols + cat_cols
        # joblib.dump(original_features, columns_filename)
        # print(f"Nombres de columnas originales guardados en: {columns_filename}")


    except FileNotFoundError as fnf_error:
        print(f"Error: Archivo no encontrado. {fnf_error}")
    except ValueError as val_error:
        print(f"Error: Problema con los datos. {val_error}")
    except KeyError as key_error:
        print(f"Error: Columna no encontrada. {key_error}")
    except Exception as e:
        print(f"Ocurrió un error inesperado durante el entrenamiento: {e}")
        import traceback
        traceback.print_exc()

