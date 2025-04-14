# data_manager.py
import pandas as pd
import numpy as np
import os

class DataManager:
    """Gestiona la carga y preprocesamiento de datos para la aplicación web."""

    def __init__(self):
        """Inicializa el gestor de datos."""
        self.loaded_data = None
        self.processed_data = None
        self.loaded_filepath = None
        self.column_dtypes = None # Para referencia futura si es necesario
        print("INFO: DataManager inicializado.") # Puedes cambiar esto por logging

    def load_csv_data(self, filepath):
        """
        Carga datos desde un archivo CSV ubicado en la ruta especificada.

        Args:
            filepath (str): La ruta completa al archivo CSV.

        Returns:
            tuple: (bool, str) indicando éxito (True) o fracaso (False) y un mensaje.
        """
        if not os.path.exists(filepath):
             return False, f"Error: El archivo no existe en la ruta '{filepath}'."

        try:
            self.loaded_data = pd.read_csv(filepath)
            self.loaded_filepath = filepath
            self.processed_data = None # Resetear datos procesados al cargar nuevos datos
            self.column_dtypes = self.loaded_data.dtypes # Guardar tipos originales
            msg = f"Archivo '{os.path.basename(filepath)}' cargado. ({len(self.loaded_data)} filas)"
            print(f"SUCCESS: {msg}")
            return True, msg
        except pd.errors.EmptyDataError:
            self.loaded_data = None
            self.loaded_filepath = None
            msg = f"Error: El archivo CSV '{os.path.basename(filepath)}' está vacío."
            print(f"WARNING: {msg}")
            return False, msg
        except Exception as e:
            self.loaded_data = None
            self.loaded_filepath = None
            msg = f"Error al leer el archivo CSV '{os.path.basename(filepath)}': {e}"
            print(f"ERROR: {msg}")
            return False, msg

    def preprocess_data(self):
        """
        Realiza el preprocesamiento de los datos previamente cargados.

        Returns:
            tuple: (bool, str) indicando éxito (True) o fracaso (False) y un mensaje.
        """
        if self.loaded_data is None:
            return False, "Error: No hay datos cargados para preprocesar. Carga un archivo primero."

        print("INFO: Iniciando preprocesamiento de datos...")
        try:
            df_procesado = self.loaded_data.copy()
            initial_rows = len(df_procesado)
            print(f"INFO: Preprocesando {initial_rows} filas desde {os.path.basename(self.loaded_filepath or 'N/A')}")

            # --- PASOS DE PREPROCESAMIENTO ---

            # 1. Limpieza de nombres de columnas
            original_cols = df_procesado.columns.tolist()
            # Reemplaza caracteres no alfanuméricos (excepto _) con nada, luego minúsculas
            df_procesado.columns = df_procesado.columns.str.strip().str.replace('[^A-Za-z0-9_]+', '', regex=True).str.lower()
            new_cols = df_procesado.columns.tolist()
            renamed_cols = {o: n for o, n in zip(original_cols, new_cols) if o != n}
            if renamed_cols:
                print(f"INFO: Columnas renombradas: {len(renamed_cols)}")

            # 2. Manejo de Infinitos y NaNs (Importante hacerlo antes de eliminar columnas si aplica)
            num_infinite_before = np.isinf(df_procesado.select_dtypes(include=np.number)).sum().sum()
            if num_infinite_before > 0:
                print(f"INFO: Encontrados {num_infinite_before} valores infinitos, reemplazando con NaN.")
                df_procesado.replace([np.inf, -np.inf], np.nan, inplace=True)

            rows_before_na = len(df_procesado)
            df_procesado.dropna(inplace=True) # Elimina filas con cualquier NaN
            rows_after_na = len(df_procesado)
            nan_removed_count = rows_before_na - rows_after_na
            if nan_removed_count > 0:
                 print(f"INFO: {nan_removed_count} filas eliminadas debido a valores NaN.")

            # 3. Eliminación de columnas (Asegúrate que los nombres coincidan DESPUÉS de limpiar)
            #    Usa los nombres de columna *limpios* aquí. ¡REVISA ESTA LISTA CUIDADOSAMENTE!
            columnas_a_eliminar_limpias = [
                 'flow_bytess', 'flow_packetss', # Revisa si la limpieza añade 's' al final
                 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
                 'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'urg_flag_count',
                 'cwe_flag_count', 'ece_flag_count',
                 'fwd_avg_bytesbulk', 'fwd_avg_packetsbulk', 'fwd_avg_bulk_rate',
                 'bwd_avg_bytesbulk', 'bwd_avg_packetsbulk', 'bwd_avg_bulk_rate',
                 'active_std', 'idle_std',
                 # Añade aquí otras columnas que identificaste para eliminar,
                 # usando el nombre que tendrían DESPUÉS de la limpieza del paso 1.
                 # Por ejemplo, si tenías ' Flow Bytes/s ', ahora sería 'flow_bytess' o 'flowbytes'
                 # dependiendo de cómo actúe la regex. Revisa la salida de print() abajo.
            ]
            print(f"DEBUG: Columnas disponibles después de limpieza y NaN: {df_procesado.columns.tolist()}") # Para depurar nombres

            # Encuentra qué columnas existen realmente en el df *después* de limpiar nombres y quitar NaNs
            columnas_existentes_a_eliminar = [col for col in columnas_a_eliminar_limpias if col in df_procesado.columns]
            if columnas_existentes_a_eliminar:
                df_procesado = df_procesado.drop(columns=columnas_existentes_a_eliminar)
                print(f"INFO: Columnas eliminadas: {len(columnas_existentes_a_eliminar)} -> {', '.join(columnas_existentes_a_eliminar)}")
            else:
                print("INFO: No se encontraron columnas especificadas para eliminar (o ya fueron eliminadas/renombradas).")

            # 4. Eliminación de duplicados (después de eliminar columnas irrelevantes)
            rows_before_duplicates = len(df_procesado)
            df_procesado.drop_duplicates(inplace=True)
            rows_after_duplicates = len(df_procesado)
            duplicates_removed_count = rows_before_duplicates - rows_after_duplicates
            if duplicates_removed_count > 0:
                print(f"INFO: {duplicates_removed_count} filas duplicadas eliminadas.")

            # --- FIN PREPROCESAMIENTO ---

            if len(df_procesado) == 0:
                self.processed_data = None
                msg = "Error: Después del preprocesamiento, el DataFrame está vacío."
                print(f"ERROR: {msg}")
                return False, msg

            self.processed_data = df_procesado
            final_rows = len(self.processed_data)
            msg = f"Preprocesamiento completado. Filas resultantes: {final_rows} (de {initial_rows} iniciales)."
            print(f"SUCCESS: {msg}")
            # Opcional: Imprimir información del DF procesado
            # print("INFO: Primeras filas de datos procesados:")
            # print(self.processed_data.head())
            # print("INFO: Información del DataFrame procesado:")
            # self.processed_data.info()
            return True, msg

        except Exception as e:
            self.processed_data = None
            msg = f"Error inesperado durante el preprocesamiento: {e}"
            print(f"ERROR: {msg}")
            import traceback
            print(traceback.format_exc()) # Imprime el traceback completo para depuración
            return False, msg

    def get_loaded_data(self):
        """Devuelve el DataFrame original cargado."""
        return self.loaded_data

    def get_processed_data(self):
        """Devuelve el DataFrame preprocesado."""
        return self.processed_data

    def _get_dataframe_head_html(self, df, rows=5, table_id="dataframe-preview"):
        """Helper para convertir las primeras filas de un DF a HTML."""
        if df is None or df.empty:
            return "<p>No hay datos para mostrar.</p>"
        try:
            # escape=False puede ser necesario si tienes HTML en tus datos, pero es un riesgo de seguridad.
            # Usar escape=True por defecto.
            return df.head(rows).to_html(classes=['data-table'], border=0, table_id=table_id, escape=True)
        except Exception as e:
            print(f"Error generando HTML para DataFrame: {e}")
            return "<p>Error al mostrar la vista previa de los datos.</p>"

    def get_loaded_data_head_html(self, rows=5):
        """Devuelve las primeras filas de los datos cargados como tabla HTML."""
        return self._get_dataframe_head_html(self.loaded_data, rows, table_id="loaded-data-preview")

    def get_processed_data_head_html(self, rows=5):
        """Devuelve las primeras filas de los datos procesados como tabla HTML."""
        return self._get_dataframe_head_html(self.processed_data, rows, table_id="processed-data-preview")