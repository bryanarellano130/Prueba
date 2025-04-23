# threat_simulator.py
import pandas as pd
import numpy as np
import datetime
import os # Importar os para usar self.temp_folder (ej. para guardar archivos)
import traceback # Importar traceback para errores detallados

class ThreatSimulator:
    """
    Simula tráfico de red y diferentes tipos de ataques cibernéticos.
    Puede generar DataFrames o guardar archivos CSV simulados.
    """

    # --- MODIFICADO: Ahora acepta 'temp_folder' como argumento ---
    def __init__(self, temp_folder):
        """
        Inicializa el simulador y el historial de simulaciones.

        Args:
            temp_folder (str): Ruta a la carpeta temporal donde se pueden guardar archivos generados.
        """
        print("DEBUG: Inicializando ThreatSimulator...")
        self.temp_folder = temp_folder # <-- Almacena la ruta de la carpeta temporal
        self.simulation_history = [] # Almacena metadatos de simulaciones pasadas

        # Asegurarse de que la carpeta temporal exista (aunque app.py ya lo hace, es una buena verificación)
        os.makedirs(self.temp_folder, exist_ok=True)

        print(f"INFO: ThreatSimulator inicializado con carpeta temporal: {self.temp_folder}")


    def run_simulation(self, config):
        """
        Ejecuta una simulación basada en la configuración proporcionada y guarda el resultado en un CSV.

        Args:
            config (dict): Un diccionario con los parámetros de la simulación.
                           Ej: {'attack_type': 'DoS', 'duration': 60, 'intensity': 'medium', 'target': '10.0.1.10'}
                           Debe coincidir con los campos del SimulationForm en app.py.

        Returns:
            dict: Un diccionario con metadatos de la simulación, incluida la ruta del archivo CSV generado,
                  o None si la configuración es inválida o ocurre un error.
        """
        # Mapear la intensidad textual a un factor numérico (ajusta esto según tu lógica)
        intensity_map = {'low': 0.05, 'medium': 0.15, 'high': 0.3}
        attack_type = config.get('attack_type', 'Unknown')
        target_ip = config.get('target', 'N/A') # Usar 'target' para coincidir con el formulario
        duration = config.get('duration', 60)
        intensity_level = config.get('intensity', 'medium') # Nivel textual
        attack_probability = intensity_map.get(intensity_level, 0.15) # Factor de probabilidad

        # Validaciones básicas de configuración
        if not isinstance(duration, int) or duration <= 0:
             print(f"ERROR: Duración inválida ({duration}) para la simulación.")
             return None
        if intensity_level not in intensity_map:
             print(f"ERROR: Nivel de intensidad inválido ({intensity_level}).")
             return None
        # Puedes añadir más validaciones para attack_type, target_ip si es necesario

        print(f"INFO: Ejecutando simulación: Tipo={attack_type}, Target={target_ip}, Dur={duration}s, Intensidad={intensity_level} ({attack_probability:.2f})")

        # --- LÓGICA DE SIMULACIÓN (PLACEHOLDER MEJORADO) ---
        # ** ¡IMPORTANTE! Reemplaza esta sección con tu lógica real de simulación **

        # Calcular número de registros (ej: un evento cada 10ms simulado)
        num_records = int(duration / 0.01) # Convertir segundos a intervalos de 10ms

        if num_records <= 0:
             print("WARNING: Duración de simulación resulta en 0 o menos registros.")
             return None # No generar datos si la duración es muy corta

        try:
            # Generar Timestamps
            start_time = pd.Timestamp.now(tz='UTC') # Usar UTC es buena práctica
            timestamps = pd.to_datetime(start_time + np.arange(num_records) * np.timedelta64(10, 'ms')) # Incrementos de 10ms

            # Generar IPs (simplista)
            src_ips = [f"192.168.{np.random.randint(1, 3)}.{np.random.randint(10, 100)}" for _ in range(num_records)]
            # Usar el target_ip proporcionado si no es "N/A" o None
            if target_ip and target_ip != 'N/A':
                 dst_ips = [target_ip] * num_records # Todo el tráfico va al target_ip
            else:
                 dst_ips = [f"10.0.{np.random.randint(0, 2)}.{np.random.randint(1, 255)}" for _ in range(num_records)] # IPs de destino aleatorias

            # Generar Puertos de Destino (más variado)
            # Puertos comunes para ataques o tráfico normal
            dst_ports = np.random.choice([22, 80, 443, 23, 21, 53, 8080] + list(range(1024, 65535)), size=num_records)

            # Generar Protocolos (ajusta probabilidades)
            protocols = np.random.choice(['TCP', 'UDP', 'ICMP'], size=num_records, p=[0.7, 0.2, 0.1]) # Más TCP común

            # Generar otros features numéricas y categóricas (ajusta rangos y distribuciones)
            data = {
                # Nombres de columna EJEMPLO (¡Asegúrate que coincidan con tus datos de entrenamiento!)
                # Si tus columnas tienen espacios o caracteres especiales, ajústalos.
                'Flow Duration': np.random.randint(100, 90000000, size=num_records), # Microsegundos
                'Total Fwd Packets': np.random.randint(1, 100, size=num_records),
                'Total Backward Packets': np.random.randint(0, 100, size=num_records),
                'Fwd Packet Length Max': np.random.rand(num_records) * 1500, # Tamaño máximo de paquete
                'Fwd Packet Length Min': np.random.rand(num_records) * 50,
                'Fwd Packet Length Mean': np.random.rand(num_records) * 500,
                'Fwd Packet Length Std': np.random.rand(num_records) * 300,
                'Bwd Packet Length Max': np.random.rand(num_records) * 1500,
                'Bwd Packet Length Min': np.random.rand(num_records) * 50,
                'Bwd Packet Length Mean': np.random.rand(num_records) * 400,
                'Bwd Packet Length Std': np.random.rand(num_records) * 250,
                'Flow Bytes/s': np.random.rand(num_records) * 10000000 + 1, # +1 para evitar div por cero
                'Flow Packets/s': np.random.rand(num_records) * 5000 + 1,
                # ... añade otras columnas numéricas que tu modelo necesite ...
                'Timestamp': timestamps,
                'Src IP': src_ips,
                'Dst IP': dst_ips,
                'Dst Port': dst_ports, # Usar los puertos generados arriba
                'Protocol': protocols,
                # ... añade otras columnas categóricas/identificadores si son relevantes ...
            }

            # Crear DataFrame
            resultado_simulacion = pd.DataFrame(data)

            # Asignar Etiquetas (Simulación de Ataques)
            # Generar un array booleano indicando si cada registro es un ataque basado en la probabilidad
            is_attack = np.random.rand(num_records) < attack_probability

            # Si es un ataque, asignar el attack_type simulado; de lo contrario, 'BENIGN'
            # Asegúrate de que 'BENIGN' sea la etiqueta de la clase normal que tu modelo espera.
            # Asegúrate de que attack_type (como 'DoS', 'PortScan') sean las etiquetas de ataque que tu modelo espera o agruparlas.
            resultado_simulacion['Label'] = np.where(is_attack, attack_type, 'BENIGN') # <-- Columna de etiqueta esperada por el detector

            # --- FIN LÓGICA PLACEHOLDER ---

            print(f"SUCCESS: Simulación completada. Generados {len(resultado_simulacion)} registros.")
            print("Distribución de etiquetas generadas:")
            # Usar .get() por si 'Label' no se generó por algún error previo
            label_counts = resultado_simulacion.get('Label', pd.Series(dtype=str)).value_counts()
            print(label_counts)


            # --- Guardar el DataFrame a un archivo CSV temporal ---
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") # Añadir microsegundos para unicidad
            output_filename = f"simulation_data_{timestamp_str}.csv"
            output_filepath = os.path.join(self.temp_folder, output_filename)

            try:
                resultado_simulacion.to_csv(output_filepath, index=False)
                print(f"SUCCESS: Datos de simulación guardados en: {output_filepath}")
            except Exception as e_save:
                print(f"ERROR: No se pudieron guardar los datos de simulación en '{output_filepath}': {e_save}")
                print(traceback.format_exc())
                # Si no se puede guardar, la simulación no es útil para el detector
                return None


            # Guardar metadatos en el historial
            history_entry = {
                "attack_type": attack_type,
                "target_ip": target_ip,
                "duration": duration,
                "intensity_level": intensity_level,
                "attack_probability": attack_probability,
                "timestamp_run": datetime.datetime.now().isoformat(timespec='seconds'),
                "num_records": len(resultado_simulacion),
                "label_distribution": label_counts.to_dict(), # Guardar la distribución generada
                "output_filepath": output_filepath # Guardar la ruta del archivo generado
            }
            self.simulation_history.append(history_entry)

            # Retornar un dict con información útil, incluida la ruta del archivo generado
            return history_entry # Retorna el dict del historial


        except Exception as e_sim:
            print(f"ERROR Crítico durante la simulación: {e_sim}")
            print(traceback.format_exc())
            return None # Retornar None si falla cualquier paso importante

    def get_history(self):
        """
        Devuelve el historial de metadatos de las simulaciones ejecutadas.

        Returns:
            list: Una lista de diccionarios, donde cada diccionario contiene
                  los metadatos de una simulación.
        """
        return self.simulation_history

    # Puedes añadir otros métodos aquí, como uno para cargar datos simulados si es necesario


# Sección para pruebas directas (opcional)
if __name__ == '__main__':
    print("Probando ThreatSimulator...")
    # Crear una carpeta temporal para la prueba si no existe
    test_temp_folder = 'temp_sim_data_test'
    os.makedirs(test_temp_folder, exist_ok=True)

    simulator = ThreatSimulator(temp_folder=test_temp_folder) # Pasar la carpeta temporal

    test_config_low = {'attack_type': 'PortScan', 'target': '10.0.1.50', 'duration': 10, 'intensity': 'low'}
    test_config_high = {'attack_type': 'DDoS', 'target': '10.0.2.100', 'duration': 15, 'intensity': 'high'}

    print("\n--- Ejecutando Simulación (Baja Intensidad) ---")
    result_low = simulator.run_simulation(test_config_low)

    print("\n--- Ejecutando Simulación (Alta Intensidad) ---")
    result_high = simulator.run_simulation(test_config_high)


    print("\n--- Resultados de la Simulación (Prueba) ---")
    if result_low:
        print(f"Simulación Baja exitosa. Archivo: {result_low.get('output_filepath')}")
        # Puedes cargar el archivo y mostrar las primeras filas si quieres verificar
        # df_low = pd.read_csv(result_low['output_filepath'])
        # print(df_low.head())
    else:
        print("La simulación de prueba Baja falló.")

    if result_high:
        print(f"Simulación Alta exitosa. Archivo: {result_high.get('output_filepath')}")
        # Puedes cargar el archivo y mostrar las primeras filas si quieres verificar
        # df_high = pd.read_csv(result_high['output_filepath'])
        # print(df_high.head())
    else:
        print("La simulación de prueba Alta falló.")

    print("\n--- Historial de Simulación (Prueba) ---")
    history = simulator.get_history()
    # Imprimir solo metadatos, no el contenido completo de los archivos
    for entry in history:
        print(entry)

    # Opcional: Limpiar los archivos temporales creados por la prueba
    # import glob
    # for f in glob.glob(os.path.join(test_temp_folder, "simulation_data_*.csv")):
    #     os.remove(f)
    # os.rmdir(test_temp_folder) # Solo si está vacío