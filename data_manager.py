# data_manager.py
import pandas as pd
import numpy as np
import os
import re
import traceback

class DataManager:
    def __init__(self, upload_folder='uploads', processed_filename='datos_preprocesados.csv'):
        self.base_dir = os.path.abspath(os.path.dirname(__file__))
        self.upload_folder = os.path.join(self.base_dir, upload_folder)
        self.processed_data_path = os.path.join(self.upload_folder, processed_filename)
        os.makedirs(self.upload_folder, exist_ok=True)
        self.loaded_data = None
        self.processed_data = self._load_processed_data() # Cargar al iniciar
        self.loaded_filepath = None
        self.column_dtypes = None
        print("INFO: DataManager inicializado.")
        if self.processed_data is not None:
             print(f"INFO: Datos procesados cargados al iniciar: {self.processed_data.shape}")
             # Asegurar nombres limpios al cargar desde archivo
             if not self.processed_data.empty:
                 self.processed_data.columns = [self._clean_col_name(col) for col in self.processed_data.columns]
                 print("DEBUG: Nombres de columnas de datos procesados cargados, limpiados.")
        else:
             print("INFO: No se encontraron datos procesados previos al iniciar.")

    def _clean_col_name(self, col_name): # Método helper para limpiar nombres
        name = str(col_name).strip()
        name = re.sub(r'[^\w_]+', '_', name) # Permitir guiones bajos existentes
        name = re.sub(r'_+', '_', name) # Reemplazar múltiples guiones bajos con uno solo
        return name.lower().strip('_')

    def load_csv_data(self, filepath): # Cargar CSV con manejo de errores
        if not os.path.exists(filepath):
            return False, f"Error: El archivo no existe en la ruta '{filepath}'."
        print(f"INFO: Intentando leer archivo CSV '{os.path.basename(filepath)}'...")
        df = None
        try:
            df = pd.read_csv(filepath, low_memory=False)
            print("DEBUG: Archivo leído con delimitador (,).")
        except Exception:
            try:
                df = pd.read_csv(filepath, sep=';', low_memory=False)
                print("DEBUG: Archivo leído con delimitador (;).")
            except Exception as e_semicolon:
                msg = f"Error: No se pudo leer CSV '{os.path.basename(filepath)}'. Detalles: {e_semicolon}"
                self.loaded_data = None; self.loaded_filepath = None; self.processed_data = None
                return False, msg
        
        # Limpiar nombres de columnas INMEDIATAMENTE después de cargar
        df.columns = [self._clean_col_name(col) for col in df.columns]
        print(f"DEBUG: Nombres de columnas limpiados después de cargar CSV: {df.columns.tolist()[:5]}...")

        self.loaded_data = df
        self.loaded_filepath = filepath
        self.processed_data = None 
        self.column_dtypes = self.loaded_data.dtypes
        msg = f"Archivo '{os.path.basename(filepath)}' cargado. ({len(self.loaded_data)} filas)"
        print(f"SUCCESS: {msg}")
        return True, msg

    def preprocess_data(self, df_to_process): # Preprocesar datos cargados
        if df_to_process is None or df_to_process.empty:
            return None, "Error: No hay datos válidos para preprocesar."
        print("INFO: Iniciando preprocesamiento inicial de datos...")
        try:
            df = df_to_process.copy()
            initial_rows = len(df)
            print(f"INFO: Preprocesando {initial_rows} filas...")
            numeric_cols_inf = df.select_dtypes(include=np.number).columns
            
            # Reemplazar valores infinitos que pueden causar problemas
            num_non_finite = (~np.isfinite(df[numeric_cols_inf])).values.sum()
            if num_non_finite > 0:
                print(f"INFO: Encontrados {num_non_finite} valores no finitos (NaN/inf). Reemplazando Inf con NaN.")
                df.loc[:, numeric_cols_inf] = df[numeric_cols_inf].replace([np.inf, -np.inf], np.nan)
            
            label_col = 'label'
            if label_col in df.columns:
                print(f"INFO: Normalizando columna '{label_col}' para que Benign=1, Attack=0...")
                y_str = df[label_col].astype(str).str.strip().str.lower()
                benign_text = 'benign'
                attack_texts = {
                    'dos slowloris', 'dos slowhttptest', 'dos hulk', 'dos goldeneye', 'heartbleed',
                    'portscan', 'ftp-patator', 'ssh-patator', 'bot', 'infiltration',
                    'web attack - brute force', 'web attack - xss', 'web attack - sql injection',
                    'web attack brute force', 'web attack xss', 'web attack sql injection',
                    'ddos', 'attack', 'ssh-bruteforce', 'ftp-bruteforce', 'sql injection',
                    'scan', 'malware'
                }
                
                def map_label_tutor_style(lbl):
                    if pd.isna(lbl): return np.nan
                    lbl_clean = str(lbl).strip().lower()
                    if lbl_clean == benign_text: return 1
                    elif lbl_clean in attack_texts: return 0
                    else:
                        try:
                            num_lbl = int(float(lbl_clean))
                            if num_lbl == 1: return 1
                            elif num_lbl == 0: return 0
                        except (ValueError, TypeError):
                            pass
                        print(f"WARN: Etiqueta desconocida '{lbl_clean}' mapeada a Attack (0).")
                        return 0
                
                df[label_col] = y_str.apply(map_label_tutor_style)

            else:
                print(f"WARN: Columna '{label_col}' no encontrada para normalizar.")
                return None, f"Columna '{label_col}' no encontrada."

            # --- INICIO DEL CAMBIO CLAVE ---
            # La lista ahora solo contiene columnas que son metadatos y NUNCA características.
            # Se ha eliminado la larga lista anterior para evitar que se borren columnas importantes.
            # El ThreatDetector se encargará de seleccionar las columnas correctas para cada modelo.
            columnas_a_eliminar_sistema = [
                'timestamp'
            ]
            # --- FIN DEL CAMBIO CLAVE ---
            
            cols_to_drop_existing = [col for col in columnas_a_eliminar_sistema if col in df.columns]
            if cols_to_drop_existing:
                df = df.drop(columns=cols_to_drop_existing)
                print(f"INFO: Columnas de metadatos eliminadas por DataManager ({len(cols_to_drop_existing)}): {cols_to_drop_existing}")
            
            rows_before_duplicates = len(df)
            df.drop_duplicates(inplace=True)
            duplicates_removed = rows_before_duplicates - len(df)
            if duplicates_removed > 0: print(f"INFO: {duplicates_removed} filas duplicadas eliminadas.")

            self.processed_data = df.copy()
            final_rows = len(self.processed_data)
            msg = f"Preprocesamiento completado. Filas restantes: {final_rows} (de {initial_rows}). Columnas: {len(df.columns)}"
            print(f"SUCCESS: {msg}")
            print(f"DEBUG: Columnas finales después de DataManager.preprocess: {df.columns.tolist()[:10]}...")
            return self.processed_data, msg

        except Exception as e:
            msg = f"Error inesperado preprocesamiento: {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")
            return None, msg

    def _load_processed_data(self): # Método privado para cargar datos procesados desde archivo
        if os.path.exists(self.processed_data_path):
            try:
                print(f"INFO [DataMgr]: Cargando datos procesados desde {self.processed_data_path}")
                df = pd.read_csv(self.processed_data_path, low_memory=False)
                # Asegurar nombres limpios al cargar
                df.columns = [self._clean_col_name(col) for col in df.columns]
                return df
            except Exception as e:
                print(f"ERROR [DataMgr]: No se pudo cargar datos procesados {self.processed_data_path}: {e}")
                # Si está corrupto, mejor eliminarlo para que se regenere bien la próxima vez.
                try: os.remove(self.processed_data_path)
                except: pass
                return None
        return None

    def get_processed_data(self): # Método para obtener datos procesados
        if self.processed_data is not None:
             # Nombres de columna ya deberían estar limpios si se cargó/procesó correctamente
             return self.processed_data.copy() 
        
        # Si no está en memoria, intenta cargarlo
        loaded_df = self._load_processed_data()
        if loaded_df is not None:
            # Asegurar nombres limpios incluso si se carga de un archivo viejo
            loaded_df.columns = [self._clean_col_name(col) for col in loaded_df.columns]
            self.processed_data = loaded_df.copy()
            return self.processed_data.copy()
        return None
        
    def update_processed_data(self, combined_df): # Método para actualizar datos procesados
        if combined_df is None or not isinstance(combined_df, pd.DataFrame):
             return False, "Error: DataFrame inválido para actualizar."
        try:
            # Asegurar que las columnas del DataFrame combinado estén limpias ANTES de guardar
            combined_df.columns = [self._clean_col_name(col) for col in combined_df.columns]
            print(f"INFO [DataMgr]: Actualizando datos procesados con DF combinado: {combined_df.shape}")
            combined_df.to_csv(self.processed_data_path, index=False)
            self.processed_data = combined_df.copy()
            msg = f"Datos procesados actualizados y guardados en {os.path.basename(self.processed_data_path)}."
            print(f"SUCCESS [DataMgr]: {msg}")
            return True, msg
        except Exception as e:
            msg = f"Error al actualizar/guardar datos procesados: {e}"
            print(f"ERROR [DataMgr]: {msg}\n{traceback.format_exc()}")
            return False, msg

    def get_loaded_data(self): # Método para obtener datos cargados raw
         """Devuelve el DataFrame cargado raw desde memoria (con nombres de columna ya limpios)."""
         return self.loaded_data.copy() if self.loaded_data is not None else None

    def _generate_preview_html(self, df, rows=10, table_id="preview-table"): # Método privado para generar HTML de vista previa
        if df is None or df.empty:
            return "<p>No hay datos disponibles.</p>"
        try:
            html = df.head(rows).to_html(classes=['table', 'table-sm', 'table-striped', 'table-hover', 'small'],
                                          border=0, index=False, escape=True, float_format='%.4g', na_rep='-')
            html = html.replace('<th>','<th scope="col">')
            return f'<div class="table-responsive">{html}</div>'
        except Exception as e:
            print(f"Error generando HTML preview ({table_id}): {e}")
            return "<p>Error al generar vista previa.</p>"

    def get_loaded_data_head_html(self, rows=10): # Método para obtener vista previa de datos cargados
        return self._generate_preview_html(self.get_loaded_data(), rows, "loaded-preview")

    def get_processed_data_head_html(self, rows=10): # Método para obtener vista previa de datos procesados
        return self._generate_preview_html(self.get_processed_data(), rows, "processed-preview")