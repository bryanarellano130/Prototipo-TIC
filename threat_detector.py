# threat_detector.py
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.preprocessing import MinMaxScaler # Para alinearse con el script del tutor
from sklearn.model_selection import train_test_split
import statsmodels.api as sm
import statsmodels.tools.sm_exceptions
import joblib
import os
import warnings
import traceback
import shutil
from werkzeug.utils import secure_filename

BASE_DIR_DETECTOR = os.path.abspath(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR_DETECTOR, 'models')

class ThreatDetector:
    """
    Detecta amenazas usando un modelo de ML entrenado (GLM con muestreo).
    Gestiona el entrenamiento, guardado, carga y predicción del modelo.
    Alineado con la lógica del tutor: Benign=1, Attack=0, MinMaxScaler, dropna.
    """
    def __init__(self, data_manager_instance=None, model_dir=MODEL_DIR, model_name="active_model.joblib", scaler_name="active_scaler.joblib", test_data_name="active_test_set.joblib", threshold=0.7): # Inicialización del detector de amenazas
        print("INFO: ThreatDetector inicializado.")
        self.data_manager_ref = data_manager_instance
        self.model_dir = model_dir
        self.active_model_name = model_name
        self.active_scaler_name = scaler_name
        self.active_test_data_name = test_data_name
        self.active_model_path = os.path.join(self.model_dir, self.active_model_name)
        self.active_scaler_path = os.path.join(self.model_dir, self.active_scaler_name)
        self.active_test_data_path = os.path.join(self.model_dir, self.active_test_data_name)
        
        self.model = None
        self.scaler = None 
        self.test_set = None 
        self.prediction_threshold = threshold
        self.feature_names_ = None 

        try:
            os.makedirs(self.model_dir, exist_ok=True)
            print(f"DEBUG: Directorio de modelos '{self.model_dir}' verificado/creado.")
        except Exception as e:
            print(f"ERROR: No se pudo asegurar la existencia del directorio de modelos '{self.model_dir}': {e}")
        
        self._load_model_components() 
        
        print(f"INFO: ThreatDetector finalizó inicialización. Umbral: {self.prediction_threshold}")
        if self.model and self.scaler and self.test_set is not None and self.feature_names_ is not None:
            print("INFO: Componentes del modelo activo y nombres de características cargados exitosamente al iniciar.")
        else:
            print("WARNING: No se pudieron cargar todos los componentes del modelo activo. El reentrenamiento es necesario.")

    def _load_model_components(self): # Carga los componentes del modelo activo desde el directorio especificado
        print(f"DEBUG: Intentando cargar componentes ACTIVOS del modelo desde '{self.model_dir}'...")
        self.model = None
        self.scaler = None
        self.test_set = None
        self.feature_names_ = None 
        try:
            if os.path.exists(self.active_model_path):
                try:
                    self.model = joblib.load(self.active_model_path)
                    print("SUCCESS: Modelo activo cargado.")
                except Exception as e:
                    print(f"ERROR al cargar modelo activo desde {self.active_model_path}: {e}\n{traceback.format_exc()}")
                    self.model = None
            else: print(f"INFO: Archivo de modelo activo '{self.active_model_path}' no encontrado.")

            if os.path.exists(self.active_scaler_path):
                try:
                    self.scaler = joblib.load(self.active_scaler_path)
                    print("SUCCESS: Scaler activo cargado.")
                    if hasattr(self.scaler, 'feature_names_in_') and self.scaler.feature_names_in_ is not None:
                        if isinstance(self.scaler.feature_names_in_, np.ndarray):
                            self.feature_names_ = self.scaler.feature_names_in_.tolist()
                            print(f"INFO: Nombres de características actualizados desde scaler activo ({len(self.feature_names_)}).")
                except Exception as e:
                    print(f"ERROR al cargar scaler activo desde {self.active_scaler_path}: {e}\n{traceback.format_exc()}")
                    self.scaler = None
            else: print(f"INFO: Archivo de scaler activo '{self.active_scaler_path}' no encontrado.")

            if os.path.exists(self.active_test_data_path):
                try:
                    loaded_test_set_tuple = joblib.load(self.active_test_data_path)
                    print("SUCCESS: Conjunto de prueba activo cargado.")
                    if isinstance(loaded_test_set_tuple, tuple) and len(loaded_test_set_tuple) == 3:
                        self.test_set = (loaded_test_set_tuple[0], loaded_test_set_tuple[1])
                        if isinstance(loaded_test_set_tuple[2], list) and self.feature_names_ is None:
                            self.feature_names_ = loaded_test_set_tuple[2] 
                            print(f"INFO: Nombres de características actualizados desde test set activo ({len(self.feature_names_)}).")
                    elif isinstance(loaded_test_set_tuple, tuple) and len(loaded_test_set_tuple) == 2:
                        self.test_set = loaded_test_set_tuple
                        print("WARN: test_set.pkl cargado no contiene nombres de características (formato antiguo).")
                except Exception as e:
                    print(f"ERROR al cargar test set activo desde {self.active_test_data_path}: {e}\n{traceback.format_exc()}")
                    self.test_set = None
            else: print(f"INFO: Archivo de test set activo '{self.active_test_data_path}' no encontrado.")
            
            if self.feature_names_ is None and self.model and hasattr(self.model, 'model') and hasattr(self.model.model, 'exog_names'):
                 model_exog_names_list = [name for name in self.model.model.exog_names if name != 'const']
                 if model_exog_names_list: 
                     self.feature_names_ = model_exog_names_list
                     print(f"INFO: Nombres de características (fallback desde exog_names del modelo) ({len(self.feature_names_)}).")
            elif self.feature_names_ is None and self.model and hasattr(self.model, 'exog_names'): # Fallback para modelos guardados con formato antiguo
                 model_exog_names_list = [name for name in self.model.exog_names if name != 'const']
                 if model_exog_names_list: 
                     self.feature_names_ = model_exog_names_list
                     print(f"INFO: Nombres de características (fallback desde exog_names directos del modelo) ({len(self.feature_names_)}).")


            if self.feature_names_ is None:
                print("ERROR CRÍTICO DE CARGA: No se pudieron determinar los nombres de las características. La detección y evaluación fallarán.")
        except Exception as e:
            print(f"ERROR inesperado durante la carga de componentes: {e}\n{traceback.format_exc()}")
            self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None

    def train_and_save_model(self, df_full_cleaned, sample_fraction_train=0.05): # Entrena el modelo GLM con los datos proporcionados y guarda los componentes activos
        print("INFO: Iniciando proceso de entrenamiento...")
        if df_full_cleaned is None or df_full_cleaned.empty:
            return False, "Error: DataFrame de entrada para entrenamiento está vacío."
        if 'label' not in df_full_cleaned.columns:
            return False, "Error: La columna 'label' (debe ser numérica 0 o 1) no se encuentra en el DataFrame de entrada."

        try:
            if self.feature_names_ is None or not isinstance(self.feature_names_, list) or not self.feature_names_:
                 temp_features = [col for col in df_full_cleaned.columns if col != 'label']
                 if not temp_features:
                     return False, "Error: No se pudieron determinar las características predictoras del DataFrame de entrada (todas las columnas menos 'label')."
                 self.feature_names_ = temp_features
                 print(f"WARN: self.feature_names_ no estaba definido. Se derivaron {len(self.feature_names_)} características de df_full_cleaned.")
            
            current_feature_cols = self.feature_names_
            print(f"INFO: Usando lista de características de referencia ({len(current_feature_cols)}): {current_feature_cols[:5]}...")

            if not pd.api.types.is_numeric_dtype(df_full_cleaned['label']):
                return False, f"Error: La columna 'label' en df_full_cleaned (dtype: {df_full_cleaned['label'].dtype}) no es numérica. DataManager debería haberla convertido a 0 (Attack) / 1 (Benign)."
            y_full_binary = df_full_cleaned['label'].astype(int)
            
            if y_full_binary.isnull().any():
                return False, f"Error: La columna 'label' (numérica) contiene NaNs inesperados: {y_full_binary.isnull().sum()}"

            print(f"INFO: Alineando DataFrame ({df_full_cleaned.shape}) con {len(current_feature_cols)} características esperadas...")
            X_full = df_full_cleaned.reindex(columns=current_feature_cols, fill_value=np.nan)
            
            print(f"INFO: Conversión a numérico para {len(current_feature_cols)} columnas en X_full...")
            for col in current_feature_cols:
                if col in X_full.columns:
                    X_full[col] = pd.to_numeric(X_full[col], errors='coerce')
            
            print("INFO: Reemplazando infinitos por NaN en columnas predictoras de X_full...")
            X_full.replace([np.inf, -np.inf], np.nan, inplace=True)
            
            rows_before_dropna_X = len(X_full)
            X_full.dropna(subset=current_feature_cols, inplace=True)
            print(f"INFO: Filas en X_full antes de dropna: {rows_before_dropna_X}, después: {len(X_full)}")

            if X_full.empty:
                return False, "Error: No quedan datos en X_full después de eliminar NaNs en columnas predictoras."

            y_full_binary_aligned = y_full_binary.loc[X_full.index].dropna()
            X_full_aligned = X_full.loc[y_full_binary_aligned.index]

            if X_full_aligned.empty or y_full_binary_aligned.empty:
                return False, "Error: No quedan datos después de alinear X_full y y_full_binary post-dropna."
            if y_full_binary_aligned.nunique() < 2:
                return False, f"Error: 'label' (y_full_binary_aligned) tiene menos de dos clases únicas ({y_full_binary_aligned.nunique()}) antes del split."

            X_train_full, X_test_eval, y_train_full_binary, y_test_eval_binary = train_test_split(
                X_full_aligned, y_full_binary_aligned, test_size=0.2, random_state=42, stratify=y_full_binary_aligned
            )
            print(f"INFO: Shapes after initial split: X_train_full={X_train_full.shape}, X_test_eval={X_test_eval.shape}")

            # Variable para los datos de entrenamiento que irán al modelo
            X_train_model_fit = X_train_full
            y_train_model_fit = y_train_full_binary

            if 0 < sample_fraction_train < 1.0 :
                if y_train_full_binary.nunique() >= 2 and len(y_train_full_binary) > 1: 
                    print(f"INFO: Aplicando muestreo estratificado ({sample_fraction_train*100:.2f}%) al conjunto de entrenamiento...")
                    # train_size es la fracción a MANTENER. El resto va al segundo conjunto (que descartamos aquí con _)
                    X_train_model_fit, _, y_train_model_fit, _ = train_test_split(
                        X_train_full, y_train_full_binary, 
                        train_size=sample_fraction_train, 
                        random_state=42, 
                        stratify=y_train_full_binary
                    )
                    print(f"INFO: Muestreo aplicado. Nuevas dimensiones para entrenamiento: X={X_train_model_fit.shape}, y={y_train_model_fit.shape}")
                else:
                    print(f"WARN: No se pudo aplicar muestreo estratificado (clases={y_train_full_binary.nunique()}, tamaño={len(y_train_full_binary)}). Usando todo X_train_full ({X_train_full.shape[0]} filas).")
            else:
                print(f"INFO: No se aplicó muestreo (sample_fraction_train={sample_fraction_train}). Usando todo X_train_full ({X_train_full.shape[0]} filas).")
            
            print(f"INFO: Dimensiones FINALES para entrenamiento del modelo: X={X_train_model_fit.shape}, y={y_train_model_fit.shape}")

            if X_train_model_fit.empty: return False, "Error: X_train_model_fit (conjunto de entrenamiento para el modelo) está vacío."

            print("INFO: Escalando datos con MinMaxScaler...")
            self.scaler = MinMaxScaler().fit(X_train_model_fit) 
            X_train_model_scaled = self.scaler.transform(X_train_model_fit)
            X_test_eval_scaled = self.scaler.transform(X_test_eval) 

            X_train_model_scaled_df = pd.DataFrame(X_train_model_scaled, columns=current_feature_cols, index=X_train_model_fit.index)
            X_test_eval_scaled_df = pd.DataFrame(X_test_eval_scaled, columns=current_feature_cols, index=X_test_eval.index)
            
            y_train_model_final_glm = y_train_model_fit.loc[X_train_model_scaled_df.index].astype(int)
            y_test_eval_final = y_test_eval_binary.loc[X_test_eval_scaled_df.index].astype(int)
            print("SUCCESS: Escalado completado.")

            print("INFO: Añadiendo constante y ajustando GLM...")
            X_train_model_final_const_glm = sm.add_constant(X_train_model_scaled_df, has_constant='add')
            X_test_eval_final_const = sm.add_constant(X_test_eval_scaled_df, has_constant='add')
            
            # Asegurar alineación de columnas para el test set que se guarda
            X_test_eval_final_const = X_test_eval_final_const.reindex(columns=X_train_model_final_const_glm.columns, fill_value=0.0)

            if y_train_model_final_glm.nunique() < 2:
                return False, f"Error: y_train_model_final_glm solo tiene {y_train_model_final_glm.nunique()} clase(s)."

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                # Asegurar que los índices estén alineados ANTES de pasar a GLM
                y_train_aligned_glm, X_train_aligned_glm = y_train_model_final_glm.align(X_train_model_final_const_glm, join='inner', axis=0)
                if X_train_aligned_glm.empty or y_train_aligned_glm.empty:
                    return False, "Error: No quedan datos para entrenar GLM después de la alineación final de X e y."
                
                self.model = sm.GLM(y_train_aligned_glm, X_train_aligned_glm, family=sm.families.Binomial()).fit()
            
            print("SUCCESS: Modelo GLM ajustado.")
            
            # Guardar los nombres de las características que realmente usó el modelo (incluyendo 'const')
            model_exog_names = []
            if hasattr(self.model, 'model') and hasattr(self.model.model, 'exog_names'):
                model_exog_names = self.model.model.exog_names
                print(f"DEBUG: Modelo ajustado, exog_names (desde model.model): {model_exog_names}")
            elif hasattr(self.model, 'exog_names'): # Para modelos más antiguos de statsmodels o diferentes estructuras
                model_exog_names = self.model.exog_names
                print(f"DEBUG: Modelo ajustado, exog_names (directo): {model_exog_names}")
            else:
                 print("WARN: Modelo ajustado NO TIENE exog_names. Usando current_feature_cols para guardar test_set.")
            
            # self.feature_names_ debe ser la lista de predictores SIN 'const'
            self.feature_names_ = [name for name in model_exog_names if name != 'const'] if model_exog_names else current_feature_cols
            print(f"INFO: self.feature_names_ establecido/confirmado a ({len(self.feature_names_)}): {self.feature_names_[:5]}...")

            # El X_test_eval_final_const ya fue alineado con X_train_model_final_const_glm (que tiene 'const')
            self.test_set = (X_test_eval_final_const, y_test_eval_final, self.feature_names_)
            
            os.makedirs(self.model_dir, exist_ok=True)
            joblib.dump(self.model, self.active_model_path)
            joblib.dump(self.scaler, self.active_scaler_path)
            joblib.dump(self.test_set, self.active_test_data_path) # Guarda X_test_const, y_test, y feature_names (sin const)
            print("SUCCESS: Modelo, scaler y test set activos guardados.")
            return True, "Modelo reentrenado y componentes activos guardados exitosamente."

        except MemoryError as me: # Capturar MemoryError específicamente
            print(f"ERROR CRITICO DE MEMORIA en entrenamiento: {me}\n{traceback.format_exc()}")
            print("Esto usualmente significa que el conjunto de datos (incluso después del muestreo) es demasiado grande.")
            print("Considera reducir 'sample_fraction_train' aún más, o usar un subconjunto más pequeño de características.")
            self.model = None; self.scaler = None; self.test_set = None
            return False, f"Error de Memoria durante el entrenamiento: {me}"
        except Exception as e:
            self.model = None; self.scaler = None; self.test_set = None
            print(f"ERROR CRITICO en entrenamiento: {e}\n{traceback.format_exc()}")
            return False, f"Error inesperado en entrenamiento: {e}"

    def run_detection(self, df_new_data): # Ejecuta la detección de amenazas en nuevos datos usando el modelo activo
        print("INFO: Iniciando proceso de detección en nuevos datos...")
        if not all([self.model, self.scaler, self.feature_names_]):
            error_msg = "Modelo, scaler o nombres de características (self.feature_names_) no cargados/definidos."
            print(f"ERROR: {error_msg} - Model: {self.model is not None}, Scaler: {self.scaler is not None}, Features: {self.feature_names_ is not None}")
            return {'data': df_new_data, 'metrics': {'report': error_msg}, 'detection_summary': {}}

        df_to_process = df_new_data.copy()
        original_labels_present = 'label' in df_to_process.columns
        
        print(f"DEBUG [Detector-Run]: Columnas en df_to_process (entrada): {df_to_process.columns.tolist()[:10]}...")
        print(f"DEBUG [Detector-Run]: Feature names esperadas (self.feature_names_ ({len(self.feature_names_)})): {self.feature_names_[:10]}...")

        try:
            X_new_aligned = df_to_process.reindex(columns=self.feature_names_, fill_value=np.nan)
        except Exception as e_reindex:
            return {'data': df_new_data, 'metrics': {'report': f"Error crítico durante reindex: {e_reindex}"}, 'detection_summary': {}}
        
        print(f"DEBUG [Detector-Run]: X_new_aligned después de reindex (shape {X_new_aligned.shape})")

        print(f"INFO [Detector-Run]: Conversión a numérico para detección...")
        for col in self.feature_names_:
            if col in X_new_aligned.columns:
                if X_new_aligned[col].dtype == 'object':
                    X_new_aligned[col] = X_new_aligned[col].replace(['Infinity', 'infinity', 'Inf', 'inf', '-Infinity', '-infinity', '-Inf', '-inf', 'NaN', 'nan', ''], np.nan)
                X_new_aligned[col] = pd.to_numeric(X_new_aligned[col], errors='coerce')
        
        print("INFO [Detector-Run]: Reemplazando infinitos por NaN...")
        X_new_aligned.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        initial_len = len(X_new_aligned)
        X_new_aligned.dropna(subset=self.feature_names_, inplace=True)
        print(f"INFO [Detector-Run]: Filas después de dropna: {len(X_new_aligned)} (de {initial_len})")

        X_new_aligned_cleaned = X_new_aligned 
        if X_new_aligned_cleaned.empty:
            empty_df_cols = list(df_new_data.columns) + ['prediction_proba', 'prediction_label_binary', 'prediction_label']
            return {'data': pd.DataFrame(columns=empty_df_cols), 
                    'metrics': {'report': 'DataFrame vacío tras limpieza en run_detection'}, 'detection_summary': {}}

        df_results = df_to_process.loc[X_new_aligned_cleaned.index].copy()

        try:
            print("INFO [Detector-Run]: Escalando nuevos datos...")
            X_new_scaled = self.scaler.transform(X_new_aligned_cleaned[self.feature_names_])
            X_new_scaled_df = pd.DataFrame(X_new_scaled, columns=self.feature_names_, index=X_new_aligned_cleaned.index)
            
            print("INFO [Detector-Run]: Añadiendo constante...")
            X_new_final_const = sm.add_constant(X_new_scaled_df, has_constant='add')
            
            model_expected_cols = None
            if hasattr(self.model, 'model') and hasattr(self.model.model, 'exog_names'):
                model_expected_cols = self.model.model.exog_names
            elif hasattr(self.model, 'exog_names'):
                model_expected_cols = self.model.exog_names

            if model_expected_cols:
                X_new_final_const = X_new_final_const.reindex(columns=model_expected_cols, fill_value=0.0)
            else:
                print("WARN [Detector-Run]: Modelo no tiene exog_names. Usando columnas actuales de X_new_final_const.")
            
            print("INFO [Detector-Run]: Realizando predicciones...")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                prediction_proba = self.model.predict(X_new_final_const) # Probabilidad de ser clase 1 (Benign)

            prediction_proba = pd.Series(prediction_proba, index=X_new_final_const.index)
            prediction_label_binary = (prediction_proba >= self.prediction_threshold).astype(int) # 1 para Benign, 0 para Attack
            
            df_results['prediction_proba'] = prediction_proba 
            df_results['prediction_label_binary'] = prediction_label_binary
            
            label_map_text = {1: 'Benign', 0: 'Attack'} 
            df_results['prediction_label'] = df_results['prediction_label_binary'].map(label_map_text)

            detection_metrics = {}
            if original_labels_present and 'label' in df_results.columns:
                y_true_original_numeric = df_results['label'] # Ya debería ser 0/1 desde DataManager
                if not pd.api.types.is_numeric_dtype(y_true_original_numeric): # Fallback si no es numerico
                    y_true_original_numeric = y_true_original_numeric.map({'Benign': 1, 'Attack': 0, 'BENIGN': 1, 'ATTACK': 0})

                y_true_binary = pd.to_numeric(y_true_original_numeric, errors='coerce').dropna()
                
                common_index = y_true_binary.index.intersection(prediction_label_binary.index)
                y_true_final = y_true_binary.loc[common_index].astype(int)
                y_pred_final = prediction_label_binary.loc[common_index].astype(int)
                
                if not y_true_final.empty and not y_pred_final.empty:
                    acc = accuracy_score(y_true_final, y_pred_final)
                    cm_list = confusion_matrix(y_true_final, y_pred_final).tolist()
                    target_names_for_report = ['Attack', 'Benign'] 
                    
                    unique_true_pred = np.unique(np.concatenate((y_true_final.unique(), y_pred_final.unique()))).astype(int)
                    actual_classes_for_report = [label_map_text[c] for c in sorted(unique_true_pred) if c in label_map_text]

                    if len(unique_true_pred) < 2:
                         report_dict = {"accuracy": acc, "note": f"Reporte limitado, solo {len(unique_true_pred)} clase(s) presentes."}
                    else:
                         report_dict = classification_report(y_true_final, y_pred_final, labels=sorted(unique_true_pred), target_names=actual_classes_for_report, output_dict=True, zero_division=0)

                    detection_metrics = {'accuracy': acc, 'confusion_matrix': cm_list, 'report': report_dict, 'classes': actual_classes_for_report}
                    print(f"SUCCESS: Métricas calculadas. Accuracy: {acc:.4f}")
                else: detection_metrics = {'report': 'Datos insuficientes para métricas post-alineación.'}
            else: detection_metrics = {'report': 'Columna "label" original no encontrada para métricas.'}
                
            detection_summary = df_results['prediction_label'].value_counts().to_dict()
            print(f"INFO [Detector-Run]: Resumen predicciones: {detection_summary}")
            return { 'data': df_results, 'metrics': detection_metrics, 'detection_summary': detection_summary }
        except Exception as e:
            print(f"ERROR crítico durante detección: {e}\n{traceback.format_exc()}")
            empty_df_cols = list(df_new_data.columns) + ['prediction_proba', 'prediction_label_binary', 'prediction_label']
            return {'data': pd.DataFrame(columns=empty_df_cols), 
                    'metrics': {'report': f'Error crítico detección: {str(e)[:200]}'}, 
                    'detection_summary': {}}

    def evaluate_on_test_set(self): # Evalúa el modelo cargado en el conjunto de prueba activo
        print("DEBUG: Evaluando el modelo cargado en el conjunto de prueba...")
        if not all([self.model, self.test_set]) or not isinstance(self.test_set, tuple) or len(self.test_set) < 3:
            return {'accuracy': None, 'report': 'Modelo o Test Set (o sus componentes) no cargado/inválido', 'confusion_matrix': None, 'classes': []}
        
        X_test_final_const, y_test_eval_cleaned, feature_names_from_test_set_eval = self.test_set # feature_names_from_test_set_eval son las features sin 'const'
        
        if not isinstance(X_test_final_const, pd.DataFrame) or X_test_final_const.empty or \
           not isinstance(y_test_eval_cleaned, pd.Series) or y_test_eval_cleaned.empty:
            return {'accuracy': None, 'report': 'Conjunto de prueba (X o y) vacío o tipo incorrecto', 'confusion_matrix': None, 'classes': []}

        try:
            print("INFO: Realizando predicciones en el conjunto de prueba cargado...")
            
            model_expected_cols_eval = None
            if hasattr(self.model, 'model') and hasattr(self.model.model, 'exog_names'):
                model_expected_cols_eval = self.model.model.exog_names
            elif hasattr(self.model, 'exog_names'):
                model_expected_cols_eval = self.model.exog_names

            if model_expected_cols_eval:
                X_test_reindexed_eval = X_test_final_const.reindex(columns=model_expected_cols_eval, fill_value=0.0)
            else:
                print("WARN (evaluate): Modelo no tiene exog_names. Usando columnas de X_test_final_const tal cual.")
                X_test_reindexed_eval = X_test_final_const # Riesgoso si las columnas no coinciden
            
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                test_prediction_proba = self.model.predict(X_test_reindexed_eval) # Probabilidad de Benign (clase 1)
            
            test_prediction_proba = pd.Series(test_prediction_proba, index=X_test_reindexed_eval.index)
            test_prediction_label = (test_prediction_proba >= self.prediction_threshold).astype(int) # 1=Benign, 0=Attack
            
            y_true = y_test_eval_cleaned.astype(int) # Ya es 0/1
            y_pred = test_prediction_label
            
            common_index = y_true.index.intersection(y_pred.index)
            y_true_final = y_true.loc[common_index]
            y_pred_final = y_pred.loc[common_index]

            if y_true_final.empty or y_pred_final.empty:
                 return {'accuracy': None, 'report': 'Test set vacío/desalineado post-predicción para métricas', 'confusion_matrix': None, 'classes': []}

            eval_accuracy = accuracy_score(y_true_final, y_pred_final)
            eval_conf_matrix = confusion_matrix(y_true_final, y_pred_final).tolist()
            target_names_for_report = ['Attack', 'Benign'] # 0=Attack, 1=Benign
            
            unique_true_pred_eval = np.unique(np.concatenate((y_true_final.unique(), y_pred_final.unique()))).astype(int)
            label_map_text = {1: 'Benign', 0: 'Attack'}
            actual_classes_for_report_eval = [label_map_text[c] for c in sorted(unique_true_pred_eval) if c in label_map_text]

            if len(unique_true_pred_eval) < 2:
                eval_report = {"accuracy": eval_accuracy, "note": f"Reporte limitado, solo {len(unique_true_pred_eval)} clase(s) presentes."}
            else:
                 # Asegurar que las etiquetas pasadas a classification_report coincidan con los datos
                 eval_report = classification_report(y_true_final, y_pred_final, labels=sorted(unique_true_pred_eval), target_names=actual_classes_for_report_eval, output_dict=True, zero_division=0)
            
            print(f"SUCCESS: Evaluación completada. Accuracy en test set: {eval_accuracy:.4f}")
            return {'accuracy': eval_accuracy, 'confusion_matrix': eval_conf_matrix, 'report': eval_report, 'classes': actual_classes_for_report_eval}
        except Exception as e:
            print(f"ERROR crítico durante la evaluación del modelo: {e}\n{traceback.format_exc()}")
            return {'accuracy': None, 'report': f'Error crítico evaluación: {str(e)[:200]}', 'confusion_matrix': None, 'classes': []}

    def get_saved_model_list(self): # Lista los modelos guardados en el directorio de modelos, excluyendo el modelo activo y los archivos de scaler/test set
        try:
            active_model_basename = os.path.basename(self.active_model_path)
            models = [f for f in os.listdir(self.model_dir)
                      if f.endswith('.joblib') and f != active_model_basename and '_scaler' not in f and '_test_set' not in f]
            return sorted(models)
        except FileNotFoundError: return []
        except Exception as e: print(f"ERROR [Detector]: Listando modelos: {e}"); return []

    def _get_associated_filenames(self, base_filename): # Obtiene los nombres de archivo asociados para el modelo, scaler y test set basados en un nombre base
        if not base_filename.endswith('.joblib'): base_filename += '.joblib'
        scaler_filename = base_filename.replace('.joblib', '_scaler.joblib')
        test_set_filename = base_filename.replace('.joblib', '_test_set.joblib')
        return base_filename, scaler_filename, test_set_filename

    def save_active_model_as(self, save_name): # Guarda el modelo activo, scaler y test set con un nombre especificado
        if not all([self.model, self.scaler, self.test_set]): return False, "No hay componentes activos para guardar."
        if not save_name: return False, "Se requiere nombre para guardar."
        safe_filename_base = secure_filename(save_name).replace(' ', '_')
        if not safe_filename_base: return False, "Nombre inválido."
        model_savename, scaler_savename, testset_savename = self._get_associated_filenames(safe_filename_base)
        paths = {'model': os.path.join(self.model_dir, model_savename),
                   'scaler': os.path.join(self.model_dir, scaler_savename),
                   'test_set': os.path.join(self.model_dir, testset_savename)}
        if paths['model'] == self.active_model_path: return False, "No puedes guardar con el nombre del modelo activo."
        try:
            print(f"INFO: Guardando modelo activo como '{model_savename}'...")
            if os.path.exists(self.active_model_path): shutil.copy2(self.active_model_path, paths['model'])
            else: raise FileNotFoundError("Modelo activo no encontrado para copiar.")
            if os.path.exists(self.active_scaler_path): shutil.copy2(self.active_scaler_path, paths['scaler'])
            else: print(f"WARN: Scaler activo no encontrado, no se copiará para '{scaler_savename}'.")
            if os.path.exists(self.active_test_data_path): shutil.copy2(self.active_test_data_path, paths['test_set'])
            else: print(f"WARN: Test set activo no encontrado, no se copiará para '{testset_savename}'.")
            return True, f'Modelo guardado como "{model_savename}".'
        except Exception as e:
            print(f"ERROR [Detector]: Guardando modelo como {model_savename}: {e}")
            for p in paths.values(): 
                if os.path.exists(p): 
                    try: os.remove(p) 
                    except: pass
            return False, f"Error al guardar: {e}"

    def load_model_as_active(self, filename_to_load): # Carga un modelo guardado como el modelo activo, actualizando scaler y test set si existen
        if not filename_to_load: return False, "Nombre de archivo requerido."
        if filename_to_load == self.active_model_name: return True, "Este ya es el modelo activo."
        model_loadname, scaler_loadname, testset_loadname = self._get_associated_filenames(filename_to_load)
        paths_to_load = {'model': os.path.join(self.model_dir, model_loadname),
                         'scaler': os.path.join(self.model_dir, scaler_loadname),
                         'test_set': os.path.join(self.model_dir, testset_loadname)}
        active_paths = {'model': self.active_model_path, 
                        'scaler': self.active_scaler_path, 
                        'test_set': self.active_test_data_path}
        if not os.path.exists(paths_to_load['model']): return False, f"Archivo de modelo '{model_loadname}' no existe."
        try:
            print(f"INFO: Cargando '{model_loadname}' como modelo activo...")
            for component_type in ['model', 'scaler', 'test_set']:
                if os.path.exists(paths_to_load[component_type]):
                    shutil.copy2(paths_to_load[component_type], active_paths[component_type])
                    print(f"INFO: {component_type.capitalize()} '{os.path.basename(paths_to_load[component_type])}' copiado como activo.")
                elif component_type != 'model':
                    print(f"WARN: {component_type.capitalize()} asociado '{os.path.basename(paths_to_load[component_type])}' no encontrado. Eliminando {component_type} activo si existe.")
                    if os.path.exists(active_paths[component_type]):
                        try: os.remove(active_paths[component_type])
                        except Exception as e_del: print(f"WARN: No se pudo eliminar {component_type} activo: {e_del}")
            self._load_model_components() 
            if self.model: return True, f"Modelo '{model_loadname}' ahora está activo."
            else: return False, f"Archivos de '{model_loadname}' copiados pero falló carga en memoria."
        except Exception as e:
            print(f"ERROR [Detector]: Cargando modelo {model_loadname} como activo: {e}")
            self._load_model_components() 
            return False, f"Error al cargar modelo: {e}"

    def delete_saved_model(self, filename_to_delete): # Elimina un modelo guardado y sus componentes asociados
        if not filename_to_delete: return False, "Nombre de archivo requerido."
        if filename_to_delete == self.active_model_name: return False, "No puedes eliminar el modelo activo. Carga otro primero."
        model_delname, scaler_delname, testset_delname = self._get_associated_filenames(filename_to_delete)
        paths_to_delete = [os.path.join(self.model_dir, f) for f in [model_delname, scaler_delname, testset_delname]]
        if not os.path.exists(paths_to_delete[0]): return False, f"Archivo de modelo '{model_delname}' no existe."
        deleted_files = []; errors = []
        for p in paths_to_delete:
            if os.path.exists(p):
                try: os.remove(p); deleted_files.append(os.path.basename(p))
                except Exception as e: errors.append(f"{os.path.basename(p)} ({e})")
        msg = f"Modelo '{filename_to_delete}' y asociados ({', '.join(deleted_files)}) eliminados."
        if errors: msg += f" Errores: {', '.join(errors)}."; return False, msg
        return True, msg