# admin_manager.py

import os
import json
import datetime
import traceback
# No se importa ThreatDetector directamente aquí si la instancia se pasa al constructor

CONFIG_FILE = 'system_config.json' # Nombre del archivo de configuración para persistencia

class AdminManager:
    """
    Gestiona la configuración del sistema y tareas administrativas.
    También maneja la persistencia de la configuración básica (umbral GLM).
    """

    def __init__(self, detector_instance):
        """
        Inicializa el gestor de administración.


        Args:
            detector_instance (ThreatDetector): Una instancia del ThreatDetector
                                                para poder interactuar con él (ej: cambiar umbral).
        """
        print("INFO: AdminManager inicializado.")
        self.detector_ref = detector_instance # Guardar una referencia a la instancia del detector

        # Cargar configuración existente o usar valores por defecto
        self.system_config = self._load_config()

        # Sincronizar el umbral GLM en la config con el del detector actual al inicio
        if self.detector_ref and hasattr(self.detector_ref, 'prediction_threshold'):
            self.system_config['glm_threshold'] = self.detector_ref.prediction_threshold
            print(f"DEBUG: Sincronizando umbral GLM en config con detector: {self.system_config['glm_threshold']}")
        else:
            if 'glm_threshold' not in self.system_config:
                self.system_config['glm_threshold'] = 0.7 # Umbral por defecto
                print(f"WARNING: Instancia de ThreatDetector no válida o sin prediction_threshold al inicio. Usando umbral por defecto: {self.system_config['glm_threshold']}.")
            else:
                 print(f"WARNING: Instancia de ThreatDetector no válida o sin prediction_threshold al inicio. Usando umbral cargado: {self.system_config['glm_threshold']}.")


        print(f"INFO: Configuración inicial del sistema en AdminManager: {self.system_config}")
        self._save_config() # Guardar la configuración inicial o actualizada


    def _load_config(self):
        """Carga la configuración del sistema desde un archivo JSON."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    print(f"INFO: Configuración del sistema cargada desde {CONFIG_FILE}")

                    # Asegurarse de que las claves esperadas existen
                    if 'glm_threshold' not in config:
                        config['glm_threshold'] = 0.7 # Fallback si falta
                        print(f"WARNING: 'glm_threshold' no encontrado en {CONFIG_FILE}. Usando por defecto.")
                    # Añadir validaciones para otras claves aquí si es necesario

                    return config
            except Exception as e:
                print(f"ERROR al cargar la configuración del sistema desde {CONFIG_FILE}: {e}\n{traceback.format_exc()}")
                print("INFO: Usando configuración por defecto.")

        else:
            print(f"INFO: Archivo de configuración del sistema '{CONFIG_FILE}' no encontrado. Usando configuración por defecto.")
        # Configuración por defecto si el archivo no existe o falló la carga
        return {
            'glm_threshold': 0.7

            # Agrega otras configuraciones por defecto aquí si las tienes
        }

    def _save_config(self):
        """Guarda la configuración actual del sistema a un archivo JSON."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.system_config, f, indent=4)
            print(f"INFO: Configuración del sistema guardada en {CONFIG_FILE}")
        except Exception as e:
            print(f"ERROR al guardar la configuración del sistema en {CONFIG_FILE}: {e}\n{traceback.format_exc()}")


    def update_glm_threshold(self, new_threshold):
        """
        Actualiza el umbral de predicción en el detector y en la configuración del AdminManager.
        NOTA: Esta función actualiza el umbral en el detector_ref. La persistencia
        de esta configuración para toda la app (variable global system_config en app.py)
        se maneja en app.py usualmente.
        """
        if self.detector_ref is None:
            return False, "Error: No hay referencia al detector para actualizar el umbral."

        # Llama al método del detector para validarlo y aplicarlo (asumiendo que existe)
        # En tu código, detector.prediction_threshold se actualiza directamente en app.py
        # Esta función en AdminManager podría ser para una lógica de validación más compleja si fuera necesario
        # o para actualizar el umbral solo en el contexto del detector que AdminManager conoce.

        try:
            new_threshold_float = float(new_threshold)
            if not (0.0 < new_threshold_float < 1.0): # Exclusivo 0 y 1
                msg = f"Umbral GLM debe estar entre 0.0 y 1.0 (exclusivo). Valor recibido: {new_threshold_float}"
                print(f"WARN: {msg}")
                return False, msg

            if hasattr(self.detector_ref, 'prediction_threshold'):
                self.detector_ref.prediction_threshold = new_threshold_float
                self.system_config['glm_threshold'] = new_threshold_float # Actualizar la copia local en AdminManager
                self._save_config() # Guardar el cambio en el system_config.json de AdminManager
                msg = f"Umbral de decisión GLM en AdminManager y su detector_ref actualizado a {new_threshold_float:.3f}"
                print(f"INFO: {msg}")
                return True, msg
            else:
                msg = "Error: detector_ref no tiene el atributo 'prediction_threshold'."
                print(f"ERROR: {msg}")
                return False, msg

        except ValueError:
            msg = f"Valor de umbral GLM inválido: {new_threshold}. Debe ser un número."
            print(f"ERROR: {msg}")
            return False, msg
        except Exception as e:
            msg = f"Error inesperado al actualizar umbral GLM en AdminManager: {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")

            return False, msg


    def get_system_logs(self, max_lines=50):
        """
        Obtiene registros simulados del sistema.

        (Placeholder - Debería leer de un archivo de log real o usar el sistema de logging de Python).
        """
        print("INFO: AdminManager obteniendo registros simulados del sistema (Placeholder).")
        # En una implementación real, aquí leerías las últimas N líneas de un archivo
        # de log configurado con el módulo 'logging' de Python.

        current_threshold_display = self.system_config.get('glm_threshold', 'N/A')
        if isinstance(current_threshold_display, (int, float)):
            current_threshold_display = f"{current_threshold_display:.2f}"


        # Simulación de logs con saltos de línea correctos para HTML <pre> o similar
        log_ejemplo_lines = [
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: AdminManager: Simulando logs del sistema.",
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: AdminManager: Configuración actual - Umbral GLM: {current_threshold_display}",
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DEBUG: AdminManager: Verificando estado del detector...",
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: AdminManager: Operación X realizada.",
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] WARN: AdminManager: Condición Y detectada.",
        ]
        # Para simular más logs si se quisiera
        # for i in range(max_lines - len(log_ejemplo_lines)):
        #    log_ejemplo_lines.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Log de relleno {i+1}")

        return log_ejemplo_lines[:max_lines] # Devuelve una lista de strings

    def load_system_config(self):
        """Devuelve la configuración cargada por AdminManager."""
        # Podrías añadir lógica aquí para recargar desde el archivo si es necesario,
        # pero usualmente se carga al inicio.
        print(f"DEBUG: AdminManager.load_system_config() devolviendo: {self.system_config}")
        return self.system_config.copy() # Devolver una copia para evitar modificaciones externas

    def save_system_config(self, config_data):
        """
        Guarda la configuración del sistema proporcionada.
        Esto es útil si app.py quiere que AdminManager persista una config global.
        """
        print(f"DEBUG: AdminManager.save_system_config() recibiendo: {config_data}")
        self.system_config = config_data.copy()
        if self.detector_ref and hasattr(self.detector_ref, 'prediction_threshold'):
             if 'glm_threshold' in self.system_config:
                self.detector_ref.prediction_threshold = self.system_config['glm_threshold']
                print(f"DEBUG: Umbral del detector_ref en AdminManager actualizado a {self.detector_ref.prediction_threshold} vía save_system_config.")
        self._save_config()
        print(f"INFO: AdminManager guardó la configuración del sistema: {self.system_config}")
