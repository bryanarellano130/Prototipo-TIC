# threat_simulator.py

import pandas as pd
import numpy as np
import datetime

class ThreatSimulator:
    """
    Simulador Universal v4: Recetas de datos completas y corregidas para ambos formatos.
    """
    def __init__(self):
        self.simulation_history = []
        print("INFO: ThreatSimulator (Universal v4 con Recetas) inicializado.")

    def _generate_cis2017_data(self, num_records):
        """
        RECETA CORREGIDA Y COMPLETA para CIC-IDS2017.
        Ahora es un espejo de la receta 2018, pero con los nombres de columna largos.
        """
        return {
            'destination_port': np.random.randint(1, 65535, size=num_records),
            'flow_duration': np.random.randint(100, 90000000, size=num_records),
            'total_fwd_packets': np.random.randint(1, 50, size=num_records),
            'total_backward_packets': np.random.randint(0, 50, size=num_records),
            'total_length_of_fwd_packets': np.random.randint(0, 150000, size=num_records),
            'total_length_of_bwd_packets': np.random.randint(0, 150000, size=num_records),
            'fwd_packet_length_max': np.random.rand(num_records) * 1500,
            'fwd_packet_length_min': np.random.rand(num_records) * 50,
            'fwd_packet_length_mean': np.random.rand(num_records) * 150,
            'fwd_packet_length_std': np.random.rand(num_records) * 200,
            'bwd_packet_length_max': np.random.rand(num_records) * 1500,
            'bwd_packet_length_min': np.random.rand(num_records) * 50,
            'bwd_packet_length_mean': np.random.rand(num_records) * 120,
            'bwd_packet_length_std': np.random.rand(num_records) * 180,
            # Estas columnas faltaban o estaban incorrectas en la versión anterior de esta receta
            'flow_bytes_s': np.random.rand(num_records) * 1000000,
            'flow_packets_s': np.random.rand(num_records) * 2000,
            'flow_iat_mean': np.random.rand(num_records) * 1000000,
            'flow_iat_std': np.random.rand(num_records) * 500000,
            'flow_iat_max': np.random.rand(num_records) * 2000000,
            'flow_iat_min': np.random.rand(num_records) * 100000,
            'fwd_iat_total': np.random.rand(num_records) * 80000000,
            'fwd_iat_mean': np.random.rand(num_records) * 1000000,
            'fwd_iat_std': np.random.rand(num_records) * 500000,
            'fwd_iat_max': np.random.rand(num_records) * 2000000,
            'fwd_iat_min': np.random.rand(num_records) * 100000,
            'bwd_iat_total': np.random.rand(num_records) * 80000000,
            'bwd_iat_mean': np.random.rand(num_records) * 1000000,
            'bwd_iat_std': np.random.rand(num_records) * 500000,
            'bwd_iat_max': np.random.rand(num_records) * 2000000,
            'bwd_iat_min': np.random.rand(num_records) * 100000,
            'fwd_psh_flags': np.random.randint(0, 2, size=num_records),
            'bwd_psh_flags': np.random.randint(0, 2, size=num_records),
            'fwd_urg_flags': np.random.randint(0, 2, size=num_records),
            'bwd_urg_flags': np.random.randint(0, 2, size=num_records),
            'fwd_header_length': np.random.choice([20, 32], size=num_records) * np.random.randint(1, 50, size=num_records).clip(min=1),
            'bwd_header_length': np.random.choice([20, 32], size=num_records) * np.random.randint(0, 50, size=num_records).clip(min=0),
            'fwd_packets_s': np.random.rand(num_records) * 1000,
            'bwd_packets_s': np.random.rand(num_records) * 1000,
            'min_packet_length': np.random.rand(num_records) * 30,
            'max_packet_length': np.random.rand(num_records) * 1500,
            'packet_length_mean': np.random.rand(num_records) * 100,
            'packet_length_std': np.random.rand(num_records) * 150,
            'packet_length_variance': (np.random.rand(num_records) * 150)**2,
            'fin_flag_count': np.random.randint(0, 2, size=num_records),
            'syn_flag_count': np.random.randint(0, 2, size=num_records),
            'rst_flag_count': np.random.randint(0, 2, size=num_records),
            'psh_flag_count': np.random.randint(0, 5, size=num_records),
            'ack_flag_count': np.random.randint(0, 20, size=num_records),
            'urg_flag_count': np.random.randint(0, 2, size=num_records),
            'cwe_flag_count': np.random.randint(0, 2, size=num_records),
            'ece_flag_count': np.random.randint(0, 2, size=num_records),
            'down_up_ratio': np.random.rand(num_records) * 3,
            'average_packet_size': np.random.rand(num_records) * 100,
            'avg_fwd_segment_size': np.random.rand(num_records) * 150,
            'avg_bwd_segment_size': np.random.rand(num_records) * 120,
            'fwd_header_length_1': np.random.choice([20, 32], size=num_records) * np.random.randint(1, 50, size=num_records).clip(min=1), # A menudo es un duplicado
            'subflow_fwd_packets': np.random.randint(1, 20, size=num_records),
            'subflow_fwd_bytes': np.random.randint(100, 50000, size=num_records),
            'subflow_bwd_packets': np.random.randint(0, 20, size=num_records),
            'subflow_bwd_bytes': np.random.randint(0, 50000, size=num_records),
            'init_win_bytes_forward': np.random.choice([8192, 65535, 4096, -1], size=num_records),
            'init_win_bytes_backward': np.random.choice([8192, 65535, 4096, -1], size=num_records),
            'act_data_pkt_fwd': np.random.randint(0, 30, size=num_records),
            'min_seg_size_forward': np.random.choice([20, 32, 0], size=num_records),
            'active_mean': np.random.rand(num_records) * 100000,
            'active_std': np.random.rand(num_records) * 50000,
            'active_max': np.random.rand(num_records) * 200000,
            'active_min': np.random.rand(num_records) * 50000,
            'idle_mean': np.random.rand(num_records) * 10000000,
            'idle_std': np.random.rand(num_records) * 5000000,
            'idle_max': np.random.rand(num_records) * 20000000,
            'idle_min': np.random.rand(num_records) * 5000000,
        }

    def _generate_cis2018_data(self, num_records):
        """Genera un DataFrame con el formato y columnas del CSE-CIC-IDS2018."""
        # Esta receta está completa y funciona bien, no necesita cambios.
        return {
            'dst_port': np.random.randint(1, 65535, size=num_records),
            'protocol': np.random.choice([6, 17, 1], p=[0.6, 0.3, 0.1], size=num_records),
            'flow_duration': np.random.randint(100, 90000000, size=num_records),
            'tot_fwd_pkts': np.random.randint(1, 50, size=num_records),
            'tot_bwd_pkts': np.random.randint(0, 50, size=num_records),
            'totlen_fwd_pkts': np.random.randint(0, 150000, size=num_records),
            'totlen_bwd_pkts': np.random.randint(0, 150000, size=num_records),
            'fwd_pkt_len_max': np.random.rand(num_records) * 1500,
            'fwd_pkt_len_min': np.random.rand(num_records) * 50,
            'fwd_pkt_len_mean': np.random.rand(num_records) * 150,
            'fwd_pkt_len_std': np.random.rand(num_records) * 200,
            'bwd_pkt_len_max': np.random.rand(num_records) * 1500,
            'bwd_pkt_len_min': np.random.rand(num_records) * 50,
            'bwd_pkt_len_mean': np.random.rand(num_records) * 120,
            'bwd_pkt_len_std': np.random.rand(num_records) * 180,
            'flow_byts_s': np.random.rand(num_records) * 1000000,
            'flow_pkts_s': np.random.rand(num_records) * 2000,
            'flow_iat_mean': np.random.rand(num_records) * 1000000,
            'flow_iat_std': np.random.rand(num_records) * 500000,
            'flow_iat_max': np.random.rand(num_records) * 2000000,
            'flow_iat_min': np.random.rand(num_records) * 100000,
            'fwd_iat_tot': np.random.rand(num_records) * 80000000,
            'fwd_iat_mean': np.random.rand(num_records) * 1000000,
            'fwd_iat_std': np.random.rand(num_records) * 500000,
            'fwd_iat_max': np.random.rand(num_records) * 2000000,
            'fwd_iat_min': np.random.rand(num_records) * 100000,
            'bwd_iat_tot': np.random.rand(num_records) * 80000000,
            'bwd_iat_mean': np.random.rand(num_records) * 1000000,
            'bwd_iat_std': np.random.rand(num_records) * 500000,
            'bwd_iat_max': np.random.rand(num_records) * 2000000,
            'bwd_iat_min': np.random.rand(num_records) * 100000,
            'fwd_psh_flags': np.random.randint(0, 2, size=num_records),
            'bwd_psh_flags': np.random.randint(0, 2, size=num_records),
            'fwd_urg_flags': np.random.randint(0, 2, size=num_records),
            'bwd_urg_flags': np.random.randint(0, 2, size=num_records),
            'fwd_header_len': np.random.choice([20, 32], size=num_records) * np.random.randint(1, 50, size=num_records).clip(min=1),
            'bwd_header_len': np.random.choice([20, 32], size=num_records) * np.random.randint(0, 50, size=num_records).clip(min=0),
            'fwd_pkts_s': np.random.rand(num_records) * 1000,
            'bwd_pkts_s': np.random.rand(num_records) * 1000,
            'pkt_len_min': np.random.rand(num_records) * 30,
            'pkt_len_max': np.random.rand(num_records) * 1500,
            'pkt_len_mean': np.random.rand(num_records) * 100,
            'pkt_len_std': np.random.rand(num_records) * 150,
            'pkt_len_var': (np.random.rand(num_records) * 150)**2,
            'fin_flag_cnt': np.random.randint(0, 2, size=num_records),
            'syn_flag_cnt': np.random.randint(0, 2, size=num_records),
            'rst_flag_cnt': np.random.randint(0, 2, size=num_records),
            'psh_flag_cnt': np.random.randint(0, 5, size=num_records),
            'ack_flag_cnt': np.random.randint(0, 20, size=num_records),
            'urg_flag_cnt': np.random.randint(0, 2, size=num_records),
            'cwe_flag_count': np.random.randint(0, 2, size=num_records),
            'ece_flag_cnt': np.random.randint(0, 2, size=num_records),
            'down_up_ratio': np.random.rand(num_records) * 3,
            'pkt_size_avg': np.random.rand(num_records) * 100,
            'fwd_seg_size_avg': np.random.rand(num_records) * 150,
            'bwd_seg_size_avg': np.random.rand(num_records) * 120,
            'fwd_byts_b_avg': np.random.randint(0, 1, size=num_records),
            'fwd_pkts_b_avg': np.random.randint(0, 1, size=num_records),
            'fwd_blk_rate_avg': np.random.randint(0, 1, size=num_records),
            'bwd_byts_b_avg': np.random.randint(0, 1, size=num_records),
            'bwd_pkts_b_avg': np.random.randint(0, 1, size=num_records),
            'bwd_blk_rate_avg': np.random.randint(0, 1, size=num_records),
            'subflow_fwd_pkts': np.random.randint(1, 20, size=num_records),
            'subflow_fwd_byts': np.random.randint(100, 50000, size=num_records),
            'subflow_bwd_pkts': np.random.randint(0, 20, size=num_records),
            'subflow_bwd_byts': np.random.randint(0, 50000, size=num_records),
            'init_fwd_win_byts': np.random.choice([8192, 65535, 4096, -1], size=num_records),
            'init_bwd_win_byts': np.random.choice([8192, 65535, 4096, -1], size=num_records),
            'fwd_act_data_pkts': np.random.randint(0, 30, size=num_records),
            'fwd_seg_size_min': np.random.choice([20, 32, 0], size=num_records),
            'active_mean': np.random.rand(num_records) * 100000,
            'active_std': np.random.rand(num_records) * 50000,
            'active_max': np.random.rand(num_records) * 200000,
            'active_min': np.random.rand(num_records) * 50000,
            'idle_mean': np.random.rand(num_records) * 10000000,
            'idle_std': np.random.rand(num_records) * 5000000,
            'idle_max': np.random.rand(num_records) * 20000000,
            'idle_min': np.random.rand(num_records) * 5000000,
        }
    
    def run_simulation(self, config, required_features=None):
        duration = config.get('duration', 60)
        intensity = config.get('intensity', 5)
        attack_types = config.get('attacks', ['DDoS', 'Scan'])
        num_records = duration * 10

        print(f"INFO: Ejecutando simulación universal v4 - Duración: {duration}s, Intensidad: {intensity}")

        # Decidir qué "receta" de datos usar.
        # La heurística es simple: si la lista de características requeridas contiene
        # nombres largos, usamos la receta 2017. De lo contrario, la 2018.
        if required_features and 'total_fwd_packets' in required_features:
            print("INFO: Heurística detectó formato CIS2017. Usando receta de datos 2017.")
            data = self._generate_cis2017_data(num_records)
        else:
            print("INFO: Heurística no detectó formato 2017. Usando receta 2018 por defecto.")
            data = self._generate_cis2018_data(num_records)
        
        data['timestamp'] = pd.to_datetime(pd.Timestamp.now(tz='UTC') + np.arange(num_records) * np.timedelta64(100, 'ms'))
        
        try:
            resultado_simulacion = pd.DataFrame(data)
        except Exception as e_df:
            print(f"ERROR: Creando DataFrame simulado: {e_df}")
            return pd.DataFrame()

        attack_probability = (intensity / 15.0)
        is_attack = np.random.rand(num_records) < attack_probability
        attack_labels_options = attack_types if attack_types else ['Generic Attack']
        attack_labels = np.random.choice(attack_labels_options, size=num_records)
        resultado_simulacion['label'] = np.where(is_attack, attack_labels, 'Benign')
        
        print(f"SUCCESS: Simulación completada. Generados {len(resultado_simulacion)} registros.")
        print(f"Columnas generadas ({len(resultado_simulacion.columns)}): {resultado_simulacion.columns.tolist()[:10]}...")
        return resultado_simulacion

    def add_to_history(self, simulation_info):
        if isinstance(simulation_info, dict):
            self.simulation_history.append(simulation_info)
        else:
            print("WARN: add_to_history recibió información no válida (no es dict).")

    def get_history(self):
        if not hasattr(self, 'simulation_history'): 
            self.simulation_history = []
        return list(self.simulation_history)