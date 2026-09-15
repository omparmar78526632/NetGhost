"""
Machine Learning Traffic Profiler
Uses Gaussian Mixture Models to model network timing patterns
"""

import os
import logging
import numpy as np
from typing import List, Tuple, Optional, Dict
from sklearn.mixture import GaussianMixture
import joblib


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrafficProfiler:
    """
    Traffic profiler using Gaussian Mixture Models.
    Models inter-arrival times from network traffic.
    """
    
    def __init__(self, n_components: int = 3):
        """
        Initialize traffic profiler.
        
        Args:
            n_components: Number of Gaussian components in mixture
        """
        self.n_components = n_components
        self.gmm = None
        self.training_data = None
        self.statistics = {}
    
    def extract_timing_from_pcap(self, pcap_file: str) -> np.ndarray:
        """
        Extract inter-arrival times from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            Array of inter-arrival times in milliseconds
        """
        try:
            from scapy.all import rdpcap
            
            logger.info(f"Reading PCAP file: {pcap_file}")
            packets = rdpcap(pcap_file)
            
            if len(packets) < 2:
                raise ValueError("PCAP file must contain at least 2 packets")
            
            # Extract timestamps
            timestamps = [float(pkt.time) for pkt in packets]
            
            # Compute inter-arrival times (in milliseconds)
            inter_arrival_times = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i-1]) * 1000  # Convert to ms
                if delta > 0:  # Filter out zero or negative deltas
                    inter_arrival_times.append(delta)
            
            logger.info(f"Extracted {len(inter_arrival_times)} inter-arrival times")
            
            return np.array(inter_arrival_times)
            
        except ImportError:
            raise ImportError("Scapy is required for PCAP processing")
        except Exception as e:
            raise RuntimeError(f"Failed to read PCAP: {str(e)}")
    
    def clean_timing_data(
        self,
        timing_data: np.ndarray,
        min_val: float = 0.1,
        max_val: float = 1000.0
    ) -> np.ndarray:
        """
        Clean timing data by removing outliers.
        
        Args:
            timing_data: Raw inter-arrival times
            min_val: Minimum acceptable value (ms)
            max_val: Maximum acceptable value (ms)
        
        Returns:
            Cleaned timing data
        """
        timing_arr = np.asarray(timing_data, dtype=float)
        cleaned = timing_arr[(timing_arr >= min_val) & (timing_arr <= max_val)]
        logger.info(f"Cleaned data: {len(cleaned)}/{len(timing_arr)} samples retained")
        return cleaned
    
    def train_gmm(
        self,
        timing_data: np.ndarray,
        n_components: Optional[int] = None
    ) -> GaussianMixture:
        """
        Train Gaussian Mixture Model on timing data.
        
        Args:
            timing_data: Inter-arrival times in milliseconds
            n_components: Number of components (overrides init value if provided)
        
        Returns:
            Trained GMM model
        """
        if n_components is not None:
            self.n_components = n_components
        
        logger.info(f"Training GMM with {self.n_components} components...")
        
        # Reshape for sklearn
        X = timing_data.reshape(-1, 1)
        self.training_data = X
        
        # Train GMM
        self.gmm = GaussianMixture(
            n_components=self.n_components,
            covariance_type='full',
            random_state=42,
            max_iter=100
        )
        
        self.gmm.fit(X)
        
        # Compute statistics
        self._compute_statistics()
        
        logger.info("GMM training complete")
        self._log_statistics()
        
        return self.gmm
    
    def _compute_statistics(self):
        """Compute statistics from trained GMM"""
        if self.gmm is None:
            return
        
        self.statistics = {
            'n_components': self.n_components,
            'means': self.gmm.means_.flatten().tolist(),
            'variances': self.gmm.covariances_.flatten().tolist(),
            'weights': self.gmm.weights_.tolist(),
            'converged': self.gmm.converged_,
            'n_iter': self.gmm.n_iter_
        }
    
    def _log_statistics(self):
        """Log model statistics"""
        if not self.statistics:
            return
        
        logger.info("GMM Statistics:")
        logger.info(f"  Components: {self.statistics['n_components']}")
        logger.info(f"  Converged: {self.statistics['converged']}")
        logger.info(f"  Iterations: {self.statistics['n_iter']}")
        
        for i in range(self.statistics['n_components']):
            logger.info(f"  Component {i}:")
            logger.info(f"    Mean: {self.statistics['means'][i]:.2f} ms")
            logger.info(f"    Variance: {self.statistics['variances'][i]:.2f}")
            logger.info(f"    Weight: {self.statistics['weights'][i]:.3f}")
    
    def sample(self, n_samples: int = 1):
        """
        Sample from underlying Gaussian Mixture Model.
        Returns (samples, component_indices) matching sklearn GMM interface.
        """
        if self.gmm is None:
            raise RuntimeError("Model not trained. Call train_gmm() first.")
        return self.gmm.sample(n_samples)

    def sample_delay(self, n_samples: int = 1) -> np.ndarray:
        """
        Generate delay samples from trained GMM.
        
        Args:
            n_samples: Number of samples to generate
        
        Returns:
            Array of delay samples in milliseconds
        """
        if self.gmm is None:
            raise RuntimeError("Model not trained. Call train_gmm() first.")
        
        samples, _ = self.gmm.sample(n_samples)
        return samples.flatten()

    def sample_bit_delay(self, bit: int, threshold_ms: float = 75.0) -> float:
        """
        Sample delay conditioned on bit value to ensure robust covert decoding
        while preserving realistic traffic characteristics from the trained GMM components.
        """
        if self.gmm is None:
            return 0.025 if bit == 0 else 0.125
        
        means = self.gmm.means_.flatten()
        covars = self.gmm.covariances_.flatten()
        
        if bit == 0:
            sub_indices = [i for i, m in enumerate(means) if m < threshold_ms - 25.0]
            if not sub_indices:
                sub_indices = [int(np.argmin(means))]
            idx = int(np.random.choice(sub_indices))
            std = float(np.sqrt(covars[idx]))
            val = float(np.random.normal(means[idx], min(std, 3.0)))
            return float(np.clip(val, 15.0, 35.0)) / 1000.0
        else:
            supra_indices = [i for i, m in enumerate(means) if m > threshold_ms + 25.0]
            if not supra_indices:
                supra_indices = [int(np.argmax(means))]
            idx = int(np.random.choice(supra_indices))
            std = float(np.sqrt(covars[idx]))
            val = float(np.random.normal(means[idx], min(std, 5.0)))
            return float(np.clip(val, 115.0, 150.0)) / 1000.0
    
    def save_model(self, filepath: str):
        """
        Save trained model to file.
        
        Args:
            filepath: Path to save model
        """
        if self.gmm is None:
            raise RuntimeError("No model to save")
        
        # Create directory if needed
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Save model and statistics
        model_data = {
            'gmm': self.gmm,
            'n_components': self.n_components,
            'statistics': self.statistics
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """
        Load trained model from file.
        
        Args:
            filepath: Path to model file
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        model_data = joblib.load(filepath)
        
        self.gmm = model_data['gmm']
        self.n_components = model_data['n_components']
        self.statistics = model_data['statistics']
        
        logger.info(f"Model loaded from {filepath}")
        self._log_statistics()
    
    def get_statistics(self) -> Dict:
        """Get model statistics"""
        return self.statistics


def create_synthetic_baseline_pcap(output_file: str, n_packets: int = 1000):
    """
    Create a synthetic baseline PCAP file for demonstration.
    Generates packets with realistic timing patterns.
    
    Args:
        output_file: Path to output PCAP file
        n_packets: Number of packets to generate
    """
    try:
        from scapy.all import IP, TCP, wrpcap
        
        logger.info(f"Creating synthetic PCAP with {n_packets} packets...")
        
        packets = []
        current_time = 1000000.0  # Starting timestamp
        
        for i in range(n_packets):
            # Generate inter-arrival time from mixture of patterns
            # Simulate: fast (10-30ms), medium (50-100ms), slow (200-500ms)
            pattern = np.random.choice([0, 1, 2], p=[0.5, 0.3, 0.2])
            
            if pattern == 0:  # Fast
                delay = np.random.uniform(0.010, 0.030)
            elif pattern == 1:  # Medium
                delay = np.random.uniform(0.050, 0.100)
            else:  # Slow
                delay = np.random.uniform(0.200, 0.500)
            
            current_time += delay
            
            # Create packet
            pkt = IP(dst="192.168.1.100") / TCP(dport=80, sport=1024+i)
            pkt.time = current_time
            packets.append(pkt)
        
        # Write PCAP
        wrpcap(output_file, packets)
        logger.info(f"Synthetic PCAP created: {output_file}")
        
    except ImportError:
        raise ImportError("Scapy is required for PCAP generation")


def test_ml_profiler():
    """Test ML profiler with synthetic data"""
    print("Testing ML Traffic Profiler...")
    
    # Create synthetic timing data
    # Mixture of 3 patterns: fast, medium, slow
    fast = np.random.normal(20, 5, 500)
    medium = np.random.normal(75, 15, 300)
    slow = np.random.normal(200, 40, 200)
    timing_data = np.concatenate([fast, medium, slow])
    timing_data = timing_data[timing_data > 0]  # Remove negative values
    
    print(f"Generated {len(timing_data)} synthetic timing samples")
    
    # Create profiler
    profiler = TrafficProfiler(n_components=3)
    
    # Train model
    profiler.train_gmm(timing_data)
    
    # Generate samples
    samples = profiler.sample_delay(10)
    print(f"\nGenerated samples: {samples}")
    
    # Save model
    test_model_path = "ml/models/test_gmm.pkl"
    profiler.save_model(test_model_path)
    
    # Load model
    profiler2 = TrafficProfiler()
    profiler2.load_model(test_model_path)
    
    # Generate samples from loaded model
    samples2 = profiler2.sample_delay(10)
    print(f"Samples from loaded model: {samples2}")
    
    print("\nML profiler test complete!")


if __name__ == "__main__":
    test_ml_profiler()
