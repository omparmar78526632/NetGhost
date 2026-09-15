"""
Unit Tests for ML Traffic Profiler
Tests GMM training and timing generation
"""

import pytest
import sys
import os
import numpy as np

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.ml_profiler import TrafficProfiler


class TestMLProfiler:
    """Test suite for ML traffic profiler"""
    
    def test_clean_timing_data(self):
        """Test timing data cleaning"""
        profiler = TrafficProfiler()
        
        # Data with outliers
        data = np.array([1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1500.0])
        
        cleaned = profiler.clean_timing_data(data, min_val=5.0, max_val=500.0)
        
        assert len(cleaned) == 5, "Should remove outliers"
        assert np.min(cleaned) >= 5.0, "Minimum not enforced"
        assert np.max(cleaned) <= 500.0, "Maximum not enforced"
    
    def test_gmm_training(self):
        """Test GMM model training"""
        profiler = TrafficProfiler(n_components=2)
        
        # Create synthetic bimodal data
        cluster1 = np.random.normal(50, 10, 200)
        cluster2 = np.random.normal(150, 20, 200)
        data = np.concatenate([cluster1, cluster2])
        data = data[data > 0]  # Remove negative values
        
        # Train
        gmm = profiler.train_gmm(data)
        
        assert gmm is not None, "Model should be trained"
        assert profiler.gmm.converged_, "Model should converge"
    
    def test_sample_generation(self):
        """Test delay sample generation"""
        profiler = TrafficProfiler(n_components=2)
        
        # Create training data
        data = np.random.normal(100, 20, 500)
        data = data[data > 0]
        
        # Train
        profiler.train_gmm(data)
        
        # Generate samples
        samples = profiler.sample_delay(100)
        
        assert len(samples) == 100, "Should generate requested number of samples"
        assert np.all(samples > 0), "Samples should be positive"
        
        # Also test direct sample() method
        raw_samples, comps = profiler.sample(10)
        assert len(raw_samples) == 10, "Should generate requested number of raw samples"
        assert len(comps) == 10, "Should generate component labels"
    
    def test_model_statistics(self):
        """Test model statistics extraction"""
        profiler = TrafficProfiler(n_components=3)
        
        # Create training data
        data = np.random.normal(100, 20, 300)
        data = data[data > 0]
        
        # Train
        profiler.train_gmm(data)
        
        # Get statistics
        stats = profiler.get_statistics()
        
        assert 'n_components' in stats
        assert 'means' in stats
        assert 'variances' in stats
        assert 'weights' in stats
        assert len(stats['means']) == 3
        assert len(stats['weights']) == 3
        
        # Weights should sum to 1
        assert abs(sum(stats['weights']) - 1.0) < 0.01
    
    def test_model_persistence(self):
        """Test model save and load"""
        profiler1 = TrafficProfiler(n_components=2)
        
        # Create and train
        data = np.random.normal(80, 15, 300)
        data = data[data > 0]
        profiler1.train_gmm(data)
        
        # Save
        model_path = 'ml/models/test_model.pkl'
        profiler1.save_model(model_path)
        
        # Load
        profiler2 = TrafficProfiler()
        profiler2.load_model(model_path)
        
        # Compare statistics
        stats1 = profiler1.get_statistics()
        stats2 = profiler2.get_statistics()
        
        assert stats1['n_components'] == stats2['n_components']
        assert np.allclose(stats1['means'], stats2['means'])
        
        # Clean up
        if os.path.exists(model_path):
            os.remove(model_path)
    
    def test_multimodal_distribution(self):
        """Test GMM on multimodal distribution"""
        profiler = TrafficProfiler(n_components=3)
        
        # Create 3-mode distribution
        mode1 = np.random.normal(30, 5, 200)
        mode2 = np.random.normal(80, 10, 300)
        mode3 = np.random.normal(200, 30, 200)
        
        data = np.concatenate([mode1, mode2, mode3])
        data = data[data > 0]
        
        # Train
        profiler.train_gmm(data)
        
        # Check that model captured modes
        stats = profiler.get_statistics()
        means = sorted(stats['means'])
        
        # Means should be roughly near the original modes
        assert means[0] < 50, "First mode not captured"
        assert 60 < means[1] < 120, "Second mode not captured"
        assert means[2] > 150, "Third mode not captured"
    
    def test_sample_statistics(self):
        """Test that generated samples match training distribution"""
        profiler = TrafficProfiler(n_components=2)
        
        # Create known distribution
        data = np.random.normal(100, 20, 1000)
        data = data[data > 0]
        
        # Train
        profiler.train_gmm(data)
        
        # Generate many samples
        samples = profiler.sample_delay(5000)
        
        # Check statistics are similar
        data_mean = np.mean(data)
        sample_mean = np.mean(samples)
        
        # Means should be close (within 10%)
        assert abs(sample_mean - data_mean) / data_mean < 0.1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
