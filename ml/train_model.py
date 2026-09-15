"""
Training Script for GMM Traffic Model
Trains a Gaussian Mixture Model on baseline traffic
"""

import os
import sys
import argparse
import numpy as np

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from ml.ml_profiler import TrafficProfiler, create_synthetic_baseline_pcap


def main():
    parser = argparse.ArgumentParser(
        description="Train GMM model on network traffic timing"
    )
    parser.add_argument(
        '--pcap',
        type=str,
        default=None,
        help='Path to baseline PCAP file'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='ml/models/gmm_timing.pkl',
        help='Output model file path'
    )
    parser.add_argument(
        '--components',
        type=int,
        default=3,
        help='Number of GMM components'
    )
    parser.add_argument(
        '--create-synthetic',
        action='store_true',
        help='Create synthetic baseline PCAP'
    )
    parser.add_argument(
        '--synthetic-packets',
        type=int,
        default=1000,
        help='Number of packets in synthetic PCAP'
    )
    
    args = parser.parse_args()
    
    # Create synthetic PCAP if requested
    if args.create_synthetic or args.pcap is None:
        synthetic_pcap = 'ml/models/baseline_synthetic.pcap'
        print(f"Creating synthetic baseline PCAP with {args.synthetic_packets} packets...")
        create_synthetic_baseline_pcap(synthetic_pcap, args.synthetic_packets)
        args.pcap = synthetic_pcap
        print(f"✓ Synthetic PCAP created: {synthetic_pcap}\n")
    
    # Initialize profiler
    profiler = TrafficProfiler(n_components=args.components)
    
    # Extract timing from PCAP
    print(f"Extracting timing data from {args.pcap}...")
    timing_data = profiler.extract_timing_from_pcap(args.pcap)
    print(f"✓ Extracted {len(timing_data)} inter-arrival times\n")
    
    # Clean data
    print("Cleaning timing data...")
    cleaned_data = profiler.clean_timing_data(timing_data)
    print(f"✓ Retained {len(cleaned_data)} samples after cleaning\n")
    
    # Train GMM
    print(f"Training GMM with {args.components} components...")
    profiler.train_gmm(cleaned_data)
    print("✓ Training complete\n")
    
    # Display statistics
    stats = profiler.get_statistics()
    print("=" * 60)
    print("GMM MODEL STATISTICS")
    print("=" * 60)
    print(f"Components:     {stats['n_components']}")
    print(f"Converged:      {stats['converged']}")
    print(f"Iterations:     {stats['n_iter']}")
    print()
    
    for i in range(stats['n_components']):
        print(f"Component {i + 1}:")
        print(f"  Mean:         {stats['means'][i]:.2f} ms")
        print(f"  Std Dev:      {np.sqrt(stats['variances'][i]):.2f} ms")
        print(f"  Weight:       {stats['weights'][i]:.3f} ({stats['weights'][i]*100:.1f}%)")
        print()
    
    # Generate sample delays
    print("Sample delays from trained model:")
    samples = profiler.sample_delay(20)
    for i, sample in enumerate(samples, 1):
        print(f"  Sample {i:2d}: {sample:6.2f} ms")
    print()
    
    # Save model
    print(f"Saving model to {args.output}...")
    profiler.save_model(args.output)
    print(f"✓ Model saved successfully\n")
    
    print("=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"\nModel file: {args.output}")
    print("\nYou can now use this model in the sender application")
    print("by selecting the 'GMM/ML' timing profile.")
    print()


if __name__ == "__main__":
    main()
