"""
Timing Profile Abstraction for NetGhost Covert Channels.

Research References:
    1. Gianvecchio, S., Wang, H., Wijesekera, D., & Jajodia, S. (2008).
       "Model-Based Covert Timing Channels: Automated Modeling and Evasion."
       Recent Advances in Intrusion Detection (RAID 2008), LNCS 5230, pp. 211-230.
       -> Basis for GMMTimingProfile: fitting a mixture model to legitimate baseline
          IPD traffic and sampling bounded inter-packet delays from the fitted model.

    2. Cabuk, S., Brodley, C. E., & Shields, C. (2004).
       "IP Covert Timing Channels: Design and Detection."
       Proceedings of the 11th ACM Conference on Computer and Communications Security (CCS '04).
       -> Basis for ConstantTimingProfile & NormalVariableTimingProfile baselines.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import numpy as np


VALID_TIMING_PROFILES = ("normal", "constant", "gamma", "gmm")


class TimingProfile(ABC):
    """Abstract base class for packet inter-packet delay (IPD) timing profiles."""

    name: str = "base"
    label: str = "Base Timing Profile"

    @abstractmethod
    def next_delay_s(self, bit: Optional[int] = None) -> float:
        """
        Calculate the next inter-packet delay in seconds.

        Args:
            bit: Optional bit value (0 or 1) for temporal IPD modulation;
                 None for unconditioned IP-ID header channel packet pacing.

        Returns:
            Delay in seconds (always > 0).
        """
        raise NotImplementedError

    def get_metadata(self) -> Dict[str, Any]:
        """Return profile metadata for logging and telemetry."""
        return {"name": self.name, "label": self.label}


class ConstantTimingProfile(TimingProfile):
    """
    Deterministic constant inter-packet delay profile.
    For header channel: uses fixed `delay_ms` between every packet.
    For temporal channel: uses fixed `bit_0_ms` / `bit_1_ms` per bit.
    """

    name = "constant"
    label = "Constant Delay"

    def __init__(
        self,
        delay_ms: float = 50.0,
        bit_0_ms: float = 25.0,
        bit_1_ms: float = 125.0,
    ):
        if delay_ms <= 0 or bit_0_ms <= 0 or bit_1_ms <= 0:
            raise ValueError("Constant delays must be positive.")
        self.delay_ms = float(delay_ms)
        self.bit_0_ms = float(bit_0_ms)
        self.bit_1_ms = float(bit_1_ms)

    def next_delay_s(self, bit: Optional[int] = None) -> float:
        if bit is None:
            return self.delay_ms / 1000.0
        return (self.bit_0_ms if bit == 0 else self.bit_1_ms) / 1000.0

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "delay_ms": self.delay_ms,
            "bit_0_ms": self.bit_0_ms,
            "bit_1_ms": self.bit_1_ms,
        }


class NormalVariableTimingProfile(TimingProfile):
    """
    Normal / Variable Load timing profile.
    Samples inter-packet delays from a bounded Gaussian distribution N(mean, std^2)
    to emulate natural network jitter rather than a fixed sleep interval.
    """

    name = "normal"
    label = "Normal / Variable Load"

    def __init__(
        self,
        mean_ms: float = 35.0,
        std_ms: float = 12.0,
        min_ms: float = 10.0,
        max_ms: float = 150.0,
        bit_0_ms: float = 25.0,
        bit_1_ms: float = 125.0,
        bit_std_ms: float = 4.0,
    ):
        self.mean_ms = float(mean_ms)
        self.std_ms = float(std_ms)
        self.min_ms = float(min_ms)
        self.max_ms = float(max_ms)
        self.bit_0_ms = float(bit_0_ms)
        self.bit_1_ms = float(bit_1_ms)
        self.bit_std_ms = float(bit_std_ms)

    def next_delay_s(self, bit: Optional[int] = None) -> float:
        if bit is None:
            val = float(np.random.normal(self.mean_ms, self.std_ms))
            return float(np.clip(val, self.min_ms, self.max_ms)) / 1000.0
        if bit == 0:
            val = float(np.random.normal(self.bit_0_ms, self.bit_std_ms))
            return float(np.clip(val, max(5.0, self.bit_0_ms - 12.0), self.bit_0_ms + 15.0)) / 1000.0
        val = float(np.random.normal(self.bit_1_ms, self.bit_std_ms))
        return float(np.clip(val, max(50.0, self.bit_1_ms - 20.0), self.bit_1_ms + 25.0)) / 1000.0


class GammaTimingProfile(TimingProfile):
    """
    Gamma-distributed variable-load timing profile (positive skewed IPD).
    """

    name = "gamma"
    label = "Gamma Distribution"

    def __init__(
        self,
        mean_ms: float = 35.0,
        shape: float = 2.0,
        min_ms: float = 10.0,
        max_ms: float = 200.0,
        bit_0_ms: float = 25.0,
        bit_1_ms: float = 125.0,
    ):
        self.mean_ms = float(mean_ms)
        self.shape = float(shape)
        self.min_ms = float(min_ms)
        self.max_ms = float(max_ms)
        self.bit_0_ms = float(bit_0_ms)
        self.bit_1_ms = float(bit_1_ms)

    def next_delay_s(self, bit: Optional[int] = None) -> float:
        if bit is None:
            scale = self.mean_ms / self.shape
            val = float(np.random.gamma(self.shape, scale))
            return float(np.clip(val, self.min_ms, self.max_ms)) / 1000.0
        target = self.bit_0_ms if bit == 0 else self.bit_1_ms
        scale = target / self.shape
        val = float(np.random.gamma(self.shape, scale))
        if bit == 0:
            return float(np.clip(val, max(5.0, target - 12.0), target + 15.0)) / 1000.0
        return float(np.clip(val, max(50.0, target - 20.0), target + 25.0)) / 1000.0


class GMMTimingProfile(TimingProfile):
    """
    Model-Based Covert Timing Profile backed by a trained Gaussian Mixture Model (GMM).
    Follows Gianvecchio et al. (2008) by sampling bounded IPDs from the fitted GMM.
    """

    name = "gmm"
    label = "GMM Fitted Distribution"

    def __init__(
        self,
        profiler,
        min_ms: float = 5.0,
        max_ms: float = 500.0,
        threshold_ms: float = 75.0,
    ):
        if profiler is None or not hasattr(profiler, "is_trained") or not profiler.is_trained():
            raise RuntimeError(
                "GMM timing profile selected, but no trained GMM model is loaded. "
                "Please train or load a GMM model in Traffic Profiler first."
            )
        self.profiler = profiler
        self.min_ms = float(min_ms)
        self.max_ms = float(max_ms)
        self.threshold_ms = float(threshold_ms)

    def next_delay_s(self, bit: Optional[int] = None) -> float:
        if bit is None:
            return self.profiler.sample_next_delay_s(min_ms=self.min_ms, max_ms=self.max_ms)
        return self.profiler.sample_bit_delay(bit, threshold_ms=self.threshold_ms)

    def get_metadata(self) -> Dict[str, Any]:
        stats = self.profiler.get_statistics() if self.profiler else {}
        return {
            "name": self.name,
            "label": self.label,
            "n_components": stats.get("n_components"),
            "n_samples": stats.get("n_samples"),
            "log_likelihood": stats.get("log_likelihood"),
        }


def create_timing_profile(
    profile_name: str,
    gmm_model=None,
    delay_ms: float = 50.0,
    bit_0_ms: float = 25.0,
    bit_1_ms: float = 125.0,
    threshold_ms: float = 75.0,
) -> TimingProfile:
    """
    Factory for constructing a validated TimingProfile instance.

    Raises:
        ValueError: If `profile_name` is unknown.
        RuntimeError: If `profile_name == 'gmm'` and no trained GMM model is available.
    """
    key = (profile_name or "normal").strip().lower()
    if key not in VALID_TIMING_PROFILES:
        raise ValueError(
            f"Invalid timing profile '{profile_name}'. "
            f"Supported profiles: {', '.join(VALID_TIMING_PROFILES)}"
        )

    if key == "constant":
        return ConstantTimingProfile(delay_ms=delay_ms, bit_0_ms=bit_0_ms, bit_1_ms=bit_1_ms)
    if key == "normal":
        return NormalVariableTimingProfile(
            mean_ms=delay_ms if delay_ms != 50.0 else 35.0,
            bit_0_ms=bit_0_ms,
            bit_1_ms=bit_1_ms,
        )
    if key == "gamma":
        return GammaTimingProfile(
            mean_ms=delay_ms if delay_ms != 50.0 else 35.0,
            bit_0_ms=bit_0_ms,
            bit_1_ms=bit_1_ms,
        )
    return GMMTimingProfile(profiler=gmm_model, threshold_ms=threshold_ms)

