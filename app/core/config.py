
from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, Field


# Application settings
class ApplicationConfig(BaseModel):
    name: str
    version: str
    simulation_mode: bool


# Filesystem monitoring settings
class MonitoringConfig(BaseModel):
    directories: List[str]
    recursive: bool


# Detection settings
class DetectionThresholds(BaseModel):
    rapid_modification: int = Field(gt=0)
    mass_rename: int = Field(gt=0)
    high_entropy: float = Field(ge=0, le=8)
    cpu_spike: int = Field(ge=0, le=100)


class DetectionConfig(BaseModel):
    window_seconds: int = Field(gt=0)
    thresholds: DetectionThresholds


# Threat scoring settings
class ScoringConfig(BaseModel):
    rapid_encryption: int = Field(ge=0)
    mass_rename: int = Field(ge=0)
    high_entropy: int = Field(ge=0)
    cpu_spike: int = Field(ge=0)
    unknown_program: int = Field(ge=0)


# Incident response settings
class ResponseConfig(BaseModel):
    simulation_mode: bool
    copy_evidence: bool
    terminate_process: bool


# Database settings
class DatabaseConfig(BaseModel):
    path: str


# Quarantine settings
class QuarantineConfig(BaseModel):
    path: str


# Complete application configuration
class RDRSConfig(BaseModel):
    application: ApplicationConfig
    monitoring: MonitoringConfig
    detection: DetectionConfig
    scoring: ScoringConfig
    response: ResponseConfig
    database: DatabaseConfig
    quarantine: QuarantineConfig


def load_config(config_path: str = "config.yaml") -> RDRSConfig:
    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file)

    if not isinstance(raw_config, dict):
        raise ValueError("Configuration must contain a YAML mapping.")

    return RDRSConfig.model_validate(raw_config)
