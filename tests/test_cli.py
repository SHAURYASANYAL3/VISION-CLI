import pytest
from vision_cli.core.config import load_config

def test_load_config_creates_file(tmp_path, monkeypatch):
    # Change CONFIG_FILE to point to our temp directory
    config_file = tmp_path / "config.yaml"
    monkeypatch.setattr("vision_cli.core.config.CONFIG_FILE", str(config_file))
    
    config = load_config()
    
    assert config_file.exists()
    assert "api_keys" in config
    assert "virustotal" in config["api_keys"]

def test_load_config_reads_existing(tmp_path, monkeypatch):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("api_keys:\n  virustotal: 'TEST_KEY'\n")
    monkeypatch.setattr("vision_cli.core.config.CONFIG_FILE", str(config_file))
    
    config = load_config()
    assert config["api_keys"]["virustotal"] == "TEST_KEY"
