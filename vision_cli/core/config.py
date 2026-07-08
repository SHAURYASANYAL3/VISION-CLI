import os
import yaml

CONFIG_FILE = os.path.expanduser("~/.vision_cli_config.yaml")

def load_config():
    """Securely loads or creates the configuration file."""
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "api_keys": {
                "alienvault": "",
                "hibp": "",
                "virustotal": ""
            }
        }
        try:
            fd = os.open(CONFIG_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with open(fd, 'w') as f:
                yaml.dump(default_config, f)
        except Exception:
            pass
        return default_config
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f) or {}
            if "api_keys" not in config:
                config["api_keys"] = {}
            if "virustotal" not in config["api_keys"]:
                config["api_keys"]["virustotal"] = ""
                try:
                    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_TRUNC, 0o600)
                    with open(fd, 'w') as f:
                        yaml.dump(config, f)
                except Exception:
                    pass
            return config
    except Exception:
        return {"api_keys": {}}
