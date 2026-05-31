import yaml
try:
    with open(".github/workflows/codeql.yml", "r") as f:
        data = yaml.safe_load(f)
    print("YAML is valid.")
except Exception as e:
    print(f"Error parsing YAML: {e}")
