# Canary: unsafe YAML load.
def load(x)
  YAML.load(x)
end
