import importlib
import os

def load_plugins():
    plugins = []
    if not os.path.exists("plugins"):
        os.makedirs("plugins")
    
    for filename in os.listdir("plugins"):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]
            plugin = importlib.import_module(f"plugins.{module_name}")
            plugins.append(plugin)
    return plugins
