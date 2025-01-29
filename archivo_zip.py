import shutil
import os

# Verifica que el archivo existe
exe_path = "pyu-data/new/Vinder.exe"
zip_path = "pyu-data/new/Vinder-1.0.1-win64.zip"

if os.path.exists(exe_path):
    shutil.make_archive(zip_path.replace('.zip', ''), 'zip', root_dir="pyu-data/new", base_dir="Vinder.exe")
    print(f"Archivo comprimido correctamente: {zip_path}")
else:
    print("Error: Vinder.exe no encontrado en la carpeta pyu-data/new/")
