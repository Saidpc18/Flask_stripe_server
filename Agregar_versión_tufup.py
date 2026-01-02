# repo_add_bundle_vinder.py
from pathlib import Path
from tufup.repo import Repository

BUNDLE_DIR = Path(r"dist/Vinder")   # carpeta del bundle final
NEW_VERSION = "1.0.5"              # tu versión

repo = Repository.from_config()

repo.add_bundle(
    new_bundle_dir=BUNDLE_DIR,
    new_version=NEW_VERSION,
    skip_patch=False,
    required=False,
)  # crea archive y (si hay anterior) patch :contentReference[oaicite:6]{index=6}

# Firma y publica cambios (NECESITA acceso a llaves privadas)
repo.publish_changes(private_key_dirs=[Path("update_repo/keys")]) :contentReference[oaicite:7]{index=7}

print("OK: agregado", NEW_VERSION)
