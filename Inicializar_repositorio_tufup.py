# repo_init_vinder.py
from pathlib import Path
from tufup.repo import Repository

REPO_DIR = Path("update_repo/repository")
KEYS_DIR = Path("update_repo/keys")

repo = Repository(
    app_name="Vinder",
    repo_dir=REPO_DIR,
    keys_dir=KEYS_DIR,
)

repo.initialize()  # crea dirs, keys, roles, root.json si no existe :contentReference[oaicite:4]{index=4}
repo.save_config()
print("OK: repo inicializado")
print("metadata:", repo.metadata_dir)
print("targets :", repo.targets_dir)
