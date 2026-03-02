import pytest
import subprocess


@pytest.fixture(scope="function")
def clab_deploy():
    lab_dirs = []

    def deploy(lab_dir="."):
        lab_dirs.append(lab_dir)
        print("start containerlab")
        subprocess.run(
            ["clab", "deploy", "--reconfigure"],
            check=True,
            cwd=lab_dir,
        )

    yield deploy

    for lab_dir in lab_dirs:
        print("finish containerlab")
        subprocess.run(
            ["clab", "destroy", "--cleanup"],
            check=False,
            cwd=lab_dir,
        )
