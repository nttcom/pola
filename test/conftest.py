import pytest
import subprocess
import os

@pytest.fixture(scope='function')
def clab_deploy():
    def _clab_deploy(dir="./"):
        print("start containerlab")
        os.chdir(dir)
        subprocess.run("clab deploy", shell=True)

    yield _clab_deploy

    print("finish containerlab")
    subprocess.run("clab destroy", shell=True)
