import pytest
import os
import time
import subprocess
import json
from deepdiff import DeepDiff

class TestShowTed:
  TEST_ABS_DIR = os.getcwd()[:os.getcwd().rfind("/test")] + "/test"
  BIN_ABS_DIR = TEST_ABS_DIR + "/bin"

  TEST_SHOW_TED_DIR = TEST_ABS_DIR + "/scenario_test/show_ted"

  def test__bin_ready(self):
    assert os.path.exists(self.BIN_ABS_DIR + "/gobgpd")
    assert os.access(self.BIN_ABS_DIR + "/gobgpd", os.X_OK)
    assert os.path.exists(self.BIN_ABS_DIR + "/polad")
    assert os.access(self.BIN_ABS_DIR + "/polad", os.X_OK)
    assert os.path.exists(self.BIN_ABS_DIR + "/pola")
    assert os.access(self.BIN_ABS_DIR + "/pola", os.X_OK)

      
  def test__srmpls(self, clab_deploy):
    TEST_SRMPLS_DIR = self.TEST_SHOW_TED_DIR + "/srmpls"
    # deploy test environment by containerlab
    clab_deploy(TEST_SRMPLS_DIR)

    # wait for vJunosRouter booting
    while subprocess.run("docker exec -it clab-srmpls-gobgp ping 10.255.0.2 -c 1", shell=True).returncode != 0:
      print("Wait for deploy vJunosRouter ...")
      time.sleep(10)

    print("Wait for pola's TED to finish syncing...")
    time.sleep(60)
    
    output = json.loads(subprocess.run("docker exec -it clab-srmpls-pola /bin/pola -p 50052 ted -j", shell=True, capture_output=True, text=True).stdout)
    print("output is", output)
    with open(TEST_SRMPLS_DIR+"/expected/srmpls.json") as f:
        expected_output = json.load(f)

    # Run "pola ted" cmd and ensure it returns the expected result.
    assert DeepDiff(output, expected_output, ignore_order=True) == {}
