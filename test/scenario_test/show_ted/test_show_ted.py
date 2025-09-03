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

  def test__gobgpd_bin_ready(self):
    assert os.path.exists(self.BIN_ABS_DIR + "/gobgpd")
    assert os.access(self.BIN_ABS_DIR + "/gobgpd", os.X_OK)

      
  def test__test1_show_ted_srmpls(self, clab_deploy):
    TEST1_DIR = self.TEST_SHOW_TED_DIR + "/test1"
    # clab で gobgp と pola を立てる
    clab_deploy(TEST1_DIR)

    # 全ての container が起動しきるまで wait
    while subprocess.run("docker exec -it clab-test1_show_ted_srmpls-gobgp ping 10.100.0.1 -c 1", shell=True).returncode != 0:
      print("Wait for deploy vJunos...")
      time.sleep(10)
      
    # ted の同期待ち
    print("Wait for pola's TED to finish syncing...")
    time.sleep(60)

    output = json.loads(subprocess.run("docker exec -it clab-test1_show_ted_srmpls-pola /bin/pola -p 50052 ted -j", shell=True, capture_output=True, text=True).stdout)
    with open(TEST1_DIR+"/expected/show_ted_srmpls.json") as f:
        expected_output = json.load(f)

    # gobgp に gobgp add command で lsdb を追加する
    # pola で show ted して、期待する結果が得られることを確認する
    assert DeepDiff(output, expected_output, ignore_order=True) == {}
