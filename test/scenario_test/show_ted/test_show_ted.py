import os
import time
import subprocess
import json
import paramiko
from deepdiff import DeepDiff


class TestShowTed:
    TEST_ABS_DIR = os.getcwd()[: os.getcwd().rfind("/test")] + "/test"
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

        print("Wait for deploy vJunosRouter for 2 minutes")
        time.sleep(120)

        # wait for vJunosRouter booting
        while (
            subprocess.run(
                "docker exec -it clab-srmpls-gobgp ping 10.255.0.2 -c 1", shell=True
            ).returncode
            != 0
        ):
            print("Wait for deploy vJunosRouter ...")
            time.sleep(10)

        print("Wait for pola's TED to finish syncing...")
        time.sleep(10)

        output = json.loads(
            subprocess.run(
                "docker exec -it clab-srmpls-pola /bin/pola -p 50052 ted -j",
                shell=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        print("output is", output)
        with open(TEST_SRMPLS_DIR + "/expected/srmpls.json") as f:
            expected_output = json.load(f)

        # Run "pola ted" cmd and ensure it returns the expected result.
        assert DeepDiff(output, expected_output, ignore_order=True) == {}

        print(
            "Disable interface ge-0/0/0 on clab-srmpls-jun-rt1 to test real-time TED sync..."
        )
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname="clab-srmpls-jun-rt1", username="admin", password="admin@123"
        )
        stdin, stdout, stderr = ssh_client.exec_command(
            "configure; set interfaces ge-0/0/0 disable; commit"
        )
        print(stdout.read().decode())
        print(stderr.read().decode())

        time.sleep(30)  # wait for pola to sync
        output2 = json.loads(
            subprocess.run(
                "docker exec -it clab-srmpls-pola /bin/pola -p 50052 ted -j",
                shell=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        print("output is", output2)
        with open(TEST_SRMPLS_DIR + "/expected/srmpls2.json") as f:
            expected_output2 = json.load(f)

        # Run "pola ted" cmd and ensure it returns the expected result.
        assert DeepDiff(output2, expected_output2, ignore_order=True) == {}

    def test__srv6_usid(self, clab_deploy):
        TEST_SRV6_USID_DIR = self.TEST_SHOW_TED_DIR + "/srv6-usid"
        # deploy test environment by containerlab
        clab_deploy(TEST_SRV6_USID_DIR)

        print("Wait for deploy vJunosRouter for 2 minutes")
        time.sleep(120)

        # wait for vJunosRouter booting
        while (
            subprocess.run(
                "docker exec -it clab-srv6-usid-gobgp ping fd00:ffff::2 -c 1",
                shell=True,
            ).returncode
            != 0
        ):
            print("Wait for deploy vJunosRouter ...")
            time.sleep(10)

        print("Wait for pola's TED to finish syncing...")
        time.sleep(10)

        output = json.loads(
            subprocess.run(
                "docker exec -it clab-srv6-usid-pola /bin/pola -p 50052 ted -j",
                shell=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        print("output is", output)
        with open(TEST_SRV6_USID_DIR + "/expected/srv6-usid.json") as f:
            expected_output = json.load(f)

        # Run "pola ted" cmd and ensure it returns the expected result.
        assert DeepDiff(output, expected_output, ignore_order=True) == {}

        print(
            "Disable interface ge-0/0/0 on clab-srv6-usid-jun-rt1 to test real-time TED sync..."
        )
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname="clab-srv6-usid-jun-rt1", username="admin", password="admin@123"
        )
        stdin, stdout, stderr = ssh_client.exec_command(
            "configure; set interfaces ge-0/0/0 disable; commit"
        )
        print(stdout.read().decode())
        print(stderr.read().decode())

        time.sleep(30)  # wait for pola to sync
        output2 = json.loads(
            subprocess.run(
                "docker exec -it clab-srv6-usid-pola /bin/pola -p 50052 ted -j",
                shell=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        print("output is", output2)
        with open(TEST_SRV6_USID_DIR + "/expected/srv6-usid2.json") as f:
            expected_output2 = json.load(f)

        # Run "pola ted" cmd and ensure it returns the expected result.
        assert DeepDiff(output2, expected_output2, ignore_order=True) == {}
