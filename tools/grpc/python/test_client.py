#!/usr/bin/env python3

# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import grpc
import pprint
import sys

import api.grpc.pola_pb2 as pola_pb2
import api.grpc.pola_pb2_grpc as pola_pb2_grpc


def main():
    lsp_data = {}
    req = pola_pb2.LspData(
            pcepSessionAddr=bytes([10, 100, 0, 1]),
            srcAddr=bytes([10, 255, 0, 1]),
            dstAddr=bytes([10, 255, 0, 2]),
            labels=[
                {"sid": 16001, "loAddr": bytes([10, 255, 0, 1])},
                {"sid": 16003, "loAddr": bytes([10, 255, 0, 3])}
            ],
            color=1,
            policyName="test_policy"
        )

    with grpc.insecure_channel("localhost:50051") as channel:
        stub = pola_pb2_grpc.PceServiceStub(channel)
        response = stub.CreateLsp(req)

    pprint.pprint(response)


if __name__ == '__main__':
    main()
