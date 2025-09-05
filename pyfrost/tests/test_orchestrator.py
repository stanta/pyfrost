"""Tests for orchestrator-related endpoints using in-process Flask app.

Updated to reflect blueprint refactor (/pyfrost prefix) and async views.
"""

import json
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from flask import Flask

from pyfrost.network.node import Node
from pyfrost.network.abstract import DataManager, NodesInfo


class MockDataManager(DataManager):
    def __init__(self):
        self.keys = {}
        self.nonces = {}

    def get_key(self, key_id: str):
        return self.keys.get(key_id)

    def set_key(self, key_id: str, key_data: dict):
        self.keys[key_id] = key_data

    def get_nonce(self, nonce_id: str):
        return self.nonces.get(nonce_id)

    def set_nonce(self, nonce_id: str, nonce_data: dict):
        self.nonces[nonce_id] = nonce_data

    def remove_nonce(self, nonce_id: str):
        self.nonces.pop(nonce_id, None)

    def remove_key(self, key_id: str):
        self.keys.pop(key_id, None)


class MockNodesInfo(NodesInfo):
    def __init__(self, nodes_config):
        self.nodes = nodes_config

    def lookup_node(self, node_id: str) -> dict:
        return self.nodes.get(int(node_id))

    def get_all_nodes(self, n: int = None) -> dict:
        return self.nodes


class TestOrchestratorAPI(unittest.TestCase):
    def setUp(self):
        nodes_config = {
            1: {'host': '127.0.0.1', 'port': 5001, 'public_key': '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'},
            2: {'host': '127.0.0.1', 'port': 5002, 'public_key': '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'},
            3: {'host': '127.0.0.1', 'port': 5003, 'public_key': '038c2c0966b4a44733418775459492549333340446241413034213a71831dc7625'},
        }
        self.data_manager = MockDataManager()
        self.nodes_info = MockNodesInfo(nodes_config)
        self.node = Node(
            data_manager=self.data_manager,
            node_id=1,
            private=123456789,
            nodes_info=self.nodes_info,
            caller_validator=lambda addr, path: True,
            data_validator=lambda data: data,
            eth_rpc_url=None,
        )
        app = Flask(__name__)
        self.node.register_blueprints(app)
        app.testing = True
        self.client = app.test_client()

    @patch('pyfrost.network.node.Node._make_request', new_callable=AsyncMock)
    def test_create_wallet(self, mock_make_request):
        def mock_dkg_flow(session, node_id, endpoint, data):
            if endpoint == '/v1/dkg/round1':
                return {'broadcast': {'sender_id': node_id}, 'validation': 'v', 'status': 'SUCCESSFUL'}
            if endpoint == '/v1/dkg/round2':
                return {'broadcast': [{'receiver_id': '2'}, {'receiver_id': '3'}], 'status': 'SUCCESSFUL'}
            if endpoint == '/v1/dkg/round3':
                return {'data': {'dkg_public_key': 'final_pk', 'public_share': 'ps'}, 'status': 'SUCCESSFUL'}
            return {}
        mock_make_request.side_effect = mock_dkg_flow
        resp = self.client.post('/pyfrost/v1/wallets', json={'party': ['2', '3'], 'threshold': 2, 'key_type': 'schnorr'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['dkg_public_key'], 'final_pk')
        self.assertIn('final_pk', self.node.created_wallets)

    def test_list_wallets(self):
        self.node.created_wallets = ['k1', 'k2']
        self.data_manager.set_key('k1', {'key_type': 'ETH'})
        resp = self.client.get('/pyfrost/v1/wallets')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data['wallets']), 2)
        self.assertTrue(data['wallets'][0]['has_local_share'])

    def test_get_wallet_info(self):
        self.node.created_wallets = ['k1']
        self.data_manager.set_key('k1', {'key_type': 'BTC'})
        resp = self.client.get('/pyfrost/v1/wallets/k1')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['wallet_info']['key_type'], 'BTC')
        resp404 = self.client.get('/pyfrost/v1/wallets/unknown')
        self.assertEqual(resp404.status_code, 404)

    def test_signing_request_lifecycle(self):
        payload = {'dkg_public_key': 'pk', 'message': 'm', 'party': ['2', '3']}
        create = self.client.post('/pyfrost/v1/signing-requests', json=payload)
        self.assertEqual(create.status_code, 200)
        request_id = create.get_json()['request_id']
        get_resp = self.client.get(f'/pyfrost/v1/signing-requests/{request_id}')
        self.assertEqual(get_resp.status_code, 200)
        reject = self.client.post(f'/pyfrost/v1/signing-requests/{request_id}/reject')
        self.assertEqual(reject.status_code, 200)
        reject_again = self.client.post(f'/pyfrost/v1/signing-requests/{request_id}/reject')
        self.assertEqual(reject_again.status_code, 400)

    @patch('pyfrost.network.node.Node._orchestrate_signature_creation', new_callable=AsyncMock)
    def test_execute_signing_request(self, mock_orchestrate):
        mock_orchestrate.return_value = {'signature': 'sig'}
        req_id = 'rid'
        self.node.signing_requests[req_id] = {'dkg_public_key': 'pk', 'message': 'm', 'party': ['2','3'], 'status': 'PENDING'}
        resp = self.client.post(f'/pyfrost/v1/signing-requests/{req_id}/execute')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'EXECUTED')

    @patch('pyfrost.network.node.Node._orchestrate_signature_creation', new_callable=AsyncMock)
    @patch('pyfrost.network.node.Web3')
    def test_send_eth_transaction(self, MockWeb3, mock_orchestrate):
        # Provide a 33-byte compressed secp256k1 public key hex (starts with 02)
        # Use generator point compressed SEC1 representation for validity
        mock_orchestrate.return_value = {
            'public_nonce': '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            'signature': 123
        }
        instance = MagicMock()
        instance.is_connected.return_value = True
        instance.eth.gas_price = 100
        instance.eth.get_transaction_count.return_value = 1
        instance.eth.chain_id = 1
        instance.eth.send_raw_transaction.return_value = b'hh'
        instance.to_checksum_address.side_effect = lambda x: x
        instance.to_wei.side_effect = lambda x, y: x
        instance.eth.account._prepare_transaction.return_value = MagicMock(hash=b'hh')
        instance.eth.account._create_transaction_with_signature.return_value = MagicMock(rawTransaction=b'raw_tx')
        self.node.w3 = instance
        dkg_pk = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        resp = self.client.post(f'/pyfrost/v1/wallets/{dkg_pk}/transactions', json={'to':'0xA','value_in_eth':0.1,'party':['2','3']})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'SUCCESSFUL')


if __name__ == '__main__':
    unittest.main()
