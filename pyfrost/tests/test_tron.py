import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from flask import Flask

from pyfrost.network.node import Node
from pyfrost.tests.test_orchestrator import MockDataManager, MockNodesInfo


class TestTronAPI(unittest.TestCase):
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
            tron_rpc_url="https://api.nileex.io",
        )
        app = Flask(__name__)
        self.node.register_blueprints(app)
        app.testing = True
        self.client = app.test_client()

    @patch('pyfrost.network.node.Node._orchestrate_signature_creation', new_callable=AsyncMock)
    def test_send_tron_transaction(self, mock_orchestrate):
        mock_orchestrate.return_value = {
            'public_nonce': '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            'signature': 123
        }

        instance = MagicMock()
        instance.is_connected.return_value = True
        instance.trx.broadcast.return_value = {'txid': 'abc123'}
        self.node.tron = instance

        dkg_pk = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        payload = {
            'chain': 'TRON',
            'to': 'TBC1qg21pBfEwS5g1N5A4gJgJgJgJgJgJgJgJg',
            'value_in_sun': 1000000,
            'party': ['2', '3']
        }
        
        resp = self.client.post(f'/pyfrost/v1/wallets/{dkg_pk}/transactions', json=payload)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'SUCCESSFUL')


if __name__ == '__main__':
    unittest.main()