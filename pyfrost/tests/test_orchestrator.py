import unittest
import json
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

from pyfrost.network.node import Node
from pyfrost.frost import Key, KeyGen
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
        if nonce_id in self.nonces:
            del self.nonces[nonce_id]

    def remove_key(self, key_id: str):
        if key_id in self.keys:
            del self.keys[key_id]


class MockNodesInfo(NodesInfo):
    def __init__(self, nodes_config):
        self.nodes = nodes_config

    def lookup_node(self, node_id: str) -> dict:
        # node_id might be int or str
        return self.nodes.get(int(node_id))

    def get_all_nodes(self, n: int = None) -> dict:
        return self.nodes


class TestOrchestratorAPI(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self.nodes_config = {
            1: {'host': '127.0.0.1', 'port': 5001, 'public_key': '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'},
            2: {'host': '127.0.0.1', 'port': 5002, 'public_key': '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'},
            3: {'host': '127.0.0.1', 'port': 5003, 'public_key': '038c2c0966b4a44733418775459492549333340446241413034213a71831dc7625'},
        }
        
        mock_data_manager = MockDataManager()
        mock_nodes_info = MockNodesInfo(self.nodes_config)
        dummy_private_key = 123456789

        # The orchestrator node
        self.orchestrator_node = Node(
            data_manager=mock_data_manager,
            node_id=1,
            private=dummy_private_key,
            nodes_info=mock_nodes_info,
            caller_validator=lambda addr, path: True,
            data_validator=lambda data: data,
            eth_rpc_url=None
        )
        self.app = self.orchestrator_node.blueprint
        # We need to create a new app for testing to avoid context issues
        from flask import Flask
        test_app = Flask(__name__)
        test_app.register_blueprint(self.app)
        test_app.testing = True
        self.client = test_app.test_client()

    def tearDown(self):
        self.loop.close()

    def run_async(self, coro):
        return self.loop.run_until_complete(coro)

    @patch('pyfrost.network.node.Node._make_request', new_callable=AsyncMock)
    def test_create_wallet(self, mock_make_request):
        """
        Test the /v1/wallets endpoint for creating a new wallet.
        """
        # --- Mocking the DKG process ---
        
        # Mock responses for DKG rounds
        def mock_dkg_flow(session, node_id, endpoint, data):
            if endpoint == '/v1/dkg/round1':
                return {
                    'broadcast': {'sender_id': node_id}, # simplified
                    'validation': 'dummy_validation',
                    'status': 'SUCCESSFUL'
                }
            elif endpoint == '/v1/dkg/round2':
                 return {
                    'broadcast': [{'receiver_id': '2'}, {'receiver_id': '3'}], # simplified
                    'status': 'SUCCESSFUL'
                }
            elif endpoint == '/v1/dkg/round3':
                return {
                    'data': {
                        'dkg_public_key': 'a_final_public_key',
                        'public_share': 'a_public_share'
                    },
                    'status': 'SUCCESSFUL'
                }
            return {}

        mock_make_request.side_effect = mock_dkg_flow
        
        # --- Call the endpoint ---
        response = self.client.post('/v1/wallets', data=json.dumps({
            'party': ['2', '3'],
            'threshold': 2,
            'key_type': 'schnorr'
        }), content_type='application/json')

        # --- Assertions ---
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('dkg_public_key', data)
        self.assertEqual(data['dkg_public_key'], 'a_final_public_key')
        self.assertIn('a_final_public_key', self.orchestrator_node.created_wallets)

    def test_list_wallets(self):
        """
        Test the /v1/wallets GET endpoint for listing wallets.
        """
        # Pre-populate wallets
        self.orchestrator_node.created_wallets = ['pub_key_1', 'pub_key_2']
        self.orchestrator_node.data_manager.set_key('pub_key_1', {'key_type': 'ETH'})

        response = self.client.get('/v1/wallets')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data['wallets']), 2)
        self.assertEqual(data['wallets'][0]['dkg_public_key'], 'pub_key_1')
        self.assertTrue(data['wallets'][0]['has_local_share'])
        self.assertEqual(data['wallets'][0]['key_type'], 'ETH')
        self.assertEqual(data['wallets'][1]['dkg_public_key'], 'pub_key_2')
        self.assertFalse(data['wallets'][1]['has_local_share'])

    def test_get_wallet_info(self):
        """
        Test the /v1/wallets/<dkg_public_key> GET endpoint.
        """
        self.orchestrator_node.created_wallets = ['pub_key_1']
        self.orchestrator_node.data_manager.set_key('pub_key_1', {'key_type': 'BTC'})

        # Test for existing wallet
        response = self.client.get('/v1/wallets/pub_key_1')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['wallet_info']['dkg_public_key'], 'pub_key_1')
        self.assertTrue(data['wallet_info']['has_local_share'])
        self.assertEqual(data['wallet_info']['key_type'], 'BTC')

        # Test for non-existing wallet
        response = self.client.get('/v1/wallets/non_existent_key')
        self.assertEqual(response.status_code, 404)

    def test_signing_request_lifecycle(self):
        """
        Test the full lifecycle of a signing request: create, get, reject.
        """
        # 1. Create
        create_payload = {
            'dkg_public_key': 'a_pub_key',
            'message': 'message_to_sign',
            'party': ['2', '3']
        }
        response = self.client.post('/v1/signing-requests', data=json.dumps(create_payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        request_id = data['request_id']
        self.assertIn(request_id, self.orchestrator_node.signing_requests)
        self.assertEqual(self.orchestrator_node.signing_requests[request_id]['status'], 'PENDING')

        # 2. Get Details
        response = self.client.get(f'/v1/signing-requests/{request_id}')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['signing_request']['message'], 'message_to_sign')

        # 3. Reject
        response = self.client.post(f'/v1/signing-requests/{request_id}/reject')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.orchestrator_node.signing_requests[request_id]['status'], 'REJECTED')

        # 4. Try to reject again (should fail)
        response = self.client.post(f'/v1/signing-requests/{request_id}/reject')
        self.assertEqual(response.status_code, 400)

    @patch('pyfrost.network.node.Node._orchestrate_signature_creation', new_callable=AsyncMock)
    def test_execute_signing_request(self, mock_orchestrate_sig):
        """
        Test the execution of a signing request.
        """
        mock_orchestrate_sig.return_value = {'signature': 'mock_signature'}
        
        request_id = 'test_exec_req'
        self.orchestrator_node.signing_requests[request_id] = {
            "dkg_public_key": 'a_pub_key',
            "message": 'a_message',
            "party": ['2', '3'],
            "status": 'PENDING',
        }

        response = self.client.post(f'/v1/signing-requests/{request_id}/execute')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'EXECUTED')
        self.assertEqual(data['signature_data']['signature'], 'mock_signature')
        self.assertEqual(self.orchestrator_node.signing_requests[request_id]['status'], 'EXECUTED')

    @patch('pyfrost.network.node.Node._orchestrate_signature_creation', new_callable=AsyncMock)
    @patch('pyfrost.network.node.Web3')
    def test_send_eth_transaction(self, MockWeb3, mock_orchestrate_sig):
        """
        Test the /v1/wallets/<dkg_public_key>/transactions endpoint for sending an ETH tx.
        """
        # --- Setup Mocks ---
        # Mock Web3 instance and its methods
        mock_w3_instance = MagicMock()
        mock_w3_instance.is_connected.return_value = True
        mock_w3_instance.eth.gas_price = 10**10 
        mock_w3_instance.eth.get_transaction_count.return_value = 5
        mock_w3_instance.eth.chain_id = 1
        mock_w3_instance.eth.send_raw_transaction.return_value = b'a_mock_tx_hash'
        mock_w3_instance.to_checksum_address.side_effect = lambda x: x
        mock_w3_instance.to_wei.side_effect = lambda x, y: x
        mock_w3_instance.eth.account._prepare_transaction.return_value = MagicMock(hash=b'some_hash')
        mock_w3_instance.eth.account._create_transaction_with_signature.return_value = MagicMock(rawTransaction=b'raw_tx')
        
        self.orchestrator_node.w3 = mock_w3_instance

        # Mock signature orchestration
        mock_orchestrate_sig.return_value = {
            'public_nonce': '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            'signature': 12345
        }
        
        dkg_public_key = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'

        # --- Call the endpoint ---
        tx_payload = {
            'to': '0xRecipientAddress',
            'value_in_eth': 0.1,
            'party': ['2', '3']
        }
        response = self.client.post(f'/v1/wallets/{dkg_public_key}/transactions', 
                                    data=json.dumps(tx_payload), 
                                    content_type='application/json')

        # --- Assertions ---
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'SUCCESSFUL')
        self.assertEqual(data['tx_hash'], '0x' + b'a_mock_tx_hash'.hex())
        
        # Verify mocks were called
        mock_orchestrate_sig.assert_called_once()
        mock_w3_instance.eth.send_raw_transaction.assert_called_once_with(b'raw_tx')


if __name__ == '__main__':
    unittest.main()
