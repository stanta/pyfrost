from fastecdsa import keys, curve
from fastecdsa.encoding.sec1 import SEC1Encoder
import hashlib
import os

# Allow different IPs for Docker environment
HOST_IP = os.getenv("PYFROST_HOST", "127.0.0.1")

VALIDATED_IPS = {
    "127.0.0.1": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    # Docker container network IPs (all containers can access each other)
    # This covers the typical Docker subnet 172.x.x.x
    "172.19.0.1": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    "172.19.0.2": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    "172.19.0.3": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    "172.19.0.4": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    "172.19.0.5": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    # Docker service names
    "node1": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    "node2": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ],
    "node3": [
        "/pyfrost/v1/dkg/round1",
        "/pyfrost/v1/dkg/round2",
        "/pyfrost/v1/dkg/round3",
        "/pyfrost/v1/sign",
        "/pyfrost/v1/generate-nonces",
    ]
}


def generate_privates_and_nodes_info(number: int = 100):
    first_private = (
        71940701385098721223324549130922930535689437869965850741649618196713151413648
    )
    nodes_info_dict = {}
    privates_list = []
    previous_key = first_private
    
    # Use Docker service names when in Docker environment
    hosts = ["node1", "node2", "node3"] if HOST_IP != "127.0.0.1" else ["127.0.0.1"] * 3
    base_port = 5000
    
    for i in range(number):
        key_bytes = previous_key.to_bytes(32, "big")
        hashed = hashlib.sha256(key_bytes).digest()
        new_private = int.from_bytes(hashed, byteorder="big") % curve.secp256k1.q
        previous_key = new_private
        public_key = keys.get_public_key(new_private, curve.secp256k1)
        compressed_pub_key = int(
            SEC1Encoder.encode_public_key(public_key, True).hex(), 16
        )
        
        # For Docker, use service names; for local, use localhost with different ports
        if HOST_IP != "127.0.0.1":
            host = hosts[i % len(hosts)]
            port = str(base_port)  # All nodes use port 5000 inside their containers
        else:
            host = "127.0.0.1"
            port = str(base_port + i)
            
        nodes_info_dict[str(i + 1)] = {
            "public_key": compressed_pub_key,
            "host": host,
            "port": port,
        }
        privates_list.append(new_private)
    return privates_list, nodes_info_dict
