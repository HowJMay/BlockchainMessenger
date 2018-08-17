import hashlib
import json
from time import time
from uuid import uuid4
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

import blockchainClass
import CryptoAlgorithm
import BlockchainMessenger
import socket


# Instantiate the Blockchain
blockchain_client = blockchainClass.Blockchain()

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


def add_accounts():
    address = CryptoAlgorithm.generate_private_key().publickey().export_key()
    node_ip = get_host_ip()
    #TODO dump json as POST request body
    
    return blockchain_client.add_account_request()

