import hashlib
import json
from time import time
from uuid import uuid4
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

import blockchainClass

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = blockchainClass.Blockchain()


# @app.route 's explaination http://python.jobbole.com/80956/
@app.route("/mine", methods = ['GET'])
def mine():
    return blockchain.mine_request(node_identifier)
    

@app.route("/transactions/new", methods = ["POST"])
def new_transaction():
    return blockchain.new_transaction_request()

@app.route("/chain", methods = ['GET'])
def full_chain():
    response = {
        "chain" : blockchain.chain,
        "length" : len(blockchain.chain),
    }

    return jsonify(response), 200

@app.route("/nodes/register", methods = ["POST"])
def register_nodes():
    return blockchain.register_nodes_request()
@app.route("/accounts/register", methods = ["POST"])
def add_accounts():
    # TODO call CryptoAlgorithm to create a pair of new RSA key

    return blockchain.add_account_request()
@app.route("/nodes/resolve", methods = ["GET"])
def consensus():
    return blockchain.consensus_request()

if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default = 5000, type = int, help = "port to listen on")
    args = parser.parse_args()
    port = args.port

    app.run(host = "0.0.0.0", port = port)
