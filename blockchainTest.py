import hashlib
import json
from time import time
from uuid import uuid4
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request



class Blockchain(object):
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        # create the genesis block
        self.new_block(proof = 100, previous_hash = 1)

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: A blockchain
        :return: True if valid, False if not
        """
        
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print (str(last_block))
            print (str(block))
            print ("----------------------\n")

            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)

            if block['previous_hash'] != last_block_hash:
                return False
            
            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """

        neighbors = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbors:
            response = requests.get("http://{}/chain".format(node))

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

         # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False
        


    def new_block(self, proof, previous_hash = None):
        """
        Create a new Block in the Blockchain
        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """

        block = {
            "index" : len(self.chain) + 1,
            "timestamp" : time(),
            "transactions" : self.current_transactions,
            "proof" : proof,
            "previous_hash" : previous_hash or self.hash(self.chain[-1]),
        }
        # reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block
    
    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: <str> Address of the Sender
        :param recipient: <str> Address of the Recipient
        :param amount: <int> Amount
        :return: <int> The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            "sender" : sender,
            "recipient" : recipient,
            "amount" : amount,
        })

        return self.last_block['index'] + 1

    def new_transaction_request(self):
        values = request.get_json()

        # Check that the required fields are in the POST'ed data
        required = ['sender', 'recipient', 'amount']
        if not all(k in values for k in required):
            return "Missing valuses", 400

        # Create a new Transaction
        index = self.new_transaction(
            values['sender'],
            values['recipient'],
            values['amount'],
        )

        response = {
            "message" : ("Transaction will be added to Block " + str(index))
        }

        return jsonify(response), 201

    def mine_request(self, node_identifier):
        # We run the proof of work algorithm to get the next proof...
        last_block = self.last_block
        proof = self.proof_of_work(last_block)
        
        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.

        self.new_transaction(
            sender = "miningpoolgenerate",
            recipient = node_identifier,
            amount = 1,
        )
        
        # Forge the new Block by adding it to the chain
        previous_hash = self.hash(last_block)
        block = self.new_block(proof, previous_hash)
        
        response = {
            "message" : "New Block Forged",
            "index" : block['index'],
            "transactions" : block["transactions"],
            "proof" : block["proof"],
            "previous_hash" : block["previous_hash"],
        }

        return jsonify(response), 200
    

    def register_nodes_request(self):
        values = request.get_json()

        """
        for values.get("nodes") explains at https://www.jianshu.com/p/ecd97b1c21c1
        the short example is in the following

        ----------code starts----------
        mobile = request.form.get("mobile")
        password = request.form.get("password",type=str,default=None)
        password_repeat = request.form.get("password_repeat",type=str,default=None)
        mobile_code = request.form.get("mobile_code",type=str,default=None)
        ----------code ends----------
        
        and the code above can get the data from the following url
        url:http://127.0.0.1:5000/register?mobile=18817366807&password=123456&password_repeat=123456&mobile_code=111111
        """
    
        nodes = values.get("nodes")
        if nodes == None:
            return "Error: Please supply a valid list of noeds", 400
        
        for node in nodes:
            self.register_node(node)

        response = {
            "message" : 'New nodes have been added',
            "total_nodes" : list(blockchain.nodes),
        }

        return jsonify(response), 201
    def consensus_request(self):
        replaced = blockchain.resolve_conflicts()

        if replaced:
            response = {
                'message': 'Our chain was replaced',
                'new_chain': blockchain.chain,
            }
        else:
            response = {
                'message': 'Our chain is authoritative',
                'chain': blockchain.chain
            }

        return jsonify(response), 200


    @property
    def last_block(self):
        return self.chain[-1]


    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys = True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
         - p is the previous proof, and p' is the new proof
        :param last_proof: <int>
        :return: <int>
        """
        
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)


        proof = 0
        
        
        while self.valid_proof(last_proof, proof, last_hash) == False:
            proof += 1
            
        
        return proof


    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """
        
        guess = "{}{}{}".format(last_proof, proof, last_hash).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


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
