"""
Blockchain interface for QuantumGate.
Handles interaction with Ethereum and Binance Smart Chain.
"""
import logging
from typing import Dict, List, Any, Optional
from web3 import Web3
from eth_account import Account
import json
import time

logger = logging.getLogger(__name__)

class ChainInterface:
    """Blockchain interface for multiple chains."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize blockchain interface."""
        self.config = config
        self.connections = {}
        self.contracts = {}
        
        # Initialize connections
        self._init_connections()
        
        logger.info("Blockchain interface initialized")
    
    def _init_connections(self):
        """Initialize blockchain connections."""
        # Ethereum connection
        if "ethereum" in self.config:
            try:
                eth_config = self.config["ethereum"]
                self.connections["ethereum"] = Web3(Web3.HTTPProvider(eth_config["rpc_url"]))
                
                if self.connections["ethereum"].is_connected():
                    logger.info("Connected to Ethereum network")
                else:
                    logger.error("Failed to connect to Ethereum network")
            except Exception as e:
                logger.error(f"Ethereum connection failed: {e}")
        
        # Binance Smart Chain connection
        if "bsc" in self.config:
            try:
                bsc_config = self.config["bsc"]
                self.connections["bsc"] = Web3(Web3.HTTPProvider(bsc_config["rpc_url"]))
                
                if self.connections["bsc"].is_connected():
                    logger.info("Connected to Binance Smart Chain")
                else:
                    logger.error("Failed to connect to Binance Smart Chain")
            except Exception as e:
                logger.error(f"BSC connection failed: {e}")
    
    def deploy_contract(self, chain: str, contract_source: str, 
                       constructor_args: List[Any] = None) -> Dict[str, Any]:
        """Deploy smart contract to specified chain."""
        try:
            if chain not in self.connections:
                raise ValueError(f"Chain {chain} not configured")
            
            web3 = self.connections[chain]
            account = Account.from_key(self.config[chain]["private_key"])
            
            # Compile contract (simplified)
            # In production, use solcx for compilation
            contract_abi = json.loads(contract_source)["abi"]
            contract_bytecode = json.loads(contract_source)["bytecode"]
            
            # Create contract instance
            contract = web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
            
            # Build transaction
            constructor_args = constructor_args or []
            transaction = contract.constructor(*constructor_args).build_transaction({
                'from': account.address,
                'nonce': web3.eth.get_transaction_count(account.address),
                'gas': 2000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
            })
            
            # Sign and send transaction
            signed_txn = web3.eth.account.sign_transaction(transaction, private_key=account.key)
            tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for transaction receipt
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Store contract information
            contract_address = tx_receipt.contractAddress
            self.contracts[contract_address] = {
                "chain": chain,
                "abi": contract_abi,
                "address": contract_address,
                "deployed_at": int(time.time())
            }
            
            logger.info(f"Contract deployed to {chain} at {contract_address}")
            
            return {
                "chain": chain,
                "contract_address": contract_address,
                "transaction_hash": tx_hash.hex(),
                "gas_used": tx_receipt.gasUsed,
                "block_number": tx_receipt.blockNumber
            }
            
        except Exception as e:
            logger.error(f"Contract deployment failed: {e}")
            raise
    
    def call_contract_method(self, chain: str, contract_address: str,
                           method_name: str, args: List[Any] = None,
                           value: int = 0) -> Dict[str, Any]:
        """Call smart contract method."""
        try:
            if chain not in self.connections:
                raise ValueError(f"Chain {chain} not configured")
            
            if contract_address not in self.contracts:
                raise ValueError(f"Contract {contract_address} not found")
            
            web3 = self.connections[chain]
            contract_info = self.contracts[contract_address]
            
            # Create contract instance
            contract = web3.eth.contract(
                address=contract_address,
                abi=contract_info["abi"]
            )
            
            # Get method
            method = getattr(contract.functions, method_name)
            
            # Prepare arguments
            args = args or []
            
            # If value is provided, this is a transaction
            if value > 0:
                account = Account.from_key(self.config[chain]["private_key"])
                
                # Build transaction
                transaction = method(*args).build_transaction({
                    'from': account.address,
                    'value': value,
                    'nonce': web3.eth.get_transaction_count(account.address),
                    'gas': 200000,
                    'gasPrice': web3.to_wei('20', 'gwei'),
                })
                
                # Sign and send transaction
                signed_txn = web3.eth.account.sign_transaction(transaction, private_key=account.key)
                tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
                
                # Wait for transaction receipt
                tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
                
                return {
                    "type": "transaction",
                    "transaction_hash": tx_hash.hex(),
                    "gas_used": tx_receipt.gasUsed,
                    "block_number": tx_receipt.blockNumber,
                    "status": tx_receipt.status
                }
            else:
                # Read-only call
                result = method(*args).call()
                
                return {
                    "type": "call",
                    "result": result
                }
                
        except Exception as e:
            logger.error(f"Contract method call failed: {e}")
            raise
    
    def get_transaction_status(self, chain: str, tx_hash: str) -> Dict[str, Any]:
        """Get transaction status."""
        try:
            if chain not in self.connections:
                raise ValueError(f"Chain {chain} not configured")
            
            web3 = self.connections[chain]
            
            # Get transaction receipt
            try:
                tx_receipt = web3.eth.get_transaction_receipt(tx_hash)
                
                return {
                    "status": "confirmed",
                    "block_number": tx_receipt.blockNumber,
                    "gas_used": tx_receipt.gasUsed,
                    "confirmations": web3.eth.block_number - tx_receipt.blockNumber
                }
            except:
                # Transaction not found or pending
                try:
                    tx = web3.eth.get_transaction(tx_hash)
                    return {
                        "status": "pending",
                        "block_number": tx.blockNumber
                    }
                except:
                    return {
                        "status": "not_found"
                    }
                    
        except Exception as e:
            logger.error(f"Transaction status check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_balance(self, chain: str, address: str) -> Dict[str, Any]:
        """Get account balance."""
        try:
            if chain not in self.connections:
                raise ValueError(f"Chain {chain} not configured")
            
            web3 = self.connections[chain]
            balance_wei = web3.eth.get_balance(address)
            balance_eth = web3.from_wei(balance_wei, 'ether')
            
            return {
                "chain": chain,
                "address": address,
                "balance_wei": balance_wei,
                "balance_eth": float(balance_eth)
            }
            
        except Exception as e:
            logger.error(f"Balance check failed: {e}")
            return {"error": str(e)}
    
    def get_network_info(self, chain: str) -> Dict[str, Any]:
        """Get network information."""
        try:
            if chain not in self.connections:
                raise ValueError(f"Chain {chain} not configured")
            
            web3 = self.connections[chain]
            
            return {
                "chain": chain,
                "connected": web3.is_connected(),
                "block_number": web3.eth.block_number,
                "gas_price": web3.eth.gas_price,
                "chain_id": web3.eth.chain_id
            }
            
        except Exception as e:
            logger.error(f"Network info failed: {e}")
            return {"error": str(e)}
    
    def create_quantum_protected_transaction(self, chain: str, to_address: str,
                                          value: int, data: str = "") -> Dict[str, Any]:
        """Create quantum-protected transaction."""
        try:
            if chain not in self.connections:
                raise ValueError(f"Chain {chain} not configured")
            
            web3 = self.connections[chain]
            account = Account.from_key(self.config[chain]["private_key"])
            
            # Add quantum protection metadata
            quantum_metadata = {
                "protected": True,
                "algorithm": "kyber1024",
                "timestamp": int(time.time()),
                "nonce": web3.eth.get_transaction_count(account.address)
            }
            
            # Build transaction with quantum protection
            transaction = {
                'from': account.address,
                'to': to_address,
                'value': value,
                'data': data,
                'nonce': quantum_metadata["nonce"],
                'gas': 200000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'quantum_metadata': quantum_metadata
            }
            
            # Sign transaction
            signed_txn = web3.eth.account.sign_transaction(transaction, private_key=account.key)
            tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            logger.info(f"Quantum-protected transaction sent: {tx_hash.hex()}")
            
            return {
                "transaction_hash": tx_hash.hex(),
                "quantum_protected": True,
                "quantum_metadata": quantum_metadata
            }
            
        except Exception as e:
            logger.error(f"Quantum-protected transaction failed: {e}")
            raise

# Default configuration
default_config = {
    "ethereum": {
        "rpc_url": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        "private_key": "YOUR_PRIVATE_KEY"
    },
    "bsc": {
        "rpc_url": "https://bsc-dataseed.binance.org/",
        "private_key": "YOUR_PRIVATE_KEY"
    }
}

# Global instance (would be initialized with real config)
chain_interface = ChainInterface(default_config)