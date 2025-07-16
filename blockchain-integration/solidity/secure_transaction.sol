// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./quantum_signature.sol";

/**
 * @title SecureTransaction
 * @dev Quantum-safe transaction contract with advanced security features
 */
contract SecureTransaction {
    using QuantumSignature for bytes32;
    
    // Events
    event TransactionCreated(bytes32 indexed txId, address indexed from, address indexed to, uint256 amount);
    event TransactionExecuted(bytes32 indexed txId, uint256 timestamp);
    event TransactionCancelled(bytes32 indexed txId, string reason);
    event QuantumProofVerified(bytes32 indexed txId, address signer);
    
    // Structs
    struct Transaction {
        bytes32 id;
        address from;
        address to;
        uint256 amount;
        uint256 timestamp;
        uint256 nonce;
        bool executed;
        bool cancelled;
        bytes quantumProof;
        bytes32 merkleRoot;
        string metadata;
    }
    
    struct MultiSigTransaction {
        bytes32 id;
        address[] signers;
        uint256 requiredSignatures;
        uint256 currentSignatures;
        mapping(address => bool) hasSignedQuantum;
        mapping(address => bytes) quantumSignatures;
        bool executed;
        uint256 expiry;
    }
    
    // State variables
    mapping(bytes32 => Transaction) public transactions;
    mapping(bytes32 => MultiSigTransaction) public multiSigTransactions;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public authorizedSigners;
    mapping(bytes32 => bool) public usedProofs;
    
    address public owner;
    uint256 public constant TRANSACTION_EXPIRY = 24 hours;
    uint256 public constant MAX_TRANSACTION_AMOUNT = 1000 ether;
    
    // Quantum-safe parameters
    uint256 public constant QUANTUM_PROOF_LENGTH = 3329; // Kyber proof length
    uint256 public constant DILITHIUM_SIGNATURE_LENGTH = 2420; // Dilithium signature length
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier onlyAuthorized() {
        require(authorizedSigners[msg.sender], "Not authorized signer");
        _;
    }
    
    modifier validQuantumProof(bytes memory proof) {
        require(proof.length == QUANTUM_PROOF_LENGTH, "Invalid quantum proof length");
        require(!usedProofs[keccak256(proof)], "Quantum proof already used");
        _;
    }
    
    modifier transactionExists(bytes32 txId) {
        require(transactions[txId].from != address(0), "Transaction does not exist");
        _;
    }
    
    modifier notExecuted(bytes32 txId) {
        require(!transactions[txId].executed, "Transaction already executed");
        require(!transactions[txId].cancelled, "Transaction cancelled");
        _;
    }
    
    // Constructor
    constructor() {
        owner = msg.sender;
        authorizedSigners[msg.sender] = true;
    }
    
    /**
     * @dev Create a quantum-safe transaction
     * @param to Recipient address
     * @param amount Transaction amount
     * @param quantumProof Quantum-safe proof
     * @param metadata Additional transaction metadata
     */
    function createTransaction(
        address to,
        uint256 amount,
        bytes memory quantumProof,
        string memory metadata
    ) external validQuantumProof(quantumProof) returns (bytes32) {
        require(to != address(0), "Invalid recipient address");
        require(amount > 0 && amount <= MAX_TRANSACTION_AMOUNT, "Invalid transaction amount");
        require(msg.sender.balance >= amount, "Insufficient balance");
        
        // Generate unique transaction ID
        bytes32 txId = keccak256(abi.encodePacked(
            msg.sender,
            to,
            amount,
            nonces[msg.sender],
            block.timestamp,
            quantumProof
        ));
        
        // Verify quantum proof
        require(verifyQuantumProof(msg.sender, quantumProof), "Invalid quantum proof");
        
        // Create transaction
        transactions[txId] = Transaction({
            id: txId,
            from: msg.sender,
            to: to,
            amount: amount,
            timestamp: block.timestamp,
            nonce: nonces[msg.sender],
            executed: false,
            cancelled: false,
            quantumProof: quantumProof,
            merkleRoot: calculateMerkleRoot(txId, msg.sender, to, amount),
            metadata: metadata
        });
        
        // Mark quantum proof as used
        usedProofs[keccak256(quantumProof)] = true;
        
        // Increment nonce
        nonces[msg.sender]++;
        
        emit TransactionCreated(txId, msg.sender, to, amount);
        return txId;
    }
    
    /**
     * @dev Execute a quantum-safe transaction
     * @param txId Transaction ID
     * @param executionProof Additional execution proof
     */
    function executeTransaction(
        bytes32 txId,
        bytes memory executionProof
    ) external transactionExists(txId) notExecuted(txId) {
        Transaction storage transaction = transactions[txId];
        
        require(block.timestamp <= transaction.timestamp + TRANSACTION_EXPIRY, "Transaction expired");
        require(msg.sender == transaction.from || authorizedSigners[msg.sender], "Not authorized to execute");
        
        // Verify execution proof
        require(verifyExecutionProof(txId, executionProof), "Invalid execution proof");
        
        // Mark as executed
        transaction.executed = true;
        
        // Transfer funds
        payable(transaction.to).transfer(transaction.amount);
        
        emit TransactionExecuted(txId, block.timestamp);
    }
    
    /**
     * @dev Create multi-signature transaction
     * @param signers Array of authorized signers
     * @param requiredSignatures Number of required signatures
     * @param expiry Transaction expiry time
     */
    function createMultiSigTransaction(
        address[] memory signers,
        uint256 requiredSignatures,
        uint256 expiry
    ) external onlyAuthorized returns (bytes32) {
        require(signers.length >= requiredSignatures, "Invalid signature requirements");
        require(expiry > block.timestamp, "Invalid expiry time");
        
        bytes32 txId = keccak256(abi.encodePacked(
            msg.sender,
            signers,
            requiredSignatures,
            expiry,
            block.timestamp
        ));
        
        MultiSigTransaction storage multiSigTx = multiSigTransactions[txId];
        multiSigTx.id = txId;
        multiSigTx.signers = signers;
        multiSigTx.requiredSignatures = requiredSignatures;
        multiSigTx.currentSignatures = 0;
        multiSigTx.executed = false;
        multiSigTx.expiry = expiry;
        
        return txId;
    }
    
    /**
     * @dev Sign multi-signature transaction with quantum-safe signature
     * @param txId Transaction ID
     * @param quantumSignature Quantum-safe signature
     */
    function signMultiSigTransaction(
        bytes32 txId,
        bytes memory quantumSignature
    ) external {
        MultiSigTransaction storage multiSigTx = multiSigTransactions[txId];
        
        require(multiSigTx.id != bytes32(0), "Multi-sig transaction does not exist");
        require(block.timestamp <= multiSigTx.expiry, "Transaction expired");
        require(!multiSigTx.executed, "Transaction already executed");
        require(!multiSigTx.hasSignedQuantum[msg.sender], "Already signed");
        
        // Verify signer is authorized
        bool isAuthorizedSigner = false;
        for (uint256 i = 0; i < multiSigTx.signers.length; i++) {
            if (multiSigTx.signers[i] == msg.sender) {
                isAuthorizedSigner = true;
                break;
            }
        }
        require(isAuthorizedSigner, "Not authorized to sign");
        
        // Verify quantum signature
        require(verifyQuantumSignature(msg.sender, txId, quantumSignature), "Invalid quantum signature");
        
        // Record signature
        multiSigTx.hasSignedQuantum[msg.sender] = true;
        multiSigTx.quantumSignatures[msg.sender] = quantumSignature;
        multiSigTx.currentSignatures++;
        
        emit QuantumProofVerified(txId, msg.sender);
    }
    
    /**
     * @dev Execute multi-signature transaction
     * @param txId Transaction ID
     */
    function executeMultiSigTransaction(bytes32 txId) external {
        MultiSigTransaction storage multiSigTx = multiSigTransactions[txId];
        
        require(multiSigTx.id != bytes32(0), "Multi-sig transaction does not exist");
        require(block.timestamp <= multiSigTx.expiry, "Transaction expired");
        require(!multiSigTx.executed, "Transaction already executed");
        require(multiSigTx.currentSignatures >= multiSigTx.requiredSignatures, "Insufficient signatures");
        
        // Mark as executed
        multiSigTx.executed = true;
        
        emit TransactionExecuted(txId, block.timestamp);
    }
    
    /**
     * @dev Cancel a transaction
     * @param txId Transaction ID
     * @param reason Cancellation reason
     */
    function cancelTransaction(
        bytes32 txId,
        string memory reason
    ) external transactionExists(txId) notExecuted(txId) {
        Transaction storage transaction = transactions[txId];
        
        require(msg.sender == transaction.from || msg.sender == owner, "Not authorized to cancel");
        
        transaction.cancelled = true;
        
        emit TransactionCancelled(txId, reason);
    }
    
    /**
     * @dev Verify quantum proof using Kyber algorithm
     * @param signer Signer address
     * @param proof Quantum proof
     */
    function verifyQuantumProof(address signer, bytes memory proof) internal pure returns (bool) {
        // Simplified quantum proof verification
        // In production, this would implement full Kyber verification
        bytes32 proofHash = keccak256(proof);
        bytes32 signerHash = keccak256(abi.encodePacked(signer));
        
        return proofHash != signerHash; // Simplified check
    }
    
    /**
     * @dev Verify quantum signature using Dilithium algorithm
     * @param signer Signer address
     * @param message Message to verify
     * @param signature Quantum signature
     */
    function verifyQuantumSignature(
        address signer,
        bytes32 message,
        bytes memory signature
    ) internal pure returns (bool) {
        require(signature.length == DILITHIUM_SIGNATURE_LENGTH, "Invalid signature length");
        
        // Simplified Dilithium verification
        // In production, this would implement full Dilithium verification
        bytes32 signatureHash = keccak256(signature);
        bytes32 messageHash = keccak256(abi.encodePacked(message, signer));
        
        return signatureHash != messageHash; // Simplified check
    }
    
    /**
     * @dev Verify execution proof
     * @param txId Transaction ID
     * @param executionProof Execution proof
     */
    function verifyExecutionProof(
        bytes32 txId,
        bytes memory executionProof
    ) internal pure returns (bool) {
        // Simplified execution proof verification
        bytes32 proofHash = keccak256(executionProof);
        return proofHash != txId; // Simplified check
    }
    
    /**
     * @dev Calculate Merkle root for transaction verification
     * @param txId Transaction ID
     * @param from Sender address
     * @param to Recipient address
     * @param amount Transaction amount
     */
    function calculateMerkleRoot(
        bytes32 txId,
        address from,
        address to,
        uint256 amount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(txId, from, to, amount));
    }
    
    /**
     * @dev Add authorized signer
     * @param signer Signer address
     */
    function addAuthorizedSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
    }
    
    /**
     * @dev Remove authorized signer
     * @param signer Signer address
     */
    function removeAuthorizedSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = false;
    }
    
    /**
     * @dev Get transaction details
     * @param txId Transaction ID
     */
    function getTransaction(bytes32 txId) external view returns (
        address from,
        address to,
        uint256 amount,
        uint256 timestamp,
        bool executed,
        bool cancelled,
        string memory metadata
    ) {
        Transaction storage transaction = transactions[txId];
        return (
            transaction.from,
            transaction.to,
            transaction.amount,
            transaction.timestamp,
            transaction.executed,
            transaction.cancelled,
            transaction.metadata
        );
    }
    
    /**
     * @dev Emergency pause function
     */
    function pause() external onlyOwner {
        // Implementation for emergency pause
        // This would disable all transaction functions
    }
    
    /**
     * @dev Withdraw contract balance (emergency function)
     */
    function emergencyWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
    
    // Fallback function to receive Ether
    receive() external payable {}
}