// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IWarpMessenger.sol";

/**
 * @title AtomicSwapBridge
 * @notice Cross-chain atomic swap bridge between XVM (UTXO-native) and C-Chain (EVM)
 * @dev Uses Warp messaging for cross-chain communication and DEX precompile for swaps
 */
contract AtomicSwapBridge {
    // ============ Constants ============
    
    /// @notice Warp precompile address
    IWarpMessenger public constant WARP = IWarpMessenger(0x0200000000000000000000000000000000000005);
    
    /// @notice DEX PoolManager precompile address
    address public constant POOL_MANAGER = 0x0000000000000000000000000000000000000400;
    
    /// @notice DEX SwapRouter precompile address
    address public constant SWAP_ROUTER = 0x0000000000000000000000000000000000000401;
    
    // ============ Enums ============
    
    enum SwapState {
        Pending,
        Locked,
        Minted,
        Swapped,
        Settled,
        Cancelled,
        Expired
    }
    
    enum Operation {
        Lock,
        Unlock,
        Mint,
        Burn,
        Swap,
        Settle
    }
    
    // ============ Structs ============
    
    struct SwapRecord {
        bytes32 swapId;
        SwapState state;
        bytes32 sourceChain;
        bytes32 destChain;
        address sender;
        address recipient;
        address asset;
        uint256 amount;
        uint256 minReceive;
        uint64 deadline;
        uint64 nonce;
        bytes32 hashLock;
        bytes32 preimage;
        uint256 createdAt;
        uint256 updatedAt;
    }
    
    struct SwapRoute {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
    
    // ============ State ============
    
    /// @notice Source chain ID (XVM)
    bytes32 public immutable sourceChainId;
    
    /// @notice Bridge operator
    address public operator;
    
    /// @notice Swap records by ID
    mapping(bytes32 => SwapRecord) public swaps;
    
    /// @notice Swap routes for each swap ID
    mapping(bytes32 => SwapRoute[]) public swapRoutes;
    
    /// @notice Nonce counter for replay protection
    uint64 public nonceCounter;
    
    /// @notice Wrapped asset mapping (native asset ID => wrapped ERC20)
    mapping(bytes32 => address) public wrappedAssets;
    
    /// @notice Trusted source bridge address on XVM
    bytes public trustedSourceBridge;
    
    // ============ Events ============
    
    event SwapInitiated(
        bytes32 indexed swapId,
        address indexed sender,
        address indexed recipient,
        address asset,
        uint256 amount,
        uint64 deadline
    );
    
    event AssetsLocked(
        bytes32 indexed swapId,
        bytes32 hashLock,
        uint256 amount
    );
    
    event AssetsMinted(
        bytes32 indexed swapId,
        address indexed recipient,
        address wrappedAsset,
        uint256 amount
    );
    
    event SwapExecuted(
        bytes32 indexed swapId,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );
    
    event SwapSettled(
        bytes32 indexed swapId,
        bytes32 preimage
    );
    
    event SwapCancelled(
        bytes32 indexed swapId,
        string reason
    );
    
    event WarpMessageSent(
        bytes32 indexed messageId,
        bytes32 indexed swapId,
        Operation operation
    );
    
    event WarpMessageReceived(
        bytes32 indexed messageId,
        bytes32 indexed sourceChain,
        Operation operation
    );
    
    // ============ Errors ============
    
    error InvalidSwapState(SwapState current, SwapState expected);
    error SwapNotFound(bytes32 swapId);
    error InvalidPreimage();
    error DeadlineNotReached();
    error DeadlineExpired();
    error InvalidSourceChain();
    error InvalidSourceBridge();
    error Unauthorized();
    error InsufficientAmount();
    error SwapFailed();
    
    // ============ Modifiers ============
    
    modifier onlyOperator() {
        if (msg.sender != operator) revert Unauthorized();
        _;
    }
    
    // ============ Constructor ============
    
    constructor(bytes32 _sourceChainId, bytes memory _trustedSourceBridge) {
        sourceChainId = _sourceChainId;
        trustedSourceBridge = _trustedSourceBridge;
        operator = msg.sender;
    }
    
    // ============ External Functions ============
    
    /**
     * @notice Process an incoming lock message from XVM via Warp
     * @param messageIndex Index of the Warp message to process
     */
    function processLockMessage(uint32 messageIndex) external {
        // Get verified Warp message
        (WarpMessage memory message, bool valid) = WARP.getVerifiedWarpMessage(messageIndex);
        require(valid, "Invalid warp message");
        
        // Verify source chain
        if (message.sourceChainID != sourceChainId) revert InvalidSourceChain();
        
        // Decode the payload
        (address sourceAddr, bytes memory payload) = abi.decode(message.payload, (address, bytes));
        
        // Verify trusted source bridge
        if (keccak256(abi.encodePacked(sourceAddr)) != keccak256(trustedSourceBridge)) {
            revert InvalidSourceBridge();
        }
        
        // Parse atomic swap payload
        (
            uint8 version,
            uint8 operation,
            bytes32 swapId,
            bytes32 srcChain,
            bytes32 dstChain,
            address sender,
            address recipient,
            bytes32 asset,
            uint256 amount,
            uint256 minReceive,
            uint64 deadline,
            uint64 nonce,
            bytes memory data
        ) = _decodeSwapPayload(payload);
        
        require(version == 1, "Unsupported version");
        require(operation == uint8(Operation.Lock), "Expected Lock operation");
        
        // Create swap record
        bytes32 hashLock;
        if (data.length >= 32) {
            assembly {
                hashLock := mload(add(data, 32))
            }
        }
        
        SwapRecord storage swap = swaps[swapId];
        swap.swapId = swapId;
        swap.state = SwapState.Locked;
        swap.sourceChain = srcChain;
        swap.destChain = dstChain;
        swap.sender = sender;
        swap.recipient = recipient;
        swap.asset = wrappedAssets[asset];
        swap.amount = amount;
        swap.minReceive = minReceive;
        swap.deadline = deadline;
        swap.nonce = nonce;
        swap.hashLock = hashLock;
        swap.createdAt = block.timestamp;
        swap.updatedAt = block.timestamp;
        
        emit WarpMessageReceived(message.messageID, srcChain, Operation.Lock);
        emit AssetsLocked(swapId, hashLock, amount);
        
        // Auto-mint wrapped assets
        _mintWrappedAssets(swapId);
    }
    
    /**
     * @notice Execute a DEX swap using the DEX precompile
     * @param swapId The swap ID
     * @param routes The swap route through pools
     */
    function executeSwap(bytes32 swapId, SwapRoute[] calldata routes) external {
        SwapRecord storage swap = swaps[swapId];
        if (swap.swapId == bytes32(0)) revert SwapNotFound(swapId);
        if (swap.state != SwapState.Minted) revert InvalidSwapState(swap.state, SwapState.Minted);
        if (block.timestamp > swap.deadline) revert DeadlineExpired();
        
        // Store routes
        for (uint256 i = 0; i < routes.length; i++) {
            swapRoutes[swapId].push(routes[i]);
        }
        
        // Execute multi-hop swap through DEX precompile
        uint256 amountIn = swap.amount;
        uint256 amountOut;
        
        for (uint256 i = 0; i < routes.length; i++) {
            SwapRoute memory route = routes[i];
            
            // Build swap call to DEX precompile
            bytes memory swapCall = _buildSwapCall(
                route.tokenIn,
                route.tokenOut,
                route.fee,
                route.tickSpacing,
                route.hooks,
                amountIn,
                i == routes.length - 1 ? swap.minReceive : 0, // Only check slippage on final hop
                swap.recipient
            );
            
            (bool success, bytes memory result) = SWAP_ROUTER.call(swapCall);
            if (!success) revert SwapFailed();
            
            // Decode output amount for next hop
            amountOut = abi.decode(result, (uint256));
            amountIn = amountOut;
            
            emit SwapExecuted(swapId, route.tokenIn, route.tokenOut, swap.amount, amountOut);
        }
        
        swap.state = SwapState.Swapped;
        swap.updatedAt = block.timestamp;
    }
    
    /**
     * @notice Settle a swap by providing the preimage
     * @param swapId The swap ID
     * @param preimage The preimage that hashes to the hashlock
     */
    function settleSwap(bytes32 swapId, bytes32 preimage) external {
        SwapRecord storage swap = swaps[swapId];
        if (swap.swapId == bytes32(0)) revert SwapNotFound(swapId);
        if (swap.state != SwapState.Swapped && swap.state != SwapState.Minted) {
            revert InvalidSwapState(swap.state, SwapState.Swapped);
        }
        
        // Verify preimage
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != swap.hashLock) revert InvalidPreimage();
        
        swap.preimage = preimage;
        swap.state = SwapState.Settled;
        swap.updatedAt = block.timestamp;
        
        // Send settlement confirmation via Warp
        bytes memory settlementPayload = _encodeSettlePayload(swapId, preimage);
        bytes32 messageId = WARP.sendWarpMessage(settlementPayload);
        
        emit SwapSettled(swapId, preimage);
        emit WarpMessageSent(messageId, swapId, Operation.Settle);
    }
    
    /**
     * @notice Cancel an expired swap
     * @param swapId The swap ID
     */
    function cancelSwap(bytes32 swapId) external {
        SwapRecord storage swap = swaps[swapId];
        if (swap.swapId == bytes32(0)) revert SwapNotFound(swapId);
        if (block.timestamp <= swap.deadline) revert DeadlineNotReached();
        if (swap.state == SwapState.Settled) {
            revert InvalidSwapState(swap.state, SwapState.Locked);
        }
        
        swap.state = SwapState.Cancelled;
        swap.updatedAt = block.timestamp;
        
        // Send unlock message via Warp to release locked assets on XVM
        bytes memory unlockPayload = _encodeUnlockPayload(swapId);
        bytes32 messageId = WARP.sendWarpMessage(unlockPayload);
        
        emit SwapCancelled(swapId, "Deadline expired");
        emit WarpMessageSent(messageId, swapId, Operation.Unlock);
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Register a wrapped asset mapping
     * @param nativeAssetId The native asset ID on XVM
     * @param wrappedAsset The wrapped ERC20 address on C-Chain
     */
    function registerWrappedAsset(bytes32 nativeAssetId, address wrappedAsset) external onlyOperator {
        wrappedAssets[nativeAssetId] = wrappedAsset;
    }
    
    /**
     * @notice Update the trusted source bridge
     * @param _trustedSourceBridge The new trusted source bridge address
     */
    function setTrustedSourceBridge(bytes calldata _trustedSourceBridge) external onlyOperator {
        trustedSourceBridge = _trustedSourceBridge;
    }
    
    /**
     * @notice Transfer operator role
     * @param newOperator The new operator address
     */
    function transferOperator(address newOperator) external onlyOperator {
        operator = newOperator;
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Get swap details
     * @param swapId The swap ID
     */
    function getSwap(bytes32 swapId) external view returns (SwapRecord memory) {
        return swaps[swapId];
    }
    
    /**
     * @notice Get swap routes
     * @param swapId The swap ID
     */
    function getSwapRoutes(bytes32 swapId) external view returns (SwapRoute[] memory) {
        return swapRoutes[swapId];
    }
    
    // ============ Internal Functions ============
    
    function _mintWrappedAssets(bytes32 swapId) internal {
        SwapRecord storage swap = swaps[swapId];
        
        // In production: mint wrapped tokens to recipient
        // For now: just update state
        swap.state = SwapState.Minted;
        swap.updatedAt = block.timestamp;
        
        emit AssetsMinted(swapId, swap.recipient, swap.asset, swap.amount);
    }
    
    function _buildSwapCall(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        int24 tickSpacing,
        address hooks,
        uint256 amountIn,
        uint256 amountOutMin,
        address recipient
    ) internal pure returns (bytes memory) {
        // Encode PoolKey
        bytes memory poolKey = abi.encode(
            tokenIn < tokenOut ? tokenIn : tokenOut,  // currency0
            tokenIn < tokenOut ? tokenOut : tokenIn,  // currency1
            fee,
            tickSpacing,
            hooks
        );
        
        // Encode swap params
        bytes memory swapParams = abi.encode(
            tokenIn < tokenOut,  // zeroForOne
            int256(amountIn),    // amountSpecified (positive = exact input)
            uint160(0)           // sqrtPriceLimitX96 (0 = no limit)
        );
        
        // Build call to swap function
        return abi.encodeWithSignature(
            "swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
            poolKey,
            swapParams,
            abi.encode(recipient, amountOutMin)
        );
    }
    
    function _decodeSwapPayload(bytes memory payload) internal pure returns (
        uint8 version,
        uint8 operation,
        bytes32 swapId,
        bytes32 srcChain,
        bytes32 dstChain,
        address sender,
        address recipient,
        bytes32 asset,
        uint256 amount,
        uint256 minReceive,
        uint64 deadline,
        uint64 nonce,
        bytes memory data
    ) {
        // Manual decoding to match Go serialization format
        uint256 offset = 0;
        
        version = uint8(payload[offset]);
        offset += 1;
        
        operation = uint8(payload[offset]);
        offset += 1;
        
        assembly {
            swapId := mload(add(payload, add(offset, 32)))
        }
        offset += 32;
        
        assembly {
            srcChain := mload(add(payload, add(offset, 32)))
        }
        offset += 32;
        
        assembly {
            dstChain := mload(add(payload, add(offset, 32)))
        }
        offset += 32;
        
        // Sender (length-prefixed)
        uint32 senderLen;
        assembly {
            senderLen := shr(224, mload(add(payload, add(offset, 32))))
        }
        offset += 4;
        
        bytes memory senderBytes = new bytes(senderLen);
        for (uint256 i = 0; i < senderLen; i++) {
            senderBytes[i] = payload[offset + i];
        }
        sender = address(bytes20(senderBytes));
        offset += senderLen;
        
        // Recipient (length-prefixed)
        uint32 recipientLen;
        assembly {
            recipientLen := shr(224, mload(add(payload, add(offset, 32))))
        }
        offset += 4;
        
        bytes memory recipientBytes = new bytes(recipientLen);
        for (uint256 i = 0; i < recipientLen; i++) {
            recipientBytes[i] = payload[offset + i];
        }
        recipient = address(bytes20(recipientBytes));
        offset += recipientLen;
        
        assembly {
            asset := mload(add(payload, add(offset, 32)))
        }
        offset += 32;
        
        assembly {
            amount := mload(add(payload, add(offset, 32)))
        }
        offset += 32;
        
        assembly {
            minReceive := mload(add(payload, add(offset, 32)))
        }
        offset += 32;
        
        assembly {
            deadline := shr(192, mload(add(payload, add(offset, 32))))
        }
        offset += 8;
        
        assembly {
            nonce := shr(192, mload(add(payload, add(offset, 32))))
        }
        offset += 8;
        
        // Data (length-prefixed)
        uint32 dataLen;
        assembly {
            dataLen := shr(224, mload(add(payload, add(offset, 32))))
        }
        offset += 4;
        
        data = new bytes(dataLen);
        for (uint256 i = 0; i < dataLen; i++) {
            data[i] = payload[offset + i];
        }
    }
    
    function _encodeSettlePayload(bytes32 swapId, bytes32 preimage) internal view returns (bytes memory) {
        SwapRecord storage swap = swaps[swapId];
        
        return abi.encode(
            uint8(1),                    // version
            uint8(Operation.Settle),     // operation
            swapId,
            swap.sourceChain,
            swap.destChain,
            swap.sender,
            swap.recipient,
            swap.asset,
            swap.amount,
            swap.minReceive,
            swap.deadline,
            swap.nonce,
            abi.encodePacked(preimage)   // data
        );
    }
    
    function _encodeUnlockPayload(bytes32 swapId) internal view returns (bytes memory) {
        SwapRecord storage swap = swaps[swapId];
        
        return abi.encode(
            uint8(1),                    // version
            uint8(Operation.Unlock),     // operation
            swapId,
            swap.sourceChain,
            swap.destChain,
            swap.sender,
            swap.recipient,
            swap.asset,
            swap.amount,
            swap.minReceive,
            swap.deadline,
            swap.nonce,
            bytes("")                    // data
        );
    }
}

/**
 * @title WarpMessage
 * @notice Struct for Warp message data
 */
struct WarpMessage {
    bytes32 sourceChainID;
    bytes32 messageID;
    address originSenderAddress;
    bytes payload;
}
