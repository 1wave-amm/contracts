// SPDX-License-Identifier: LicenseRef-Degensoft-Aqua-Source-1.1

pragma solidity 0.8.30;

/// @custom:license-url https://github.com/1inch/aqua-app-template/blob/main/LICENSES/Aqua-Source-1.1.txt
/// @custom:copyright © 2025 Degensoft Ltd

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAqua} from "@1inch/aqua/src/interfaces/IAqua.sol";
import {TransientLock, TransientLockLib} from "@1inch/aqua/src/libs/ReentrancyGuard.sol";
import {AquaApp} from "@1inch/aqua/src/AquaApp.sol";

/// @title IAquaAdapter
/// @notice Interface for AquaAdapter to call publishPairs after swaps
interface IAquaAdapter {
    function publishPairs() external;
}

contract WaveSwap is AquaApp {
    using Math for uint256;
    using TransientLockLib for TransientLock;

    event SwapExactIn(address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut);
    event SwapExactOut(address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut);

    error InsufficientOutputAmount(uint256 amountOut, uint256 amountOutMin);
    error ExcessiveInputAmount(uint256 amountIn, uint256 amountInMax);

    struct Strategy {
        address maker;
        address token0;
        address token1;
        uint256 feeBps;
        bytes32 salt;
    }

    uint256 internal constant BPS_BASE = 10_000;

    constructor(IAqua aqua_) AquaApp(aqua_) {}

    function quoteExactIn(Strategy calldata strategy, bool zeroForOne, uint256 amountIn)
        external
        view
        returns (uint256 amountOut)
    {
        bytes32 strategyHash = keccak256(abi.encode(strategy));
        (,, uint256 balanceIn, uint256 balanceOut) = _getInAndOut(strategy, strategyHash, zeroForOne);
        amountOut = _quoteExactIn(strategy, balanceIn, balanceOut, amountIn);
    }

    function quoteExactOut(Strategy calldata strategy, bool zeroForOne, uint256 amountOut)
        external
        view
        returns (uint256 amountIn)
    {
        bytes32 strategyHash = keccak256(abi.encode(strategy));
        (,, uint256 balanceIn, uint256 balanceOut) = _getInAndOut(strategy, strategyHash, zeroForOne);
        amountIn = _quoteExactOut(strategy, balanceIn, balanceOut, amountOut);
    }

    function swapExactIn(
        Strategy calldata strategy,
        bool zeroForOne,
        uint256 amountIn,
        uint256 amountOutMin,
        address to,
        bytes calldata
    ) external nonReentrantStrategy(keccak256(abi.encode(strategy))) returns (uint256 amountOut) {
        bytes32 strategyHash = keccak256(abi.encode(strategy));

        (address tokenIn, address tokenOut, uint256 balanceIn, uint256 balanceOut) =
            _getInAndOut(strategy, strategyHash, zeroForOne);
        amountOut = _quoteExactIn(strategy, balanceIn, balanceOut, amountIn);
        require(amountOut >= amountOutMin, InsufficientOutputAmount(amountOut, amountOutMin));

        // Pull output tokens from maker's strategy to recipient
        AQUA.pull(strategy.maker, strategyHash, tokenOut, amountOut, to);

        // Transfer input tokens from caller to this contract
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // Approve Aqua to transfer tokens (required for push)
        IERC20(tokenIn).approve(address(AQUA), amountIn);

        // Push input tokens directly to Aqua strategy balance
        AQUA.push(strategy.maker, address(this), strategyHash, tokenIn, amountIn);

        // Verify the push was successful
        _safeCheckAquaPush(strategy.maker, strategyHash, tokenIn, balanceIn + amountIn);

        // Automatically call publishPairs on the AquaAdapter (maker) after swap
        IAquaAdapter(strategy.maker).publishPairs();

        emit SwapExactIn(tokenIn, tokenOut, amountIn, amountOut);
    }

    function swapExactOut(
        Strategy calldata strategy,
        bool zeroForOne,
        uint256 amountOut,
        uint256 amountInMax,
        address to,
        bytes calldata
    ) external nonReentrantStrategy(keccak256(abi.encode(strategy))) returns (uint256 amountIn) {
        bytes32 strategyHash = keccak256(abi.encode(strategy));

        (address tokenIn, address tokenOut, uint256 balanceIn, uint256 balanceOut) =
            _getInAndOut(strategy, strategyHash, zeroForOne);
        amountIn = _quoteExactOut(strategy, balanceIn, balanceOut, amountOut);
        require(amountIn <= amountInMax, ExcessiveInputAmount(amountIn, amountInMax));

        // Pull output tokens from maker's strategy to recipient
        AQUA.pull(strategy.maker, strategyHash, tokenOut, amountOut, to);

        // Transfer and push input tokens
        IERC20 tokenInContract = IERC20(tokenIn);
        tokenInContract.transferFrom(msg.sender, address(this), amountIn);
        tokenInContract.approve(address(AQUA), amountIn);
        AQUA.push(strategy.maker, address(this), strategyHash, tokenIn, amountIn);

        // Verify the push was successful
        _safeCheckAquaPush(strategy.maker, strategyHash, tokenIn, balanceIn + amountIn);

        // Automatically call publishPairs on the AquaAdapter (maker) after swap
        IAquaAdapter(strategy.maker).publishPairs();

        emit SwapExactOut(tokenIn, tokenOut, amountIn, amountOut);
    }

    function _quoteExactIn(Strategy calldata strategy, uint256 balanceIn, uint256 balanceOut, uint256 amountIn)
        internal
        view
        virtual
        returns (uint256 amountOut)
    {
        // Use constant product formula (x*y=const) after fee deduction:
        // balanceIn * balanceOut == (balanceIn + amountIn) * (balanceOut - amountOut)
        uint256 amountInWithFee = amountIn * (BPS_BASE - strategy.feeBps) / BPS_BASE;
        amountOut = (amountInWithFee * balanceOut) / (balanceIn + amountInWithFee);
    }

    function _quoteExactOut(Strategy calldata strategy, uint256 balanceIn, uint256 balanceOut, uint256 amountOut)
        internal
        view
        virtual
        returns (uint256 amountIn)
    {
        // Use constant product formula (x*y=const) after fee deduction:
        // balanceIn * balanceOut == (balanceIn + amountIn) * (balanceOut - amountOut)
        uint256 amountOutWithFee = amountOut * BPS_BASE / (BPS_BASE - strategy.feeBps);
        amountIn = (balanceIn * amountOutWithFee).ceilDiv(balanceOut - amountOutWithFee);
    }

    function _getInAndOut(Strategy calldata strategy, bytes32 strategyHash, bool zeroForOne)
        private
        view
        returns (address tokenIn, address tokenOut, uint256 balanceIn, uint256 balanceOut)
    {
        tokenIn = zeroForOne ? strategy.token0 : strategy.token1;
        tokenOut = zeroForOne ? strategy.token1 : strategy.token0;
        (balanceIn, balanceOut) = AQUA.safeBalances(strategy.maker, address(this), strategyHash, tokenIn, tokenOut);
    }
}
