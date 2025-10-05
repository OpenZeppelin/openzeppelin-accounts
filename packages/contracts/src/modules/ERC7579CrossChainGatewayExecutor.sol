// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Executor} from "./ERC7579Executor.sol";
import {ERC7786Recipient} from "@openzeppelin/contracts/crosschain/ERC7786Recipient.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

/**
 * @dev Cross-chain executor module that enables accounts to receive and execute operations
 * from other chains through ERC-7786 compliant gateways.
 *
 * This module implements a message-passing approach where operations are initiated on one chain
 * and executed on destination chains through standardized cross-chain messaging protocols.
 * This approach allows **different operations per chain** but introduces **gateway finality
 * dependencies** and **relayer requirements**. Some use cases include:
 *
 * #### Usage pattern:
 *
 * 1. Account on origin chain sends message through ERC-7786 gateway
 * 2. Gateway relays message to destination chain (bridge-dependent timing)
 * 3. Destination gateway calls receiveMessage on this module
 * 4. Module validates sender and executes operation if authorized (see `_isValidCrossChainSender`)
 * 5. Operation is executed on the destination account
 *
 * NOTE: By default, only EVM chains are supported and the cross-chain sender must match the target account address,
 * which is possible if the account is deployed deterministically on all chains. Override `_isValidCrossChainSender`
 * for custom authorization or address mapping.
 */
abstract contract ERC7579CrossChainGatewayExecutor is
    ERC7579Executor,
    ERC7786Recipient
{
    using InteroperableAddress for bytes;

    address private immutable _gateway;

    /// @dev Initializes the module with a trusted ERC-7786 gateway.
    constructor(address gateway) {
        _gateway = gateway;
    }

    /**
     * @dev Processes cross-chain messages from the trusted gateway and executes ERC-7579 operations.
     *
     * The expected format of`payload` is (packed):
     * `[account, salt, mode, data]`
     *
     * NOTE: The message is still processed even if the sender is not the account itself but
     * the payload is not executed. See `_isValidCrossChainSender` for sender authorization logic.
     */
    function _processMessage(
        address /* gateway */,
        bytes32 /* receiveId */,
        bytes calldata sender,
        bytes calldata payload
    ) internal virtual override {
        address account = address(bytes20(payload[0:20]));
        if (_isValidCrossChainSender(account, sender)) {
            execute(
                account,
                bytes32(payload[20:52]),
                bytes32(payload[52:84]),
                payload[84:]
            );
        } // no op when the sender itself is not the account, the message is still received
    }

    /// @inheritdoc ERC7579Executor
    function _validateExecution(
        address /* account */,
        bytes32 /* salt */,
        bytes32 /* mode */,
        bytes calldata data
    ) internal virtual override returns (bytes calldata) {
        // No need for further validation since we rely on the gateway to validate the message
        return data;
    }

    /**
     * @dev Determines if the calling gateway is authorized to send messages to this module.
     *
     * By default, only the immutable trusted gateway set during construction can send messages
     * that will be processed by this module.
     */
    function _isAuthorizedGateway(
        address gateway,
        bytes calldata /* sender */
    ) internal view virtual override returns (bool) {
        return gateway == _gateway;
    }

    /**
     * @dev Validates if the cross-chain sender is authorized to execute operations on the account.
     *
     * NOTE: Only EVM chains are supported and the cross-chain sender must match the target account address,
     * which is possible if the account is deployed deterministically on all chains.
     */
    function _isValidCrossChainSender(
        address account,
        bytes calldata sender
    ) internal view virtual returns (bool) {
        (, address msgSender) = sender.parseEvmV1Calldata();
        return account == msgSender;
    }
}
