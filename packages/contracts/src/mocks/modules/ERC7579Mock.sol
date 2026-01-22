// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    IERC7579Module,
    IERC7579Hook
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC7579Validator} from "../../modules/validators/ERC7579Validator.sol";
import {ERC7579Executor} from "../../modules/executors/ERC7579Executor.sol";
import {ERC7579MultisigConfidentialValidator} from "../../modules/validators/ERC7579MultisigConfidentialValidator.sol";
import {
    ERC7579MultisigWeightedConfidentialValidator
} from "../../modules/validators/ERC7579MultisigWeightedConfidentialValidator.sol";

abstract contract ERC7579ModuleMock is IERC7579Module {
    uint256 private _moduleTypeId;

    event ModuleInstalledReceived(address account, bytes data);
    event ModuleUninstalledReceived(address account, bytes data);

    constructor(uint256 moduleTypeId) {
        _moduleTypeId = moduleTypeId;
    }

    function onInstall(bytes calldata data) public virtual {
        emit ModuleInstalledReceived(msg.sender, data);
    }

    function onUninstall(bytes calldata data) public virtual {
        emit ModuleUninstalledReceived(msg.sender, data);
    }

    function isModuleType(uint256 moduleTypeId) external view returns (bool) {
        return moduleTypeId == _moduleTypeId;
    }
}

abstract contract ERC7579ModuleMaliciousMock is ERC7579ModuleMock {
    function onUninstall(bytes calldata /*data*/) public virtual override {
        revert("uninstall reverts");
    }
}

abstract contract ERC7579HookMock is ERC7579ModuleMock(MODULE_TYPE_HOOK), IERC7579Hook {
    event PreCheck(address sender, uint256 value, bytes data);
    event PostCheck(bytes hookData);

    function preCheck(
        address msgSender,
        uint256 value,
        bytes calldata msgData
    ) external returns (bytes memory hookData) {
        emit PreCheck(msgSender, value, msgData);
        return msgData;
    }

    function postCheck(bytes calldata hookData) external {
        emit PostCheck(hookData);
    }
}

abstract contract ERC7579FallbackHandlerMock is ERC7579ModuleMock(MODULE_TYPE_FALLBACK) {
    event ERC7579FallbackHandlerMockCalled(address account, address sender, uint256 value, bytes data);

    error ERC7579FallbackHandlerMockRevert();

    function _msgAccount() internal view returns (address) {
        return msg.sender;
    }

    function _msgSender() internal pure returns (address) {
        return address(bytes20(msg.data[msg.data.length - 20:]));
    }

    function _msgData() internal pure returns (bytes calldata) {
        return msg.data[:msg.data.length - 20];
    }

    function callPayable() public payable {
        emit ERC7579FallbackHandlerMockCalled(_msgAccount(), _msgSender(), msg.value, _msgData());
    }

    function callView() public view returns (address, address) {
        return (_msgAccount(), _msgSender());
    }

    function callRevert() public pure {
        revert ERC7579FallbackHandlerMockRevert();
    }
}

contract ERC7579ValidatorMock is ERC7579Validator {
    mapping(address sender => address signer) private _associatedSigners;

    function onInstall(bytes calldata data) public virtual override {
        _associatedSigners[msg.sender] = address(bytes20(data[0:20]));
    }

    function onUninstall(bytes calldata /* data */) public virtual override {
        delete _associatedSigners[msg.sender];
    }

    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        return SignatureChecker.isValidSignatureNow(_associatedSigners[account], hash, signature);
    }
}

contract ERC7579ExecutorMock is ERC7579Executor {
    function onInstall(bytes calldata data) external {}

    function onUninstall(bytes calldata data) external {}

    function execute(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata data
    ) public payable virtual returns (bytes[] memory returnData) {
        return _execute(account, salt, mode, data);
    }
}

contract ERC7579MultisigConfidentialValidatorMock is ERC7579MultisigConfidentialValidator, ZamaEthereumConfig {}

contract ERC7579MultisigWeightedConfidentialValidatorMock is
    ERC7579MultisigWeightedConfidentialValidator,
    ZamaEthereumConfig
{}
