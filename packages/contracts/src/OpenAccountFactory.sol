// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {OpenAccount} from "./OpenAccount.sol";

/// @dev Implementation contract for the OpenAccount factory.
contract OpenAccountImplementation is OpenAccount, UUPSUpgradeable {
    constructor() EIP712("OpenAccount", "1") {
        _disableInitializers();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyEntryPointOrSelf {}
}

/**
 * @dev A factory contract to create OpenAccount instances on demand.
 */
contract OpenAccountFactory {
    address public immutable implementation = address(new OpenAccountImplementation());

    /// @dev Predict the address of the account
    function predictAddress(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        Mode configMode,
        bytes memory configCalldata,
        bytes32 salt
    ) public view returns (address) {
        return
            Create2.computeAddress(
                salt,
                _proxyCreationCodeHash(moduleTypeIds, modules, initDatas, configMode, configCalldata)
            );
    }

    /// @dev Create OpenAccount instances on demand and initialize them with the given modules and init datas
    function createAndInitialize(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        Mode configMode,
        bytes memory configCalldata,
        bytes32 salt
    ) public returns (address) {
        bytes memory proxyCreationCode = _proxyCreationCode(
            moduleTypeIds,
            modules,
            initDatas,
            configMode,
            configCalldata
        );
        bytes32 codeHash = keccak256(proxyCreationCode);
        address predicted = Create2.computeAddress(salt, codeHash);
        if (predicted.code.length == 0) {
            Create2.deploy(0, salt, proxyCreationCode);
        }
        return predicted;
    }

    function _proxyCreationCode(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        Mode configMode,
        bytes memory configCalldata
    ) private view returns (bytes memory) {
        return
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    implementation,
                    abi.encodeCall(
                        OpenAccount.initialize,
                        (moduleTypeIds, modules, initDatas, configMode, configCalldata)
                    )
                )
            );
    }

    function _proxyCreationCodeHash(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        Mode configMode,
        bytes memory configCalldata
    ) private view returns (bytes32) {
        return keccak256(_proxyCreationCode(moduleTypeIds, modules, initDatas, configMode, configCalldata));
    }
}
