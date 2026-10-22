# Audits

| Date           | Commit                                                                          | Auditor      | Scope                                                                                                                                                                               | Links                       |
| -------------- | ------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| September 2026 | [`a044509`](https://github.com/openzeppelin/openzeppelin-accounts/tree/a044509) | OpenZeppelin | ERC7579SocialRecoveryExecutor, Multisig (full review); ERC7579Multisig, ERC7579MultisigWeighted, ERC7579DelayedExecutor, ERC7579Executor (diff against `6e14ef8`)                     | [🔗](./2026-09-a044509.pdf) |
| April 2026     | [`e7c7c65`](https://github.com/openzeppelin/openzeppelin-accounts/tree/e7c7c65) | OpenZeppelin | ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential, ERC7579MultisigConfidentialValidator, ERC7579MultisigWeightedConfidentialValidator, MultisigCoordinator           | [🔗](./2026-04-e7c7c65.pdf) |
| December 2025  | [`6e14ef8`](https://github.com/openzeppelin/openzeppelin-accounts/tree/6e14ef8) | OpenZeppelin | ERC7579Multisig, ERC7579MultisigWeighted, ERC7579DelayedExecutor, ERC7579Executor, ERC7579Validator                                                                                 | [🔗](./2025-12-6e14ef8.pdf) |

Resolutions for the April 2026 and September 2026 audits are at commits `f70475d` and `4ceb836` respectively.

## Unaudited contracts

The following contracts have not been in the scope of any audit:

- Account: `OpenAccount`, `OpenAccountFactory` (and `OpenAccountImplementation`)
- Extensions: `AccountERC8043Upgradeable`
- Signers: `ERC7579ECDSA`, `ERC7579P256`, `ERC7579WebAuthn`, `ERC7579SessionKeys`
- Validators: `ERC7579ECDSAValidator`, `ERC7579P256Validator`, `ERC7579WebAuthnValidator`, `ERC7579MultisigValidator`, `ERC7579MultisigWeightedValidator`, `ERC7579SessionKeysValidator`
- Executors: `ERC7579NativeSpender`, `ERC7579ERC20Spender`
- Utilities: `CrossChainSignatureChecker`, `ERC8043Utils`
