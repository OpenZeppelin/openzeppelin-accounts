import {
  Chain,
  Client,
  Hex,
  WalletActions,
  GetContractReturnType,
  PublicActions,
  getContract,
  Transport,
  Account,
  RpcSchema,
  Address,
  padHex,
} from 'viem';
import ECDSAValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json' with { type: 'json' };
import WebAuthnValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579WebAuthnValidator.sol/ERC7579WebAuthnValidator.json' with { type: 'json' };

const deployECDSAValidator = async (
  deployer: Client<Transport, Chain, Account, RpcSchema, PublicActions & WalletActions<Chain, Account>>,
): Promise<GetContractReturnType<typeof ECDSAValidatorArtifact.abi>> =>
  deployer
    .deployContract({
      abi: ECDSAValidatorArtifact.abi,
      bytecode: ECDSAValidatorArtifact.bytecode.object as Hex,
    })
    .then(hash => deployer.waitForTransactionReceipt({ hash }))
    .then(receipt =>
      getContract({
        address: receipt.contractAddress as Address,
        abi: ECDSAValidatorArtifact.abi,
        client: deployer,
      }),
    );

const deployWebAuthnValidator = async (
  deployer: Client<Transport, Chain, Account, RpcSchema, PublicActions & WalletActions<Chain, Account>>,
): Promise<GetContractReturnType<typeof WebAuthnValidatorArtifact.abi>> =>
  deployer
    .deployContract({
      abi: WebAuthnValidatorArtifact.abi,
      bytecode: WebAuthnValidatorArtifact.bytecode.object as Hex,
    })
    .then(hash => deployer.waitForTransactionReceipt({ hash }))
    .then(receipt =>
      getContract({
        address: receipt.contractAddress as Address,
        abi: WebAuthnValidatorArtifact.abi,
        client: deployer,
      }),
    );

export { deployECDSAValidator, deployWebAuthnValidator };
