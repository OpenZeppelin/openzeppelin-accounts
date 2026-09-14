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
} from 'viem';
import { ECDSAValidatorArtifact } from '../../artifacts/ERC7579ECDSAValidator.js';
import { WebAuthnValidatorArtifact } from '../../artifacts/ERC7579WebAuthnValidator.js';

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
