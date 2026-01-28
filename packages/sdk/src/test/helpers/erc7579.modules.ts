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

const validatorNonceKey = (validator: Address): bigint => BigInt(padHex(validator, { dir: 'right', size: 24 }));

const deployECDSAValidator = async (
  deployer: Client<Transport, Chain, Account, RpcSchema, PublicActions & WalletActions<Chain, Account>>,
): Promise<GetContractReturnType<typeof ECDSAValidatorArtifact.abi>> => {
  return deployer
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
};

export { deployECDSAValidator, validatorNonceKey };
