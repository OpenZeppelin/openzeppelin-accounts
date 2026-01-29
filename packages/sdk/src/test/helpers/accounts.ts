import {
  createWalletClient,
  parseEther,
  http,
  publicActions,
  encodePacked,
  bytesToHex,
  getContract,
  type GetContractReturnType,
  type Hex,
  type Address,
  type Chain,
  type Client,
  type LocalAccount,
  type PublicActions,
  type RpcSchema,
  type TestClient,
  type Transport,
  type WalletActions,
  type ExactPartial,
  type EstimateUserOperationGasReturnType,
  type TransactionReceipt,
} from 'viem';
import { ExecutionContext } from 'ava';
import { Account, generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import {
  createBundlerClient,
  estimateUserOperationGas,
  SmartAccount,
  UserOperationRequest,
} from 'viem/account-abstraction';
import { foundry } from 'viem/chains';
import { ModuleTypes } from '../../erc7579.utils.js';
import { toOpenAccount } from '../../open-account.js';
import type { Context } from './setup.js';
import OpenAccountFactoryArtifact from '@open-accounts-framework/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' with { type: 'json' };

interface OpenAccountContext extends Context {
  factory: GetContractReturnType<typeof OpenAccountFactoryArtifact.abi, Client>;
  account: SmartAccount;
  deployAccount: () => Promise<TransactionReceipt>;
}

const createAndFundEOA = async <
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
>(
  anvilPort: number,
  client: TestClient<'anvil', transport, chain, account, true, rpcSchema>,
  value: bigint = parseEther('100'),
): Promise<Client<Transport, Chain, LocalAccount, RpcSchema, PublicActions & WalletActions<Chain, LocalAccount>>> => {
  const eoa = createWalletClient({
    account: privateKeyToAccount(generatePrivateKey()),
    chain: foundry,
    transport: http(`http://localhost:${anvilPort}/`),
  }).extend(publicActions);
  await client.setBalance({ address: eoa.account.address, value });
  return eoa;
};

const createAndFundOpenAccount = async (
  t: ExecutionContext<OpenAccountContext>,
  { validator, signerKey, salt }: { validator: Address; signerKey: LocalAccount; salt: Hex },
) => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  t.context.factory = await deployer
    .deployContract({
      abi: OpenAccountFactoryArtifact.abi,
      bytecode: OpenAccountFactoryArtifact.bytecode.object as Hex,
      nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
    })
    .then(hash => deployer.waitForTransactionReceipt({ hash }))
    .then(receipt =>
      getContract({
        address: receipt.contractAddress as Address,
        abi: OpenAccountFactoryArtifact.abi,
        client: t.context.testClient,
      }),
    );

  t.context.account = await toOpenAccount({
    client: t.context.testClient as Client<Transport, Chain, LocalAccount, RpcSchema>,
    signer: signerKey,
    factory: t.context.factory,
    moduleTypeIds: [ModuleTypes.VALIDATOR],
    modules: [validator],
    initDatas: [encodePacked(['address'], [signerKey.address])],
    salt,
    getStubSignature: async () => bytesToHex(crypto.getRandomValues(new Uint8Array(65))),
    userOperation: {
      estimateGas: userOp =>
        estimateGasOverride(userOp)(t.context.bundlerPort, t.context.account, t.context.testClient),
    },
  });
  await t.context.testClient.setBalance({ address: t.context.account.address, value: parseEther('100') });
  t.context.deployAccount = () =>
    t.context.account.getFactoryArgs().then(async ({ factory, factoryData }) =>
      deployer
        .sendTransaction({
          to: factory as Address,
          data: factoryData as Hex,
          nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
        })
        .then(hash => deployer.waitForTransactionReceipt({ hash })),
    );
};

const estimateGasOverride =
  (userOp: UserOperationRequest, minVerificationGas: bigint = 150000n) =>
  async (
    bundlerPort: number,
    account: SmartAccount,
    client: TestClient<'anvil'>,
  ): Promise<ExactPartial<EstimateUserOperationGasReturnType>> => {
    const gas = await estimateUserOperationGas(
      createBundlerClient({
        account,
        client,
        transport: http(`http://localhost:${bundlerPort}/`),
      }),
      {
        calls: [{ to: account.address, data: userOp.callData }],
      },
    );
    return {
      verificationGasLimit:
        gas.verificationGasLimit < minVerificationGas ? minVerificationGas : gas.verificationGasLimit,
    };
  };

export { OpenAccountContext, createAndFundEOA, createAndFundOpenAccount, estimateGasOverride };
