import fs from 'node:fs';
import path from 'node:path';
import { ExecutionContext } from 'ava';
import {
  createTestClient,
  TestClient,
  parseEther,
  http,
  Hex,
  getContract,
  Client,
  Transport,
  Chain,
  RpcSchema,
  encodePacked,
  bytesToHex,
  type GetContractReturnType,
} from 'viem';
import { Instance, Server } from 'prool';
import {
  createBundlerClient,
  entryPoint09Address,
  estimateUserOperationGas,
  SmartAccount,
} from 'viem/account-abstraction';
import { Address, LocalAccount, privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import OpenAccountFactoryArtifact from '@open-accounts-framework/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' with { type: 'json' };
import { toOpenAccount } from '../../accounts/open-account.js';
import { MODULE_TYPE_VALIDATOR } from '../../erc7579.utils.js';
import { createAndFundEOA } from './eoa.js';

interface Context {
  testClient: TestClient<'anvil'>;
  anvilServer: Server.CreateServerReturnType;
  bundlerServer: Server.CreateServerReturnType;
  anvil: Instance.Instance;
  alto: Instance.Instance;
}

interface OpenAccountContext extends Context {
  factory: GetContractReturnType<typeof OpenAccountFactoryArtifact.abi, Client>;
  account: SmartAccount;
  deployAccount: () => Promise<Hex>;
}

const anvilPrivateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const anvilAddress = privateKeyToAccount(anvilPrivateKey).address;

const clientArgs = {
  chain: foundry,
  transport: http(),
} as const;

const testClientArgs = {
  mode: 'anvil',
  ...clientArgs,
} as const;

const senderCreatorV09Address = '0x0A630a99Df908A81115A3022927Be82f9299987e' as const;

const entrypointV09Bytecode = fs.readFileSync(
  path.join('node_modules', 'hardhat-predeploy', 'bin', `${entryPoint09Address}.bytecode`),
  'hex',
) as Hex;

const senderCreatorV09Bytecode = fs.readFileSync(
  path.join('node_modules', 'hardhat-predeploy', 'bin', `${senderCreatorV09Address}.bytecode`),
  'hex',
) as Hex;

const setup = async (t: ExecutionContext<Context>) => {
  t.context.testClient = createTestClient(testClientArgs);
  await setupAnvil(t);
  await setupEntrypoint(t);
  await setupBundler(t);
};

const setupAnvil = async (t: ExecutionContext<Context>) => {
  t.context.anvil = Instance.anvil({
    hardfork: 'Prague',
  });
  t.context.anvilServer = Server.create({
    instance: t.context.anvil,
  });

  await Promise.all([t.context.anvil.start(), t.context.anvilServer.start()]);
};

const setupEntrypoint = async (t: ExecutionContext<Context>) => {
  await t.context.testClient.setCode({
    address: entryPoint09Address,
    bytecode: entrypointV09Bytecode,
  });
  await t.context.testClient.setCode({
    address: senderCreatorV09Address,
    bytecode: senderCreatorV09Bytecode,
  });
};

const setupBundler = async (t: ExecutionContext<Context>) => {
  t.context.alto = Instance.alto({
    entrypoints: [entryPoint09Address],
    rpcUrl: 'http://localhost:8545/',
    executorPrivateKeys: [anvilPrivateKey],
    utilityPrivateKey: anvilPrivateKey,
    safeMode: false,
  });
  t.context.bundlerServer = Server.create({
    instance: t.context.alto,
  });
  await Promise.all([
    t.context.alto.start(),
    t.context.bundlerServer.start(),
    t.context.testClient.setBalance({ address: anvilAddress, value: parseEther('100') }),
  ]);
};

const setupOpenAccount = async (
  t: ExecutionContext<OpenAccountContext>,
  { validator, signerKey, salt }: { validator: Address; signerKey: LocalAccount; salt: Hex },
) => {
  const deployer = await createAndFundEOA(t.context.testClient);
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
    moduleTypeIds: [MODULE_TYPE_VALIDATOR],
    modules: [validator],
    initDatas: [encodePacked(['address'], [signerKey.address])],
    salt,
    getStubSignature: async () => bytesToHex(crypto.getRandomValues(new Uint8Array(65))),
    userOperation: {
      estimateGas: async userOp => {
        const gas = await estimateUserOperationGas(
          createBundlerClient({
            client: t.context.testClient,
            transport: http('http://localhost:3000/'),
          }),
          {
            account: t.context.account,
            calls: [{ to: t.context.account.address, data: userOp.callData }],
          },
        );
        const MIN_VERIFICATION_GAS = 150000n;
        return {
          verificationGasLimit:
            gas.verificationGasLimit < MIN_VERIFICATION_GAS ? MIN_VERIFICATION_GAS : gas.verificationGasLimit,
        };
      },
    },
  });
  await t.context.testClient.setBalance({ address: t.context.account.address, value: parseEther('100') });
  t.context.deployAccount = () =>
    t.context.account.getFactoryArgs().then(async ({ factory, factoryData }) =>
      deployer.sendTransaction({
        to: factory as Address,
        data: factoryData as Hex,
        nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
      }),
    );
};

const cleanup = async (t: ExecutionContext<Context>) => {
  await Promise.all([cleanupAnvil(t), cleanupBundler(t)]);
};

const cleanupAnvil = async (t: ExecutionContext<Context>) => {
  await Promise.all([t.context.anvil.stop(), t.context.anvilServer.stop()]);
};

const cleanupBundler = async (t: ExecutionContext<Context>) => {
  await Promise.all([t.context.alto.stop(), t.context.bundlerServer.stop()]);
};

export {
  Context,
  OpenAccountContext,
  createAndFundEOA,
  setup,
  setupAnvil,
  setupEntrypoint,
  setupBundler,
  setupOpenAccount,
  cleanup,
  cleanupAnvil,
  cleanupBundler,
};
