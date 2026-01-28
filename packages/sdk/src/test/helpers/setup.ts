import fs from 'node:fs';
import path from 'node:path';
import { ExecutionContext } from 'ava';
import { createTestClient, TestClient, parseEther, http, Hex } from 'viem';
import { Instance, Server } from 'prool';
import { entryPoint09Address } from 'viem/account-abstraction';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

interface Context {
  testClient: TestClient<'anvil'>;
  anvilServer: Server.CreateServerReturnType;
  bundlerServer: Server.CreateServerReturnType;
  anvil: Instance.Instance;
  alto: Instance.Instance;
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

const needsStart = (instance: Instance.Instance) =>
  instance.status === 'stopped' || instance.status === 'idle' || instance.status === 'stopping';
const needsStop = (instance: Instance.Instance) =>
  instance.status === 'started' || instance.status === 'starting' || instance.status === 'restarting';

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

  if (needsStart(t.context.anvil) && t.context.anvil.status) {
    try {
      await Promise.all([t.context.anvil.start(), t.context.anvilServer.start()]);
    } catch (error: unknown) {
      if (!(error as Error).message.startsWith('Failed to start process "anvil": Error: Address already in use')) {
        throw error;
      }
    }
  }
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
  if (needsStart(t.context.alto)) {
    try {
      await Promise.all([
        t.context.alto.start(),
        t.context.bundlerServer.start(),
        t.context.testClient.setBalance({ address: anvilAddress, value: parseEther('100') }),
      ]);
    } catch (error: unknown) {
      if (!(error as Error).message.startsWith('Failed to start process "anvil": Error: Address already in use')) {
        throw error;
      }
    }
  }
};

const cleanup = async (t: ExecutionContext<Context>) => {
  await Promise.all([cleanupAnvil(t), cleanupBundler(t)]);
};

const cleanupAnvil = async (t: ExecutionContext<Context>) => {
  if (needsStop(t.context.anvil)) {
    await Promise.all([t.context.anvil.stop(), t.context.anvilServer.stop()]);
  }
};

const cleanupBundler = async (t: ExecutionContext<Context>) => {
  if (needsStop(t.context.alto)) {
    await Promise.all([t.context.alto.stop(), t.context.bundlerServer.stop()]);
  }
};

export { Context, setup, cleanup };
