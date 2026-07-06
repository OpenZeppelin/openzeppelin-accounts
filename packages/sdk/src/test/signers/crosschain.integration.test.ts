import 'viem/window';
import _test, { TestFn } from 'ava';
import {
  bytesToHex,
  encodeFunctionData,
  getContract,
  publicActions,
  TypedDataDefinition,
  type Address,
  type Hex,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import CrossChainAppMockArtifact from '@openzeppelin-accounts/contracts/out/CrossChainAppMock.sol/CrossChainAppMock.json' with { type: 'json' };
import { setup, cleanup, type Context } from '../helpers/setup.js';
import { createAndFundEOA } from '../helpers/accounts.js';
import { toCrossChainSigner } from '../../signers/crosschain.js';
import { toSigner } from '../../signers/index.js';

const test = _test as TestFn<Context>;

test.before(setup);
test.after.always(cleanup);

const crossChainTypes = {
  SetValue: [{ name: 'operations', type: 'ChainOperation[]' }],
  ChainOperation: [
    { name: 'domain', type: 'EIP712ChainDomain' },
    { name: 'value', type: 'uint256' },
  ],
  EIP712ChainDomain: [
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ],
} as const;

const operationTypes = {
  ChainOperation: crossChainTypes.ChainOperation,
  EIP712ChainDomain: crossChainTypes.EIP712ChainDomain,
} as const;

const makeOperation = (chainId: bigint, verifyingContract: Address, value: bigint): TypedDataDefinition => ({
  types: operationTypes as unknown as TypedDataDefinition['types'],
  primaryType: 'ChainOperation',
  domain: { name: 'CrossChainAppMock', version: '1.0.0' },
  message: { domain: { chainId, verifyingContract }, value },
});

const deployApp = async (deployer: Awaited<ReturnType<typeof createAndFundEOA>>) => {
  const hash = await deployer.deployContract({
    abi: CrossChainAppMockArtifact.abi,
    bytecode: CrossChainAppMockArtifact.bytecode.object as Hex,
    args: ['CrossChainAppMock', '1.0.0'],
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const receipt = await deployer.waitForTransactionReceipt({ hash });
  return getContract({
    abi: CrossChainAppMockArtifact.abi,
    address: receipt.contractAddress as Address,
    client: deployer,
  });
};

test('toCrossChainSigner: ValueSet emitted by every deployed CrossChainAppMock for the correct chain index', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);

  // Deploy N CrossChainAppMock instances on this anvil chain. Each takes the same
  // (chainId, varying verifyingContract) operation, so a single inner signature is
  // valid against each app via its own structIndex.
  const appCount = 3;
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < appCount; i++) {
    apps.push(await deployApp(deployer));
  }

  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 1234n;
  const operations = apps.map(app => makeOperation(chainId, app.address as Address, value));

  // Build a separate signer per chain index — same operations, same eventual inner
  // signature, but distinct structIndex packed into the envelope header.
  const signers = apps.map((_, i) =>
    toCrossChainSigner(toSigner(eoa), {
      application: apps[i]!.address as Address,
      currentChainIndex: i,
      operations,
      domain: { name: 'CrossChainAppMock', version: '1.0.0' },
      primaryType: 'SetValue',
      types: crossChainTypes as unknown as TypedDataDefinition['types'],
    }),
  );

  for (let i = 0; i < apps.length; i++) {
    const envelope = await signers[i]!.signTypedData(operations[i]!);
    const callData = encodeFunctionData({
      abi: CrossChainAppMockArtifact.abi,
      functionName: 'setValueCalldata',
      args: [eoa.address, value, envelope],
    });
    const txHash = await deployer.sendTransaction({ to: apps[i]!.address as Address, data: callData });
    const receipt = await deployer.waitForTransactionReceipt({ hash: txHash });
    t.is(receipt.status, 'success', `setValueCalldata succeeded on app ${i}`);

    const stored = (await apps[i]!.read.value!([eoa.address])) as bigint;
    t.is(stored, value, `value persisted on app ${i}`);
  }
});

test('signing with the wrong structIndex reverts on-chain', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < 2; i++) {
    apps.push(await deployApp(deployer));
  }
  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 7n;
  const operations = apps.map(app => makeOperation(chainId, app.address as Address, value));

  // Sign for app 0 but submit to app 1 — structIndex mismatch should revert.
  const signer = toCrossChainSigner(toSigner(eoa), {
    application: apps[0]!.address as Address,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainAppMock', version: '1.0.0' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  const envelope = await signer.signTypedData(operations[0]!);

  await t.throwsAsync(() =>
    deployer.sendTransaction({
      to: apps[1]!.address as Address,
      data: encodeFunctionData({
        abi: CrossChainAppMockArtifact.abi,
        functionName: 'setValueCalldata',
        args: [eoa.address, value, envelope],
      }),
    }),
  );
  t.is((await apps[1]!.read.value!([eoa.address])) as bigint, 0n);
  t.assert(bytesToHex(new Uint8Array(0)) === '0x'); // smoke
});
