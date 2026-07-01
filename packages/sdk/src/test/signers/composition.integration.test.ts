import 'viem/window';
import _test, { TestFn } from 'ava';
import {
  encodeFunctionData,
  getContract,
  publicActions,
  TypedDataDefinition,
  type Address,
  type Hex,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import ERC7913CrossChainAppMockArtifact from '@openzeppelin-accounts/contracts/out/ERC7913CrossChainAppMock.sol/ERC7913CrossChainAppMock.json' with { type: 'json' };
import { setup, cleanup, type Context } from '../helpers/setup.js';
import { createAndFundEOA } from '../helpers/accounts.js';
import { toCrossChainSigner } from '../../signers/to-cross-chain-signer.js';
import { toERC7913Signer } from '../../signers/to-erc7913-signer.js';
import { toSigner } from '../../signers/to-signer.js';

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
  domain: { name: 'ERC7913CrossChainAppMock', version: '1.0.0' },
  message: { domain: { chainId, verifyingContract }, value },
});

const deployApp = async (deployer: Awaited<ReturnType<typeof createAndFundEOA>>) => {
  const hash = await deployer.deployContract({
    abi: ERC7913CrossChainAppMockArtifact.abi,
    bytecode: ERC7913CrossChainAppMockArtifact.bytecode.object as Hex,
    args: ['ERC7913CrossChainAppMock', '1.0.0'],
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const receipt = await deployer.waitForTransactionReceipt({ hash });
  return getContract({
    abi: ERC7913CrossChainAppMockArtifact.abi,
    address: receipt.contractAddress as Address,
    client: deployer,
  });
};

test('composition: toERC7913Signer(toCrossChainSigner(eoa)) verifies on-chain via ERC7913CrossChainAppMock', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < 2; i++) apps.push(await deployApp(deployer));

  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 5678n;
  const operations = apps.map(app => ({ operation: makeOperation(chainId, app.address as Address, value) }));

  for (let i = 0; i < apps.length; i++) {
    const composed = toERC7913Signer(
      toCrossChainSigner(toSigner(eoa), {
        application: apps[i]!.address as Address,
        currentChainIndex: i,
        operations,
        domain: { name: 'ERC7913CrossChainAppMock', version: '1.0.0' },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
      { address: eoa.address },
    );

    const composedSig = await composed.signTypedData(operations[i]!.operation);

    const txHash = await deployer.sendTransaction({
      to: apps[i]!.address as Address,
      data: encodeFunctionData({
        abi: ERC7913CrossChainAppMockArtifact.abi,
        functionName: 'setValue',
        args: [value, composedSig],
      }),
    });
    const receipt = await deployer.waitForTransactionReceipt({ hash: txHash });
    t.is(receipt.status, 'success', `setValue succeeded on app ${i}`);

    const stored = (await apps[i]!.read.value!([eoa.address])) as bigint;
    t.is(stored, value, `value persisted on app ${i}`);
  }
});
