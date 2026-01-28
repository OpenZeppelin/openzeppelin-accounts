import _test, { TestFn } from 'ava';
import { createAndFundEOA, setupOpenAccount, setup, cleanup, OpenAccountContext } from '../helpers/setup.js';
import { bytesToHex, GetContractReturnType, http, encodePacked, parseEther, publicActions, Transport } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { BundlerClient, createBundlerClient, SmartAccount } from 'viem/account-abstraction';
import ECDSAValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json' with { type: 'json' };
import { deployECDSAValidator, validatorNonceKey } from '../helpers/erc7579.modules.js';
import { erc7579Actions, ERC7579Actions } from '../../erc7579.actions.js';
import { MODULE_TYPE_VALIDATOR } from '../../erc7579.utils.js';

interface OpenAccountTestContext extends OpenAccountContext {
  ECDSAValidator: GetContractReturnType<typeof ECDSAValidatorArtifact.abi>;
  bundlerClient: Omit<
    BundlerClient<Transport, undefined, SmartAccount>,
    'client' | 'paymaster' | 'paymasterContext' | 'userOperation'
  > &
    ERC7579Actions<SmartAccount>;
}

const test = _test as TestFn<OpenAccountTestContext>;

test.before(setup);

test.beforeEach(async t => {
  const deployer = await createAndFundEOA(t.context.testClient);
  t.context.ECDSAValidator = await deployECDSAValidator(deployer);
  await setupOpenAccount(t, {
    validator: t.context.ECDSAValidator.address,
    signerKey: privateKeyToAccount(generatePrivateKey()),
    salt: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
  });
  t.context.bundlerClient = createBundlerClient({
    account: t.context.account,
    client: t.context.testClient,
    transport: http('http://localhost:3000/'),
  }).extend(erc7579Actions());
});

test.after.always(cleanup);

test('installs, uses, and uninstalls ECDSAValidator module', async t => {
  const deployer = await createAndFundEOA(t.context.testClient);
  const validator = await deployECDSAValidator(deployer);
  const signer = privateKeyToAccount(generatePrivateKey());
  const client = t.context.bundlerClient;

  // Install module
  await t.context.account.getNonce({ key: validatorNonceKey(validator.address) }).then(nonce =>
    client.installModules({
      modules: [
        {
          type: MODULE_TYPE_VALIDATOR,
          address: validator.address,
          initData: encodePacked(['address'], [signer.address]),
        },
      ],
      nonce,
    }),
  );
  await client
    .isModuleInstalled({
      type: MODULE_TYPE_VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, true));

  // Use module
  const receiver = privateKeyToAccount(generatePrivateKey());
  await t.context.account.getNonce({ key: validatorNonceKey(validator.address) }).then(nonce =>
    client.execute({
      calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }],
      nonce,
    }),
  );
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('1')));

  // Uninstall module
  await t.context.account.getNonce({ key: validatorNonceKey(validator.address) }).then(nonce =>
    client.uninstallModules({
      modules: [{ type: MODULE_TYPE_VALIDATOR, address: validator.address, deInitData: '0x' }],
      nonce,
    }),
  );
  await client
    .isModuleInstalled({
      type: MODULE_TYPE_VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, false));
});
