import {
  Address,
  concat,
  encodeFunctionData,
  getCreate2Address,
  keccak256,
  Client,
  Transport,
  Chain,
  Account,
  RpcSchema,
  Hex,
  GetContractReturnType,
  encodeAbiParameters,
  padHex,
  size,
  toHex,
  parseAbiParameters,
  zeroHash,
  publicActions,
  OneOf,
} from 'viem';
import { toERC7579Account, ToERC7579AccountParameters } from './erc7579-account.js';
import { ToSmartAccountParameters, SmartAccount, SmartAccountImplementation } from 'viem/account-abstraction';
import OpenAccountFactoryArtifact from '@openzeppelin-accounts/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' with { type: 'json' };
import { encodeMode, EncodeMode, ModuleType, parseModuleTypeId } from './erc7579.utils.js';
import { erc1967ProxyCode } from './erc1967.utils.js';
import { IERC7579AccountConfigABI } from './erc7579.abi.js';

/**
 * Parameters for using an existing deployed OpenAccount.
 *
 * @property {Address} address The address of the already deployed OpenAccount contract
 */
type OpenAccountExistingParameters = {
  address: Address;
};

/**
 * Parameters for creating a new OpenAccount via the factory.
 *
 * @property {GetContractReturnType} factory The OpenAccountFactory contract instance used to create and deploy accounts
 * @property {ModuleType[]} moduleTypeIds Array of module type identifiers (validator, executor, hook, fallback) to install during initialization
 * @property {Address[]} modules Array of module contract addresses corresponding to each module type
 * @property {Hex[]} initDatas Array of initialization data for each module, passed during module installation
 * @property {EncodeMode} [configMode] Optional execution mode for the configuration calldata
 * @property {Hex} [configCalldata] Optional calldata to execute after initialization for account configuration
 * @property {Hex} [salt] Optional salt for deterministic address generation via CREATE2
 */
type OpenAccountFactoryParameters<
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
> = {
  factory: GetContractReturnType<typeof OpenAccountFactoryArtifact.abi, Client<transport, chain, account, rpcSchema>>;
  moduleTypeIds: ModuleType[];
  modules: Address[];
  initDatas: Hex[];
  configMode?: EncodeMode;
  configCalldata?: Hex;
  salt?: Hex;
};

/**
 * Union type for OpenAccount parameters.
 *
 * Supports two modes:
 * 1. Using an existing deployed account via `OpenAccountExistingParameters`
 * 2. Creating a new account via factory using `OpenAccountFactoryParameters`
 *
 * @property {Address} validator The address of the ERC-7579 validator module that authorises this signer. Used to (1) prefix `signMessage`/`signTypedData` outputs for ERC-1271 routing, and (2) encode the validator in the upper 20 bytes of the nonce key for UserOp routing
 */
type OpenAccountParameters<
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
> = OneOf<OpenAccountExistingParameters | OpenAccountFactoryParameters<transport, chain, account, rpcSchema>> & {
  validator: Address;
};

/**
 * Parameters required to create an OpenAccount smart account.
 *
 * Combines ERC-7579 account parameters with OpenAccount-specific parameters.
 * See {@link OpenAccountFactoryParameters} for creating new accounts or {@link OpenAccountExistingParameters} for using existing accounts.
 *
 * @property {Client} client The viem client to use for blockchain interactions
 * @property {ERC7579AccountSigner} signer The signer to use for signing messages and operations. Accepts the SDK's `Signer` interface (from `toERC7913Signer`, `toCrossChainSigner`, `toMultisigner`, ...) or a viem `LocalAccount` / `WebAuthnAccount`.
 * @property {function(UserOperationRequest?): Promise<Hex>} getStubSignature Function that returns a stub signature for gas estimation
 */
type ToOpenAccountParameters<
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
> = Pick<ToERC7579AccountParameters<transport, chain, account, rpcSchema>, 'client' | 'signer' | 'getStubSignature'> &
  Partial<Omit<ToSmartAccountParameters, 'signMessage' | 'signTypedData' | 'signUserOperation'>> &
  OpenAccountParameters<transport, chain, account, rpcSchema>;

/**
 * Creates a smart account client for an OpenAccount.
 */
const toOpenAccount = async (parameters: ToOpenAccountParameters): Promise<SmartAccount> => {
  const { client, signer, validator, ...override } = parameters;
  const { getAddress, getFactoryArgs } = await openAccountArgs(parameters);

  const account = await toERC7579Account({
    client,
    signer,
    getAddress,
    getFactoryArgs,
    ...override,
  });

  const defaults = {
    signMessage: account.signMessage,
    signTypedData: account.signTypedData,
    getNonce: account.getNonce,
  };

  account.signMessage = signMessageParameters =>
    defaults.signMessage
      .bind(account)(signMessageParameters)
      .then(sig => concat([validator, sig]));
  account.signTypedData = typedDataParameters =>
    defaults.signTypedData
      .bind(account)(typedDataParameters)
      .then(sig => concat([validator, sig]));
  account.getNonce = async ({ key }: { key?: bigint } = {}) => {
    if (key !== undefined && size(toHex(key)) > 4) {
      throw new Error(`Key must be at most 4 bytes when a validator is configured, got ${toHex(key)}`);
    }
    return defaults.getNonce.bind(account)({
      key: BigInt(padHex(validator, { dir: 'right', size: 24 })) | (key ?? 0n),
    });
  };

  return account;
};

/**
 * Prepares the `getAddress` and `getFactoryArgs` functions for an OpenAccount.
 * In case the parameters include a factory, it must include the module type ids, modules, init datas, config mode, config calldata and salt
 * to create the account. Otherwise, if an `address` is provided, it the client will assume the account is already deployed at that address.
 */
const openAccountArgs = async (
  parameters: ToOpenAccountParameters,
): Promise<Pick<SmartAccountImplementation, 'getAddress' | 'getFactoryArgs'>> => {
  const { client } = parameters;

  if ('address' in parameters && parameters.address) {
    const accountId = await client.extend(publicActions).readContract({
      abi: IERC7579AccountConfigABI,
      address: parameters.address,
      functionName: 'accountId',
    });
    if (!accountId.startsWith('@openzeppelin/contracts.AccountERC7579.'))
      throw new Error('Not an OpenAccount or not deployed');
    return {
      getAddress: async () => parameters.address,
      getFactoryArgs: async () => ({
        factory: undefined,
        factoryData: undefined,
      }),
    };
  } else if ('factory' in parameters) {
    const { factory, moduleTypeIds, modules, initDatas, configMode, configCalldata, salt } = parameters;
    const implementation = (await factory.read.implementation?.()) as Address;
    if (!implementation) throw new Error('Implementation not found');

    const initializationArgs: [bigint[], Hex[], Hex[], Hex, Hex, Hex] = [
      moduleTypeIds.map(parseModuleTypeId),
      modules,
      initDatas,
      encodeMode(configMode) as Hex,
      configCalldata ?? '0x',
      salt ?? zeroHash,
    ];

    return {
      getAddress: async (): Promise<Address> =>
        getCreate2Address({
          bytecode: erc1967ProxyCode(implementation),
          from: parameters.factory.address,
          salt: keccak256(
            encodeAbiParameters(
              parseAbiParameters(['uint256[]', 'address[]', 'bytes[]', 'bytes32', 'bytes', 'bytes32']),
              initializationArgs,
            ),
          ),
        }),
      getFactoryArgs: async () => ({
        factory: factory.address,
        factoryData: encodeFunctionData({
          abi: OpenAccountFactoryArtifact.abi,
          functionName: 'createAndInitialize',
          args: initializationArgs,
        }),
      }),
    };
  }

  throw new Error('Invalid parameters');
};

export {
  OpenAccountExistingParameters,
  OpenAccountFactoryParameters,
  OpenAccountParameters,
  ToOpenAccountParameters,
  toOpenAccount,
};
