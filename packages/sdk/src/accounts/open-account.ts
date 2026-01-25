import {
  Address,
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
  parseAbiParameters,
  zeroHash,
} from 'viem';
import { toERC7579Account, ToERC7579AccountParameters } from './erc7579-account.js';
import { ToSmartAccountParameters, ToSmartAccountReturnType } from 'viem/account-abstraction';
import OpenAccountFactoryArtifact from '@open-accounts-framework/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' with { type: 'json' };
import { encodeMode, EncodeMode, ModuleType, parseModuleTypeId } from '../erc7579.utils.js';
import { erc1967ProxyCode } from '../erc1967.utils.js';

/**
 * Parameters required to create an OpenAccount.
 *
 * @property {Client} client The viem client to use for blockchain interactions
 * @property {LocalAccount} signer The local account signer to use for signing messages and operations
 * @property {function(UserOperationRequest?): Promise<Hex>} getStubSignature Function that returns a stub signature for gas estimation
 * @property {GetContractReturnType} factory The OpenAccountFactory contract instance used to create and deploy accounts
 * @property {ModuleType[]} moduleTypeIds Array of module type identifiers (validator, executor, etc.) to install during initialization
 * @property {Address[]} modules Array of module contract addresses corresponding to each module type
 * @property {Hex[]} initDatas Array of initialization data for each module, passed during module installation
 * @property {EncodeMode} [configMode] Optional execution mode for the configuration calldata
 * @property {Hex} [configCalldata] Optional calldata to execute after initialization for account configuration
 * @property {Hex} [salt] Optional salt for deterministic address generation via CREATE2
 */
type ToOpenAccountParameters<
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
> = Pick<ToERC7579AccountParameters<transport, chain, account, rpcSchema>, 'client' | 'signer' | 'getStubSignature'> & {
  factory: GetContractReturnType<typeof OpenAccountFactoryArtifact.abi, Client<transport, chain, account, rpcSchema>>;
  moduleTypeIds: ModuleType[];
  modules: Address[];
  initDatas: Hex[];
  configMode?: EncodeMode;
  configCalldata?: Hex;
  salt?: Hex;
} & Partial<ToSmartAccountParameters>;

/**
 * Creates a smart account client for an OpenAccount.
 */
const toOpenAccount = async (parameters: ToOpenAccountParameters): Promise<ToSmartAccountReturnType> => {
  const { client, signer, factory, moduleTypeIds, modules, initDatas, configMode, configCalldata, salt, ...override } =
    parameters;
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

  const address = getCreate2Address({
    bytecode: erc1967ProxyCode(implementation),
    from: factory.address,
    salt: keccak256(
      encodeAbiParameters(
        parseAbiParameters(['uint256[]', 'address[]', 'bytes[]', 'bytes32', 'bytes', 'bytes32']),
        initializationArgs,
      ),
    ),
  });

  const factoryArgs = {
    factory: factory.address,
    factoryData: encodeFunctionData({
      abi: OpenAccountFactoryArtifact.abi,
      functionName: 'createAndInitialize',
      args: initializationArgs,
    }),
  };

  return toERC7579Account({
    client,
    signer,
    getAddress: async () => address,
    getFactoryArgs: async () => Promise.resolve(factoryArgs),
    ...override,
  });
};

export { ToOpenAccountParameters, toOpenAccount };
