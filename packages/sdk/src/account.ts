import {
  entryPoint09Abi,
  entryPoint09Address,
  EntryPointVersion,
  getUserOperationHash,
  toSmartAccount,
  ToSmartAccountParameters,
  ToSmartAccountReturnType,
  UserOperationRequest,
  SmartAccountImplementation,
} from 'viem/account-abstraction';
import { Address, type Client, getContract, Hex, LocalAccount } from 'viem';
import { encodeCalls, decodeCalls } from './erc7579.utils.js';

/**
 * Parameters required to create an ERC-7579 account.
 *
 * @property {Client} client The viem client to use for blockchain interactions
 * @property {LocalAccount} signer The local account signer to use for signing messages and operations
 * @property {function(): Promise<Address>} getAddress Function that resolves to the account's address
 * @property {function(): Promise<{factory?: Address, factoryData?: Hex}>} getFactoryArgs Function that returns the factory address and data for account deployment
 * @property {function(UserOperationRequest?): Promise<Hex>} getStubSignature Function that returns a stub signature for gas estimation
 */
type ToERC7579AccountParameters = {
  client: Client;
  signer: LocalAccount;
  getAddress: () => Promise<Address>;
  getFactoryArgs: () => Promise<{
    factory?: Address | undefined;
    factoryData?: Hex | undefined;
  }>;
  // eslint-disable-next-line no-unused-vars
  getStubSignature: (parameters?: UserOperationRequest | undefined) => Promise<Hex>;
} & Partial<ToSmartAccountParameters>;

const entryPointV09 = {
  address: entryPoint09Address,
  abi: entryPoint09Abi,
  version: '0.9' as EntryPointVersion,
} as const;

/**
 * Creates a smart account client for an ERC-7579 account.
 */
const toERC7579Account = async (parameters: ToERC7579AccountParameters): Promise<ToSmartAccountReturnType> => {
  const { client, signer, getAddress, getFactoryArgs, ...override } = parameters;

  return toSmartAccount({
    client,
    entryPoint: entryPointV09,
    decodeCalls,
    encodeCalls: async calls => encodeCalls(calls),
    getAddress,
    getFactoryArgs,
    async getNonce({ key } = {}) {
      return this.getAddress().then(addr => getContract({ client, ...entryPointV09 }).read.getNonce([addr, key ?? 0n]));
    },
    signMessage: signer.signMessage,
    signTypedData: signer.signTypedData,
    async signUserOperation(userOperation: Parameters<SmartAccountImplementation['signUserOperation']>[0]) {
      const userOpHash = getUserOperationHash({
        entryPointAddress: entryPointV09.address,
        entryPointVersion: entryPointV09.version,
        userOperation: {
          ...userOperation,
          sender: userOperation.sender ?? (await getAddress()),
        },
        chainId: userOperation.chainId!,
      });
      return signer.signMessage({ message: { raw: userOpHash } });
    },
    ...override,
  });
};

export { ToERC7579AccountParameters, toERC7579Account };
