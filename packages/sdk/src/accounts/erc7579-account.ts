import {
  entryPoint09Abi,
  entryPoint09Address,
  EntryPointVersion,
  toSmartAccount,
  ToSmartAccountParameters,
  ToSmartAccountReturnType,
  UserOperationRequest,
  SmartAccountImplementation,
  getUserOperationTypedData,
} from 'viem/account-abstraction';
import { type Account, Address, Chain, type Client, getContract, Hex, LocalAccount, RpcSchema, Transport } from 'viem';
import { encodeCalls, decodeCalls } from '../erc7579.utils.js';

/**
 * Parameters required to create an ERC-7579 account.
 *
 * @property {Client} client The viem client to use for blockchain interactions
 * @property {LocalAccount} signer The local account signer to use for signing messages and operations
 * @property {function(): Promise<Address>} getAddress Function that resolves to the account's address
 * @property {function(): Promise<{factory?: Address, factoryData?: Hex}>} getFactoryArgs Function that returns the factory address and data for account deployment
 * @property {function(UserOperationRequest?): Promise<Hex>} getStubSignature Function that returns a stub signature for gas estimation
 */
type ToERC7579AccountParameters<
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
> = {
  client: Client<transport, chain, account, rpcSchema>;
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
      return signer.signTypedData(
        getUserOperationTypedData({
          entryPointAddress: entryPointV09.address,
          userOperation: {
            ...userOperation,
            sender: userOperation.sender ?? (await getAddress()),
          },
          chainId: client.chain?.id ?? 1,
        }),
      );
    },
    ...override,
  });
};

export { ToERC7579AccountParameters, toERC7579Account };
