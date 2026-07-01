import {
  entryPoint09Abi,
  entryPoint09Address,
  EntryPointVersion,
  toSmartAccount,
  ToSmartAccountParameters,
  SmartAccount,
  UserOperationRequest,
  SmartAccountImplementation,
  getUserOperationTypedData,
  WebAuthnAccount,
} from 'viem/account-abstraction';
import {
  type Account,
  Address,
  Chain,
  type Client,
  Hex,
  LocalAccount,
  RpcSchema,
  Transport,
  SignableMessage,
  OneOf,
} from 'viem';
import { encodeCalls, decodeCalls } from './erc7579.utils.js';
import { toSigner } from './signers/to-signer.js';
import type { Signer } from './signers/types.js';

/**
 * Signer accepted by {@link toERC7579Account} and downstream factories.
 *
 * Either the SDK's narrow {@link Signer} interface (returned by wrappers like
 * `toERC7913Signer`, `toCrossChainSigner`, `toMultisigSigner`) or a viem
 * `LocalAccount` / `WebAuthnAccount`, which is normalized via {@link toSigner}.
 */
type ToERC7579AccountSigner =
  | Signer
  | OneOf<Omit<LocalAccount, 'address' | 'signTransaction' | 'source'> | WebAuthnAccount>;

/**
 * Parameters required to create an ERC-7579 account.
 *
 * @property {Client} client The viem client to use for blockchain interactions
 * @property {ToERC7579AccountSigner} signer The signer to use for signing messages and operations. Accepts the SDK's {@link Signer} interface (from `toERC7913Signer`, `toCrossChainSigner`, ...) or a viem `LocalAccount` / `WebAuthnAccount`.
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
  signer: ToERC7579AccountSigner;
  getAddress: () => Promise<Address>;
  getFactoryArgs: () => Promise<{
    factory?: Address | undefined;
    factoryData?: Hex | undefined;
  }>;
  getStubSignature: (parameters?: UserOperationRequest | undefined) => Promise<Hex>;
} & Partial<ToSmartAccountParameters>;

const entryPointV09 = {
  address: entryPoint09Address,
  abi: entryPoint09Abi,
  version: '0.9' as EntryPointVersion,
} as const;

const isSigner = (candidate: ToERC7579AccountSigner): candidate is Signer =>
  'signMessage' in candidate && 'signTypedData' in candidate && !('source' in candidate) && !('type' in candidate);

/**
 * Creates a smart account client for an ERC-7579 account.
 */
const toERC7579Account = async (parameters: ToERC7579AccountParameters): Promise<SmartAccount> => {
  const { client, signer: signerInput, getAddress, getFactoryArgs, ...override } = parameters;
  const signer: Signer = isSigner(signerInput)
    ? signerInput
    : toSigner(signerInput as OneOf<LocalAccount | WebAuthnAccount>);

  return toSmartAccount({
    client,
    entryPoint: entryPointV09,
    decodeCalls,
    encodeCalls: async calls => encodeCalls(calls),
    getAddress,
    getFactoryArgs,
    async signMessage({ message }: { message: SignableMessage }) {
      return signer.signMessage({ message });
    },
    async signTypedData(parameters) {
      return signer.signTypedData(parameters as Parameters<Signer['signTypedData']>[0]);
    },
    async signUserOperation(userOperation: Parameters<SmartAccountImplementation['signUserOperation']>[0]) {
      const typedData = getUserOperationTypedData({
        entryPointAddress: entryPointV09.address,
        userOperation: {
          ...userOperation,
          sender: userOperation.sender ?? (await getAddress()),
        },
        chainId: client.chain?.id ?? 1,
      });
      return signer.signTypedData(typedData as Parameters<Signer['signTypedData']>[0]);
    },
    ...override,
  });
};

export { ToERC7579AccountParameters, ToERC7579AccountSigner, toERC7579Account };
