import { Chain, Client, Hash, Transport, Address, Hex, Call, encodeFunctionData, getAddress } from 'viem';
import {
  type GetSmartAccountParameter,
  type SmartAccount,
  sendUserOperation,
  SendUserOperationParameters,
} from 'viem/account-abstraction';
import { readContract } from 'viem/actions';
import { getAction, parseAccount } from 'viem/utils';
import { IERC7579AccountConfigABI, IERC7579ModuleConfigABI } from './erc7579.abi.js';
import {
  CallType,
  encodeCalls,
  EncodeMode,
  encodeMode,
  ExecType,
  parseModuleTypeId,
  type ModuleType,
} from './erc7579.utils.js';

/**
 * Extracts the smart account from the client or parameters.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {object} [parameters] Optional parameters containing an account override
 * @returns {SmartAccount} The smart account instance
 * @throws {Error} If no account is found
 */
function hoistAccount<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters?: Partial<Pick<GetSmartAccountParameter<TSmartAccount>, 'account'>>,
): SmartAccount {
  let account = client.account;

  if (parameters) {
    account = (parameters.account || account) as TSmartAccount;
  }

  if (!account) {
    throw new Error('Account not found');
  }

  return account;
}

/**
 * Retrieves the account ID for an ERC-7579 account.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {object} [parameters] Optional parameters containing an account override
 * @returns {Promise<string>} The account ID string
 */
async function accountId<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters?: GetSmartAccountParameter<TSmartAccount>,
): Promise<string> {
  const account = await hoistAccount(client, parameters);

  const publicClient = account.client;

  return getAction(
    publicClient,
    readContract,
    'readContract',
  )({
    abi: IERC7579AccountConfigABI,
    functionName: 'accountId',
    address: await account.getAddress(),
  });
}

/**
 * Parameters required to install modules on an ERC-7579 account.
 *
 * @property {object[]} modules Array of modules to install
 * @property {ModuleType} modules[].type The type of module to install
 * @property {Address} modules[].address The address of the module contract
 * @property {Hex} modules[].initData The initialization data for the module
 * @property {ExecType} [execType] Optional execution type for the user operation
 */
type InstallModulesParameters<TSmartAccount extends SmartAccount | undefined> =
  GetSmartAccountParameter<TSmartAccount> &
    Omit<SendUserOperationParameters<TSmartAccount, TSmartAccount, readonly Call[]>, 'calls' | 'callData'> & {
      modules: {
        type: ModuleType;
        address: Address;
        initData: Hex;
      }[];
      execType?: ExecType;
      calls?: readonly Call[];
      callData?: Hex;
    };

/**
 * Installs one or more modules on an ERC-7579 account via a user operation.
 * If multiple modules are provided, they are installed in a batch.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {InstallModulesParameters} parameters The parameters for installing modules
 * @returns {Promise<Hex>} The hash of the user operation
 * @throws {Error} If no modules are provided
 */
async function installModules<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters: InstallModulesParameters<TSmartAccount>,
): Promise<Hex> {
  const account = await hoistAccount(client, parameters);

  if (!parameters.modules.length) {
    throw new Error('No modules to install');
  }

  const actionArgs = { ...parameters, account: parseAccount(account) as SmartAccount };

  const installations: readonly Call[] = parameters.modules.map(({ type, address, initData }) => ({
    to: account.address,
    value: 0n,
    data: encodeFunctionData({
      abi: IERC7579ModuleConfigABI,
      functionName: 'installModule',
      args: [parseModuleTypeId(type), address, initData],
    }),
  }));

  if ('calls' in actionArgs) {
    actionArgs.calls = [
      {
        to: account.address,
        value: 0n,
        data: encodeCalls(installations.concat(actionArgs.calls ?? []), { execType: parameters.execType }),
      },
    ];
  } else {
    actionArgs.callData = encodeCalls(
      installations.concat([{ to: account.address, value: 0n, data: actionArgs.callData }]),
      {
        execType: parameters.execType,
      },
    );
  }

  return getAction(
    client,
    sendUserOperation,
    'sendUserOperation',
  )(actionArgs as SendUserOperationParameters<TSmartAccount, TSmartAccount, readonly Call[]>);
}

/**
 * Parameters required to check if a module is installed on an ERC-7579 account.
 *
 * @property {ModuleType} type The type of module to check
 * @property {Address} address The address of the module contract
 * @property {Hex} additionalContext Additional context data for the module check
 */
type IsModuleInstalledParameters<TSmartAccount extends SmartAccount | undefined> =
  GetSmartAccountParameter<TSmartAccount> & {
    type: ModuleType;
    address: Address;
    additionalContext?: Hex;
  };

/**
 * Checks if a module is installed on an ERC-7579 account.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {IsModuleInstalledParameters} parameters The parameters for checking module installation
 * @returns {Promise<boolean>} True if the module is installed, false otherwise
 */
async function isModuleInstalled<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters: IsModuleInstalledParameters<TSmartAccount>,
): Promise<boolean> {
  const account = await hoistAccount(client, parameters);
  const { type, address, additionalContext } = parameters;

  const publicClient = account.client;

  return getAction(
    publicClient,
    readContract,
    'readContract',
  )({
    abi: IERC7579ModuleConfigABI,
    functionName: 'isModuleInstalled',
    args: [parseModuleTypeId(type), getAddress(address), additionalContext ?? '0x'],
    address: account.address,
  });
}

/**
 * Parameters required to check if an ERC-7579 account supports a specific execution mode.
 *
 * @property {CallType} [callType] The call type to check
 * @property {ExecType} [execType] The execution type to check
 * @property {Hex} [selector] The function selector to check
 * @property {Hex} [payload] The payload data to check
 */
type SupportsExecutionModeParameters<TSmartAccount extends SmartAccount | undefined> =
  GetSmartAccountParameter<TSmartAccount> & EncodeMode;

/**
 * Checks if an ERC-7579 account supports a specific execution mode.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {SupportsExecutionModeParameters} parameters The parameters for checking execution mode support
 * @returns {Promise<boolean>} True if the execution mode is supported, false otherwise
 */
async function supportsExecutionMode<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters: SupportsExecutionModeParameters<TSmartAccount>,
): Promise<boolean> {
  const account = await hoistAccount(client, parameters);
  const { callType, execType, selector, payload } = parameters;

  const publicClient = account.client;

  return getAction(
    publicClient,
    readContract,
    'readContract',
  )({
    abi: IERC7579AccountConfigABI,
    functionName: 'supportsExecutionMode',
    args: [
      encodeMode({
        callType,
        execType,
        selector,
        payload,
      }),
    ],
    address: account.address,
  });
}

/**
 * Parameters required to check if an ERC-7579 account supports a specific module type.
 *
 * @property {ModuleType} type The module type to check
 */
type SupportsModuleParameters<TSmartAccount extends SmartAccount | undefined> =
  GetSmartAccountParameter<TSmartAccount> & {
    type: ModuleType;
  };

/**
 * Checks if an ERC-7579 account supports a specific module type.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {SupportsModuleParameters} parameters The parameters for checking module type support
 * @returns {Promise<boolean>} True if the module type is supported, false otherwise
 */
async function supportsModule<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters: SupportsModuleParameters<TSmartAccount>,
): Promise<boolean> {
  const account = await hoistAccount(client, parameters);

  const publicClient = account.client;

  return getAction(
    publicClient,
    readContract,
    'readContract',
  )({
    abi: IERC7579AccountConfigABI,
    functionName: 'supportsModule',
    args: [parseModuleTypeId(parameters.type)],
    address: account.address,
  });
}

/**
 * Parameters required to uninstall modules from an ERC-7579 account.
 *
 * @property {object[]} modules Array of modules to uninstall
 * @property {ModuleType} modules[].type The type of module to uninstall
 * @property {Address} modules[].address The address of the module contract
 * @property {Hex} modules[].deInitData The deinitialization data for the module
 * @property {ExecType} [execType] Optional execution type for the user operation
 */
type UninstallModulesParameters<TSmartAccount extends SmartAccount | undefined> = Omit<
  SendUserOperationParameters<TSmartAccount, TSmartAccount, readonly Call[]>,
  'calls' | 'callData'
> & {
  modules: {
    type: ModuleType;
    address: Address;
    deInitData?: Hex;
  }[];
  execType?: ExecType;
  calls?: readonly Call[];
  callData?: Hex;
};

/**
 * Uninstalls one or more modules from an ERC-7579 account via a user operation.
 * If multiple modules are provided, they are uninstalled in a batch.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {UninstallModulesParameters} parameters The parameters for uninstalling modules
 * @returns {Promise<Hex>} The hash of the user operation
 * @throws {Error} If no modules are provided
 */
async function uninstallModules<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters: UninstallModulesParameters<TSmartAccount>,
): Promise<Hex> {
  const account = await hoistAccount(client, parameters);

  if (!parameters.modules.length) {
    throw new Error('No modules to uninstall');
  }

  const actionArgs = { ...parameters, account: parseAccount(account) as SmartAccount };

  const uninstallations: readonly Call[] = parameters.modules.map(({ type, address, deInitData }) => ({
    to: account.address,
    value: 0n,
    data: encodeFunctionData({
      abi: IERC7579ModuleConfigABI,
      functionName: 'uninstallModule',
      args: [parseModuleTypeId(type), address, deInitData ?? ('0x' as `0x${string}`)],
    }),
  }));

  if ('calls' in actionArgs) {
    actionArgs.calls = [
      {
        to: account.address,
        value: 0n,
        data: encodeCalls(uninstallations.concat(actionArgs.calls ?? []), { execType: parameters.execType }),
      },
    ];
  } else {
    actionArgs.callData = encodeCalls(
      uninstallations.concat([{ to: account.address, value: 0n, data: actionArgs.callData }]),
      {
        execType: parameters.execType,
      },
    );
  }

  return getAction(
    client,
    sendUserOperation,
    'sendUserOperation',
  )(actionArgs as SendUserOperationParameters<TSmartAccount, TSmartAccount, readonly Call[]>);
}

/**
 * Parameters required to execute calls on an ERC-7579 account.
 *
 * @property {ExecType} [execType] Optional execution type for the user operation
 */
type ExecuteParameters<TSmartAccount extends SmartAccount | undefined> = GetSmartAccountParameter<TSmartAccount> &
  SendUserOperationParameters<TSmartAccount, TSmartAccount, readonly Call[]> & {
    execType?: ExecType;
  };

/**
 * Executes calls on an ERC-7579 account via a user operation.
 *
 * @param {Client} client The viem client with optional smart account
 * @param {ExecuteParameters} parameters The parameters for executing calls
 * @returns {Promise<Hex>} The hash of the user operation
 */
async function execute<TSmartAccount extends SmartAccount | undefined>(
  client: Client<Transport, Chain | undefined, TSmartAccount>,
  parameters: ExecuteParameters<TSmartAccount>,
): Promise<Hex> {
  const account = await hoistAccount(client, parameters);
  const { execType } = parameters;

  const actionArgs = { ...parameters, account: parseAccount(account) as SmartAccount };

  if ('calls' in actionArgs) {
    actionArgs.calls = [
      {
        to: account.address,
        value: 0n,
        data: encodeCalls(actionArgs.calls ?? [], { execType }),
      },
    ];
  } else {
    actionArgs.callData = encodeCalls([{ to: account.address, value: 0n, data: actionArgs.callData }], { execType });
  }

  return getAction(
    client,
    sendUserOperation,
    'sendUserOperation',
  )(actionArgs as SendUserOperationParameters<TSmartAccount, TSmartAccount, readonly Call[]>);
}

/**
 * ERC-7579 actions interface for smart account operations.
 *
 * @property {function} accountId Retrieves the account ID for an ERC-7579 account
 * @property {function} installModules Installs one or more modules on an ERC-7579 account
 * @property {function} isModuleInstalled Checks if a module is installed on an ERC-7579 account
 * @property {function} supportsExecutionMode Checks if an ERC-7579 account supports a specific execution mode
 * @property {function} supportsModule Checks if an ERC-7579 account supports a specific module type
 * @property {function} uninstallModules Uninstalls one or more modules from an ERC-7579 account
 * @property {function} execute Executes calls on an ERC-7579 account
 */
export type ERC7579Actions<TSmartAccount extends SmartAccount | undefined> = {
  accountId: (parameters?: GetSmartAccountParameter<TSmartAccount>) => Promise<string>;
  installModules: (parameters: InstallModulesParameters<TSmartAccount>) => Promise<Hash>;
  isModuleInstalled: (parameters: IsModuleInstalledParameters<TSmartAccount>) => Promise<boolean>;
  supportsExecutionMode: (parameters: SupportsExecutionModeParameters<TSmartAccount>) => Promise<boolean>;
  supportsModule: (parameters: SupportsModuleParameters<TSmartAccount>) => Promise<boolean>;
  uninstallModules: (parameters: UninstallModulesParameters<TSmartAccount>) => Promise<Hash>;
  execute: (parameters: ExecuteParameters<TSmartAccount>) => Promise<Hash>;
};

/**
 * Creates an ERC-7579 actions object for a given client.
 * This function returns a factory that creates action methods bound to the client.
 *
 * @returns {function} A factory function that takes a client and returns ERC-7579 actions
 */
function erc7579Actions() {
  return <TSmartAccount extends SmartAccount | undefined>(
    client: Client<Transport, Chain | undefined, TSmartAccount>,
  ): ERC7579Actions<TSmartAccount> => ({
    accountId: args => accountId(client, args),
    installModules: args => installModules(client, args),
    isModuleInstalled: args => isModuleInstalled(client, args),
    supportsExecutionMode: args => supportsExecutionMode(client, args),
    supportsModule: args => supportsModule(client, args),
    uninstallModules: args => uninstallModules(client, args),
    execute: args => execute(client, args),
  });
}

export {
  InstallModulesParameters,
  IsModuleInstalledParameters,
  CallType,
  SupportsExecutionModeParameters,
  SupportsModuleParameters,
  UninstallModulesParameters,
  ExecuteParameters,
  erc7579Actions,
  accountId,
  installModules,
  isModuleInstalled,
  supportsExecutionMode,
  supportsModule,
  uninstallModules,
  execute,
};
