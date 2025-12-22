import {
  Address,
  Call,
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  Hex,
  hexToBigInt,
  parseAbiParameters,
  size,
  slice,
} from 'viem';
import { IERC7579ExecutionABI } from './erc7579.abi.js';

const MODULE_TYPE_VALIDATOR = 1;
const MODULE_TYPE_EXECUTOR = 2;
const MODULE_TYPE_FALLBACK = 3;
const MODULE_TYPE_HOOK = 4;

const EXEC_TYPE_DEFAULT = '0x00';
const EXEC_TYPE_TRY = '0x01';

const CALL_TYPE_CALL = '0x00';
const CALL_TYPE_BATCH = '0x01';
const CALL_TYPE_DELEGATE = '0xff';

/**
 * Module type identifier for ERC-7579 modules.
 * Can be specified as a number (1-4) or a string ('validator', 'executor', 'fallback', 'hook').
 */
type ModuleType = 1 | 2 | 3 | 4 | 'validator' | 'executor' | 'fallback' | 'hook';

/**
 * Call type for ERC-7579 execution modes.
 * Can be specified as a hex string ('0x00', '0x01', '0xff') or a string ('call', 'batchcall', 'delegatecall').
 */
type CallType = '0x00' | '0x01' | '0xff' | 'call' | 'batchcall' | 'delegatecall';

/**
 * Execution type for ERC-7579 execution modes.
 * Can be specified as a hex string ('0x00', '0x01') or a string ('default', 'try').
 */
type ExecType = '0x00' | '0x01' | 'default' | 'try';

/**
 * Parameters for encoding execution mode.
 *
 * @property {CallType} [callType] The call type to use for execution
 * @property {ExecType} [execType] The execution type to use
 * @property {Hex} [selector] The function selector (4 bytes)
 * @property {Hex} [payload] The payload data (22 bytes)
 */
type EncodeMode = {
  callType?: CallType;
  execType?: ExecType;
  selector?: Hex;
  payload?: Hex;
};

/**
 * Execution call parameters.
 *
 * @property {Address} target The target address for the call
 * @property {bigint} value The value to send with the call
 * @property {Hex} callData The call data to execute
 */
type Execution = {
  target: Address;
  value: bigint;
  callData: Hex;
};

/**
 * Parses a module type identifier to its numeric representation.
 *
 * @param {ModuleType} type The module type to parse
 * @returns {bigint} The numeric module type identifier
 * @throws {Error} If the module type is invalid
 */
const parseModuleTypeId = (type: ModuleType): bigint => {
  switch (type) {
    case 'validator':
      return BigInt(1);
    case 'executor':
      return BigInt(2);
    case 'fallback':
      return BigInt(3);
    case 'hook':
      return BigInt(4);
    default:
      if (typeof type === 'number' && type >= 1 && type <= 4) {
        return BigInt(type);
      }
      throw new Error('Invalid module type');
  }
};

/**
 * Parses a call type to its hex representation.
 *
 * @param {CallType} type The call type to parse
 * @returns {Hex} The hex representation of the call type
 * @throws {Error} If the call type is invalid
 */
const parseCallType = (type: CallType): Hex => {
  switch (type) {
    case 'call':
      return CALL_TYPE_CALL;
    case 'batchcall':
      return CALL_TYPE_BATCH;
    case 'delegatecall':
      return CALL_TYPE_DELEGATE;
    default:
      if (type.startsWith('0x')) {
        return type;
      }
      throw new Error('Invalid call type');
  }
};

/**
 * Parses an execution type to its hex representation.
 *
 * @param {ExecType} type The execution type to parse
 * @returns {Hex} The hex representation of the execution type
 * @throws {Error} If the execution type is invalid
 */
const parseExecType = (type: ExecType): Hex => {
  switch (type) {
    case 'default':
      return EXEC_TYPE_DEFAULT;
    case 'try':
      return EXEC_TYPE_TRY;
    default:
      if (type.startsWith('0x')) {
        return type;
      }
      throw new Error('Invalid exec type');
  }
};

/**
 * Encodes execution mode parameters into a packed hex string.
 *
 * @param {EncodeMode} [parameters] The execution mode parameters to encode
 * @param {CallType} [parameters.callType] The call type (default: CALL_TYPE_CALL)
 * @param {ExecType} [parameters.execType] The execution type (default: EXEC_TYPE_DEFAULT)
 * @param {Hex} [parameters.selector] The function selector (default: '0x00000000')
 * @param {Hex} [parameters.payload] The payload data (default: '0x00000000000000000000000000000000000000000000')
 * @returns {Hex} The encoded execution mode as a packed hex string
 */
const encodeMode = ({
  callType = CALL_TYPE_CALL,
  execType = EXEC_TYPE_DEFAULT,
  selector = '0x00000000',
  payload = '0x00000000000000000000000000000000000000000000',
}: EncodeMode = {}) =>
  encodePacked(
    ['bytes1', 'bytes1', 'bytes4', 'bytes4', 'bytes22'],
    [parseCallType(callType), parseExecType(execType), '0x00000000', selector, payload],
  );

/**
 * Decodes a packed hex string into execution mode parameters.
 *
 * @param {Hex} mode The packed hex string to decode
 * @returns {Required<EncodeMode>} The decoded execution mode parameters
 */
const decodeMode = (mode: Hex): Required<EncodeMode> => ({
  callType: slice(mode, 0, 1) as CallType,
  execType: slice(mode, 1, 2) as ExecType,
  selector: slice(mode, 6, 10),
  payload: slice(mode, 10, 32),
});

/**
 * Encodes a single execution call into a packed hex string.
 *
 * @param {Address} target The target address for the call
 * @param {bigint} [value] The value to send with the call (default: 0n)
 * @param {Hex} [data] The call data to execute (default: '0x')
 * @returns {Hex} The encoded execution call as a packed hex string
 */
const encodeSingle = (target: Address, value = 0n, data: Hex = '0x'): Hex =>
  encodePacked(['address', 'uint256', 'bytes'], [target, value, data]);

/**
 * Decodes a packed hex string into a single execution call.
 *
 * @param {Hex} data The packed hex string to decode
 * @returns {Execution} The decoded execution call
 */
const decodeSingle = (data: Hex): Execution => ({
  target: slice(data, 0, 20),
  value: hexToBigInt(slice(data, 20, 52), { size: 32 }),
  callData: size(data) > 52 ? slice(data, 52) : '0x',
});

/**
 * Encodes multiple execution calls into an ABI-encoded array.
 *
 * @param {...Execution[]} entries The execution calls to encode
 * @returns {Hex} The ABI-encoded array of execution calls
 */
const encodeBatch = (...entries: Execution[]): Hex =>
  encodeAbiParameters(parseAbiParameters('(address,uint256,bytes)[]'), [
    entries.map<[Address, bigint, Hex]>(e => [e.target, e.value, e.callData]),
  ]);

/**
 * Decodes an ABI-encoded array into multiple execution calls.
 *
 * @param {Hex} data The ABI-encoded array to decode
 * @returns {Execution[]} The decoded array of execution calls
 */
const decodeBatch = (data: Hex): Execution[] =>
  decodeAbiParameters(parseAbiParameters('(address,uint256,bytes)[]'), data)[0].map<Execution>(
    ([target, value, callData]) => ({
      target,
      value,
      callData,
    }),
  );

/**
 * Encodes a delegatecall execution into a packed hex string.
 *
 * @param {Address} target The target address for the delegatecall
 * @param {Hex} [data] The call data to execute (default: '0x')
 * @returns {Hex} The encoded delegatecall as a packed hex string
 */
const encodeDelegate = (target: Address, data: Hex = '0x'): Hex => encodePacked(['address', 'bytes'], [target, data]);

/**
 * Decodes a packed hex string into a delegatecall execution.
 *
 * @param {Hex} data The packed hex string to decode
 * @returns {Execution} The decoded delegatecall execution (value is always 0n)
 */
const decodeDelegate = (data: Hex): Execution => ({
  target: slice(data, 0, 20),
  callData: size(data) > 20 ? slice(data, 20) : '0x',
  value: 0n,
});

/**
 * Encodes an array of calls into ERC-7579 execute function data.
 * Automatically selects single call, batch call, or delegatecall encoding based on the number of calls.
 *
 * @param {readonly Call[]} calls The calls to encode
 * @param {object} [options] Encoding options
 * @param {ExecType} [options.execType] The execution type to use
 * @param {object} [options] Additional options passed to encodeFunctionData
 * @returns {Hex} The encoded function data for the execute function
 */
const encodeCalls = (
  calls: readonly Call[],
  { execType, ...args }: { execType?: ExecType } & Partial<Parameters<typeof encodeFunctionData>[0]> = {
    abi: IERC7579ExecutionABI,
    functionName: 'execute',
  },
): Hex => {
  const isBatch = calls.length > 1;
  return encodeFunctionData({
    ...args,
    abi: IERC7579ExecutionABI,
    functionName: 'execute',
    args: [
      encodeMode({
        callType: isBatch ? CALL_TYPE_BATCH : CALL_TYPE_CALL,
        execType,
      }),
      isBatch
        ? encodeBatch(
            ...calls.map(({ to, value, data }) => ({
              target: to,
              value: value ?? 0n,
              callData: data ?? '0x',
            })),
          )
        : encodeSingle(calls[0]!.to, calls[0]!.value, calls[0]!.data),
    ],
  });
};

/**
 * Decodes ERC-7579 execute function data into an array of calls.
 * Supports single call, batch call, and delegatecall decoding.
 *
 * @param {Hex} data The function data to decode
 * @returns {Promise<Call[]>} The decoded array of calls
 * @throws {Error} If the call type is unrecognized
 */
const decodeCalls = async (data: Hex): Promise<Call[]> => {
  const { args } = decodeFunctionData({
    abi: IERC7579ExecutionABI,
    data,
  });
  const [mode, executionCalldata] = args;
  let batch: Execution | Execution[];
  switch (decodeMode(mode).callType) {
    case CALL_TYPE_DELEGATE: {
      batch = decodeDelegate(executionCalldata);
      break;
    }
    case CALL_TYPE_BATCH: {
      batch = decodeBatch(executionCalldata);
      break;
    }
    case CALL_TYPE_CALL: {
      batch = decodeSingle(executionCalldata);
      break;
    }
    default:
      throw new Error('Unrecognized call type');
  }
  return (Array.isArray(batch) ? batch : [batch]).map(({ target, value, callData }) => ({
    to: target,
    value,
    data: callData,
  }));
};

export {
  ModuleType,
  CallType,
  ExecType,
  EncodeMode,
  Execution,
  MODULE_TYPE_VALIDATOR,
  MODULE_TYPE_EXECUTOR,
  MODULE_TYPE_FALLBACK,
  MODULE_TYPE_HOOK,
  EXEC_TYPE_DEFAULT,
  EXEC_TYPE_TRY,
  CALL_TYPE_CALL,
  CALL_TYPE_BATCH,
  CALL_TYPE_DELEGATE,
  parseModuleTypeId,
  parseCallType,
  parseExecType,
  encodeMode,
  decodeMode,
  encodeSingle,
  decodeSingle,
  encodeBatch,
  decodeBatch,
  encodeDelegate,
  decodeDelegate,
  encodeCalls,
  decodeCalls,
};
