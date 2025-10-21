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

type EncodeMode = {
  callType?: Hex;
  execType?: Hex;
  selector?: Hex;
  payload?: Hex;
};

type Execution = {
  target: Address;
  value: bigint;
  callData: Hex;
};

const encodeMode = ({
  callType = CALL_TYPE_CALL,
  execType = EXEC_TYPE_DEFAULT,
  selector = '0x00000000',
  payload = '0x00000000000000000000000000000000000000000000',
}: EncodeMode = {}) =>
  encodePacked(
    ['bytes1', 'bytes1', 'bytes4', 'bytes4', 'bytes22'],
    [callType, execType, '0x00000000', selector, payload],
  );

const decodeMode = (mode: Hex): Required<EncodeMode> => ({
  callType: slice(mode, 0, 1),
  execType: slice(mode, 1, 2),
  selector: slice(mode, 6, 10),
  payload: slice(mode, 10, 32),
});

const encodeSingle = (target: Address, value = 0n, data: Hex = '0x') =>
  encodePacked(['address', 'uint256', 'bytes'], [target, value, data]);

const decodeSingle = (data: Hex): Execution => ({
  target: slice(data, 0, 20),
  value: hexToBigInt(slice(data, 20, 52), { size: 32 }),
  callData: size(data) > 52 ? slice(data, 52) : '0x',
});

const encodeBatch = (...entries: Execution[]) =>
  encodeAbiParameters(parseAbiParameters('(address,uint256,bytes)[]'), [
    entries.map<[Address, bigint, Hex]>(e => [e.target, e.value, e.callData]),
  ]);

const decodeBatch = (data: Hex) =>
  decodeAbiParameters(parseAbiParameters('(address,uint256,bytes)[]'), data)[0].map<Execution>(
    ([target, value, callData]) => ({
      target,
      value,
      callData,
    }),
  );

const encodeDelegate = (target: Address, data: Hex = '0x') => encodePacked(['address', 'bytes'], [target, data]);

const decodeDelegate = (data: Hex): Execution => ({
  target: slice(data, 0, 20),
  callData: size(data) > 20 ? slice(data, 20) : '0x',
  value: 0n,
});

const encodeCalls = async (calls: readonly Call[]) => {
  const isBatch = calls.length > 1;
  return encodeFunctionData({
    abi: IERC7579ExecutionABI,
    functionName: 'execute',
    args: [
      encodeMode({
        callType: isBatch ? CALL_TYPE_BATCH : CALL_TYPE_CALL,
      }),
      isBatch
        ? encodeBatch(
            ...calls.map<Execution>(({ to, value, data }) => ({
              target: to,
              value: value ?? 0n,
              callData: data ?? '0x',
            })),
          )
        : encodeSingle(calls[0]!.to, calls[0]!.value, calls[0]!.data),
    ],
  });
};

const decodeCalls = async (data: Hex) => {
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
