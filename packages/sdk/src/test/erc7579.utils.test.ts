import { test, testProp, fc } from '@fast-check/ava';
import { Hex, zeroAddress, toHex, isAddressEqual } from 'viem';
import {
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
  CallType,
  ExecType,
  ModuleType,
  CallTypes,
  ExecutionTypes,
} from '../erc7579.utils.js';

function hexa(): fc.Arbitrary<string> {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map<string>(n => items[n]!);
}

const addressArbitrary = fc
  .string({ minLength: 20, maxLength: 20, unit: hexa() })
  .map(address => toHex(address, { size: 20 }));
const calldataArbitrary = fc.string({ minLength: 0, maxLength: 100, unit: hexa() }).map(calldata => toHex(calldata));
const valueArbitrary = fc.option(fc.bigInt({ min: 0n }), { nil: undefined }).map(val => val ?? 0n);
const executionArbitrary = fc.record({
  target: addressArbitrary,
  value: valueArbitrary,
  callData: calldataArbitrary,
});
const callTypeArbitrary = fc.constantFrom(CallTypes.CALL, CallTypes.BATCH, CallTypes.DELEGATE);
const execTypeArbitrary = fc.constantFrom(ExecutionTypes.DEFAULT, ExecutionTypes.TRY);

test('parseModuleTypeId handles string types correctly', t => {
  t.is(parseModuleTypeId('validator'), 1n);
  t.is(parseModuleTypeId('executor'), 2n);
  t.is(parseModuleTypeId('fallback'), 3n);
  t.is(parseModuleTypeId('hook'), 4n);
});

test('parseModuleTypeId handles numeric types correctly', t => {
  t.is(parseModuleTypeId(1), 1n);
  t.is(parseModuleTypeId(2), 2n);
  t.is(parseModuleTypeId(3), 3n);
  t.is(parseModuleTypeId(4), 4n);
});

test('parseModuleTypeId throws on invalid input', t => {
  t.throws(() => parseModuleTypeId('invalid' as ModuleType), { message: /Invalid module type/ });
  t.throws(() => parseModuleTypeId(5 as ModuleType), { message: /Invalid module type/ });
  t.throws(() => parseModuleTypeId(0 as ModuleType), { message: /Invalid module type/ });
});

test('parseCallType handles string types correctly', t => {
  t.is(parseCallType('call'), CallTypes.CALL);
  t.is(parseCallType('batchcall'), CallTypes.BATCH);
  t.is(parseCallType('delegatecall'), CallTypes.DELEGATE);
});

test('parseCallType handles hex types correctly', t => {
  t.is(parseCallType('0x00'), CallTypes.CALL);
  t.is(parseCallType('0x01'), CallTypes.BATCH);
  t.is(parseCallType('0xff'), CallTypes.DELEGATE);
  t.is(parseCallType('0xab' as CallType), '0xab');
});

test('parseCallType throws on invalid input', t => {
  t.throws(() => parseCallType('invalid' as CallType), { message: /Invalid call type/ });
  t.throws(() => parseCallType('nothex' as CallType), { message: /Invalid call type/ });
});

test('parseExecType handles string types correctly', t => {
  t.is(parseExecType('default'), ExecutionTypes.DEFAULT);
  t.is(parseExecType('try'), ExecutionTypes.TRY);
});

test('parseExecType handles hex types correctly', t => {
  t.is(parseExecType('0x00'), ExecutionTypes.DEFAULT);
  t.is(parseExecType('0x01'), ExecutionTypes.TRY);
  t.is(parseExecType('0xab' as ExecType), '0xab');
});

test('parseExecType throws on invalid input', t => {
  t.throws(() => parseExecType('invalid' as ExecType), { message: /Invalid exec type/ });
  t.throws(() => parseExecType('nothex' as ExecType), { message: /Invalid exec type/ });
});

testProp(
  'encodeMode and decodeMode are inverses',
  [
    fc.tuple(
      callTypeArbitrary,
      execTypeArbitrary,
      fc.string({ minLength: 8, maxLength: 8 }).map((h: string) => `0x${h}` as Hex),
      fc.string({ minLength: 44, maxLength: 44 }).map((h: string) => `0x${h}` as Hex),
    ),
  ],
  (t, [callType, execType, selector, payload]) => {
    const mode = encodeMode({ callType, execType, selector, payload });
    const decoded = decodeMode(mode);

    t.is(decoded.callType, callType);
    t.is(decoded.execType, execType);
    t.is(decoded.selector, selector);
    t.is(decoded.payload, payload);
  },
);

testProp(
  'encodeSingle and decodeSingle are inverses',
  [fc.tuple(addressArbitrary, valueArbitrary, calldataArbitrary)],
  (t, [target, value, callData]) => {
    const encoded = encodeSingle(target, value, callData);
    const decoded = decodeSingle(encoded);
    t.is(decoded.target, target);
    t.is(decoded.value, value);
    t.is(decoded.callData, callData);
  },
);

testProp(
  'encodeBatch and decodeBatch are inverses',
  [fc.array(executionArbitrary, { minLength: 1, maxLength: 5 })],
  (t, executions) => {
    const encoded = encodeBatch(...executions);
    const decoded = decodeBatch(encoded);

    t.is(decoded.length, executions.length);

    for (let i = 0; i < executions.length; i++) {
      t.true(isAddressEqual(decoded[i]!.target, executions[i]!.target));
      t.is(decoded[i]!.value, executions[i]!.value);
      t.is(decoded[i]!.callData, executions[i]!.callData ?? '0x');
    }
  },
);

testProp(
  'encodeDelegate and decodeDelegate are inverses',
  [fc.tuple(addressArbitrary, calldataArbitrary)],
  (t, [target, data]) => {
    const encoded = encodeDelegate(target, data);
    const decoded = decodeDelegate(encoded);

    t.is(decoded.target, target);
    t.is(decoded.callData, data ?? '0x');
    t.is(decoded.value, 0n);
  },
);

testProp(
  'encodeCalls and decodeCalls are inverses for single calls',
  [
    fc.record({
      to: addressArbitrary,
      value: valueArbitrary,
      data: calldataArbitrary,
    }),
  ],
  async (t, call) => {
    const encoded = await encodeCalls([call]);
    const decoded = await decodeCalls(encoded);

    t.is(decoded.length, 1);
    t.is(decoded[0]!.to, call.to);
    t.is(decoded[0]!.value, call.value);
    t.is(decoded[0]!.data, call.data ?? '0x');
  },
);

testProp(
  'encodeCalls and decodeCalls are inverses for batch calls',
  [
    fc.array(
      fc.record({
        to: addressArbitrary,
        value: valueArbitrary,
        data: calldataArbitrary,
      }),
      { minLength: 2, maxLength: 5 },
    ),
  ],
  async (t, calls) => {
    const encoded = await encodeCalls(calls);
    const decoded = await decodeCalls(encoded);

    t.is(decoded.length, calls.length);

    for (let i = 0; i < calls.length; i++) {
      t.true(isAddressEqual(decoded[i]!.to, calls[i]!.to));
      t.is(decoded[i]!.value, calls[i]!.value);
      t.is(decoded[i]!.data, calls[i]!.data ?? '0x');
    }
  },
);

test('encodeMode uses defaults correctly', t => {
  const mode = encodeMode();
  const decoded = decodeMode(mode);

  t.is(decoded.callType, CallTypes.CALL);
  t.is(decoded.execType, ExecutionTypes.DEFAULT);
  t.is(decoded.selector, '0x00000000');
});

test('decodeSingle handles minimal data correctly', t => {
  const target = zeroAddress;
  const encoded = encodeSingle(target);
  const decoded = decodeSingle(encoded);

  t.is(decoded.target, target);
  t.is(decoded.value, 0n);
  t.is(decoded.callData, '0x');
});

test('encodeBatch handles empty array', async t => {
  t.throws(() => encodeCalls([]), { message: /undefined/ });
});
