const { mapValues } = require('../../../../lib/@openzeppelin-contracts/test/helpers/iterate');

const formatType = schema => Object.entries(schema).map(([name, type]) => ({ name, type }));

module.exports = mapValues(
  {
    ScheduleRecover: {
      salt: 'bytes32',
      mode: 'bytes32',
      recoveryCalldata: 'bytes',
    },
    CancelRecover: {
      salt: 'bytes32',
      mode: 'bytes32',
      recoveryCalldata: 'bytes',
    },
    AllowHandle: {
      account: 'address',
      handle: 'bytes32',
      to: 'address',
    },
    AllowHandleTransient: {
      account: 'address',
      handle: 'bytes32',
      to: 'address',
    },
  },
  formatType,
);

module.exports.formatType = formatType;
