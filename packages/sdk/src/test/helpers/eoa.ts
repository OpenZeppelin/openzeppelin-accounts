import {
  createWalletClient,
  parseEther,
  http,
  publicActions,
  type Chain,
  type Client,
  type LocalAccount,
  type PublicActions,
  type RpcSchema,
  type TestClient,
  type Transport,
  type WalletActions,
} from 'viem';
import { Account, generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const createAndFundEOA = async <
  transport extends Transport = Transport,
  chain extends Chain | undefined = Chain | undefined,
  account extends Account | undefined = Account | undefined,
  rpcSchema extends RpcSchema | undefined = undefined,
>(
  client: TestClient<'anvil', transport, chain, account, true, rpcSchema>,
  value: bigint = parseEther('100'),
): Promise<Client<Transport, Chain, LocalAccount, RpcSchema, PublicActions & WalletActions<Chain, LocalAccount>>> => {
  const eoa = createWalletClient({
    account: privateKeyToAccount(generatePrivateKey()),
    chain: foundry,
    transport: http(),
  }).extend(publicActions);
  await client.setBalance({ address: eoa.account.address, value });
  return eoa;
};

export { createAndFundEOA };
