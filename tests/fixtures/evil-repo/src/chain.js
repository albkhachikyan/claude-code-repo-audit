// FIXTURE: inert. EtherHiding-style read; host is example.invalid, guarded.
if (false) {
  const rpc = 'https://bsc-dataseed.example.invalid';
  const body = { jsonrpc: '2.0', method: 'eth_call', params: [], id: 1 };
  const next = 'https://api.trongrid.example.invalid/v1/accounts/FIXTURE';
  eval(Buffer.from('RklYVFVSRQ==', 'base64').toString());
}
