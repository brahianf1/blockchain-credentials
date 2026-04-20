import json, os
import subprocess
subprocess.check_call(["pip", "install", "py-solc-x"])

from solcx import compile_standard, install_solc
install_solc('0.8.0')
contract_path = 'backend/contracts/CredentialRegistry.sol'
with open(contract_path, 'r') as f:
    source = f.read()

compiled = compile_standard({
    'language': 'Solidity',
    'sources': {'CredentialRegistry.sol': {'content': source}},
    'settings': {'outputSelection': {'*': {'*': ['abi', 'metadata', 'evm.bytecode']}}},
}, solc_version='0.8.0')

bytecode = compiled['contracts']['CredentialRegistry.sol']['CredentialRegistry']['evm']['bytecode']['object']
abi = compiled['contracts']['CredentialRegistry.sol']['CredentialRegistry']['abi']

with open('backend/contracts/CredentialRegistry.json', 'w') as f:
    json.dump({'abi': abi, 'bytecode': bytecode}, f, indent=2)

print('Compiled successfully!')
