# State For The Stateless Implementation

## Requirements 

- This project relies on Intel SGX and bitcoin-cli. It been tested on Ubuntu 14.04.1 with SGX 1.8 and Bitcoin Core Daemon version v0.13.1.0-g03422e5. 

- Please note that this project assumes the SGX SDK is installed with the prefix /opt/intel/sgxsdk-1.8/.

## Build and Run

Default is to build and run on a local testnet with default wallet.  Make sure the local wallet has been initialized with getwalletinfo before running. 

```
  $ cd src
  $ make
  $ bitcoind -regtest -daemon
  $ bitcoin-cli getwalletinfo
  $ bitcoin-cli -regtest generate 101
  $ ./app-generic <transaction hash> [Optional: Tip Amound]
```

## Custom JS scripts

Scripts are assumed to be stored in script.js and be in the following format

```javascript
function nextStep(prevState, stepInput, randomCoins) {
  // Do your functionality here
  return StateToBeEncrypted + '@' + StepOutput + '@' + PublicOutput;
}
```

The '@' symbols are used as delineators to seperate the three function outputs.  The random coins input is a hex string of length 32.  If you need more randomness than this, it can be used to seed a PRNG.

Note that SGX doesn't have direct access to trusted time and calling for javascript randomness is not hooked into the sgx_read_rand functionality, so calling these functions from javascript will cause failures.

## Related Links 

- Please see [the paper](https://eprint.iacr.org/2017/201) and the [related paper](https://eprint.iacr.org/2017/1091) for more information about the cryptographic protocol and related proofs. 
- Please see [Obscuro Project](https://github.com/BitObscuro/Obscuro) for how bitcoin has been integrated into SGX
- Please see [Luckychain Project](https://github.com/luckychain) for an integration of duktape into SGX

## Contact

Please remember this is a research implementation and should not be used for deploying real systems.  For questions, please contact gkaptchuk (at) jhu (dot) edu.

