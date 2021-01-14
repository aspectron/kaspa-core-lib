# Kaspacore Lib

**JavaScript Kaspa library.**

*IMPORTANT: THIS LIBRARY IS WORK IN PROGRESS, THIS IS NOT PRODUCTION READY*

## Based on Bitcore by BitPay

Based on the popular Bitcore library developed by BitPay, Kaspacore library provides primitives for interfacing with Kaspa network.

## Get Started

```sh
git clone git@github.com:aspectron/kaspacore-lib
```

Adding Kaspacore to your app's `package.json`:

```json
"dependencies": {
    "aspectron/kaspacore-lib": "*",
    ...
}
```

## Documentation

The complete docs are hosted here: [bitcore documentation](https://github.com/bitpay/bitcore). There's also a [bitcore API reference](https://github.com/bitpay/bitcore/blob/master/packages/bitcore-node/docs/api-documentation.md) available generated from the JSDocs of the project, where you'll find low-level details on each bitcore utility.

## Examples

- [Generate a random address](docs/examples.md#generate-a-random-address)
- [Generate a address from a SHA256 hash](docs/examples.md#generate-a-address-from-a-sha256-hash)
- [Import an address via WIF](docs/examples.md#import-an-address-via-wif)
- [Create a Transaction](docs/examples.md#create-a-transaction)
- [Sign a Bitcoin message](docs/examples.md#sign-a-bitcoin-message)
- [Verify a Bitcoin message](docs/examples.md#verify-a-bitcoin-message)
- [Create an OP RETURN transaction](docs/examples.md#create-an-op-return-transaction)
- [Create a 2-of-3 multisig P2SH address](docs/examples.md#create-a-2-of-3-multisig-p2sh-address)
- [Spend from a 2-of-2 multisig P2SH address](docs/examples.md#spend-from-a-2-of-2-multisig-p2sh-address)

## Building the Browser Bundle

To build a kaspacore-lib full bundle for the browser:

```sh
gulp browser
```

This will generate files named `kaspacore-lib.js` and `kaspacore-lib.min.js`.

You can also use our pre-generated files, provided for each release along with a PGP signature by one of the project's maintainers. To get them, checkout the [releases](https://github.com/bitpay/bitcore/blob/master/packages/bitcore-lib/CHANGELOG.md).

## Development & Tests

```sh
git clone https://github.com/bitpay/kaspacore-lib
cd kaspacore-lib
npm install
```

Run all the tests:

```sh
gulp test
```

You can also run just the Node.js tests with `gulp test:node`, just the browser tests with `gulp test:browser`
or create a test coverage report (you can open `coverage/lcov-report/index.html` to visualize it) with `gulp coverage`.

## Security

We're using Kaspacore in production, as are many others, but please use common sense when doing anything related to finances! We take no responsibility for your implementation decisions.

If you find a security issue, please email security@bitpay.com.

## Contributing

See [CONTRIBUTING.md](https://github.com/bitpay/bitcore/blob/master/Contributing.md) on the main bitcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Bitcore - Copyright 2013-2019 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.
Kaspacore - Copyright 2020 ASPECTRON Inc.
