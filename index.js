'use strict';


const secp256k1 = require('secp256k1-wasm');
const blake2b = require('blake2b-wasm');

var kaspacore = module.exports;

kaspacore.secp256k1 = secp256k1;

// module information
kaspacore.version = 'v' + require('./package.json').version;
kaspacore.versionGuard = function(version) {
	if (version !== undefined) {
		var message = 'More than one instance of kaspacore-lib found. ' +
			'Please make sure to require kaspacore-lib and check that submodules do' +
			' not also include their own kaspacore-lib dependency.';
		throw new Error(message);
	}
};
global._kaspacoreLibVersion = kaspacore.version;


const wasmModulesLoadStatus = new Map();
kaspacore.wasmModulesLoadStatus = wasmModulesLoadStatus;
wasmModulesLoadStatus.set("blake2b", false);
wasmModulesLoadStatus.set("secp256k1", false);

const setWasmLoadStatus = (mod, loaded) => {
	//console.log("setWasmLoadStatus:", mod, loaded)
	wasmModulesLoadStatus.set(mod, loaded);
	let allLoaded = true;
	wasmModulesLoadStatus.forEach((loaded, mod) => {
		//console.log("wasmModulesLoadStatus:", mod, loaded)
		if (!loaded)
			allLoaded = false;
	})

	if (allLoaded)
		kaspacore.ready();
}


blake2b.ready(() => {
	setWasmLoadStatus("blake2b", true);
})

secp256k1.onRuntimeInitialized = () => {
	//console.log("onRuntimeInitialized")
	setTimeout(() => {
		setWasmLoadStatus("secp256k1", true);
	}, 1);
}

secp256k1.onAbort = (error) => {
	console.log("secp256k1:onAbort:", error)
}
const deferred = ()=>{
	let methods = {};
	let promise = new Promise((resolve, reject)=>{
		methods = {resolve, reject};
	})
	Object.assign(promise, methods);
	return promise;
}
const readySignal = deferred();

kaspacore.ready = ()=>{
	readySignal.resolve(true);
}
kaspacore.initRuntime = ()=>{
	return readySignal;
}


// crypto
kaspacore.crypto = {};
kaspacore.crypto.BN = require('./lib/crypto/bn');
kaspacore.crypto.ECDSA = require('./lib/crypto/ecdsa');
kaspacore.crypto.Schnorr = require('./lib/crypto/schnorr');
kaspacore.crypto.Hash = require('./lib/crypto/hash');
kaspacore.crypto.Random = require('./lib/crypto/random');
kaspacore.crypto.Point = require('./lib/crypto/point');
kaspacore.crypto.Signature = require('./lib/crypto/signature');

// encoding
kaspacore.encoding = {};
kaspacore.encoding.Base58 = require('./lib/encoding/base58');
kaspacore.encoding.Base58Check = require('./lib/encoding/base58check');
kaspacore.encoding.BufferReader = require('./lib/encoding/bufferreader');
kaspacore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
kaspacore.encoding.Varint = require('./lib/encoding/varint');

// utilities
kaspacore.util = {};
kaspacore.util.buffer = require('./lib/util/buffer');
kaspacore.util.js = require('./lib/util/js');
kaspacore.util.preconditions = require('./lib/util/preconditions');
kaspacore.util.base32 = require('./lib/util/base32');
kaspacore.util.convertBits = require('./lib/util/convertBits');
kaspacore.setDebugLevel = (level)=>{
	kaspacore.util.js.debugLevel = level;
}

// errors thrown by the library
kaspacore.errors = require('./lib/errors');

// main bitcoin library
kaspacore.Address = require('./lib/address');
kaspacore.Block = require('./lib/block');
kaspacore.MerkleBlock = require('./lib/block/merkleblock');
kaspacore.BlockHeader = require('./lib/block/blockheader');
kaspacore.HDPrivateKey = require('./lib/hdprivatekey.js');
kaspacore.HDPublicKey = require('./lib/hdpublickey.js');
kaspacore.Networks = require('./lib/networks');
kaspacore.Opcode = require('./lib/opcode');
kaspacore.PrivateKey = require('./lib/privatekey');
kaspacore.PublicKey = require('./lib/publickey');
kaspacore.Script = require('./lib/script');
kaspacore.Transaction = require('./lib/transaction');
kaspacore.URI = require('./lib/uri');
kaspacore.Unit = require('./lib/unit');

// dependencies, subject to change
kaspacore.deps = {};
kaspacore.deps.bnjs = require('bn.js');
kaspacore.deps.bs58 = require('bs58');
kaspacore.deps.Buffer = Buffer;
kaspacore.deps.elliptic = require('elliptic');
kaspacore.deps._ = require('lodash');

// Internal usage, exposed for testing/advanced tweaking
kaspacore.Transaction.sighash = require('./lib/transaction/sighash');
