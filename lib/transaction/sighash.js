'use strict';

var buffer = require('buffer');

var Signature = require('../crypto/signature');
var Script = require('../script');
var Output = require('./output');
var BufferReader = require('../encoding/bufferreader');
var BufferWriter = require('../encoding/bufferwriter');
var BN = require('../crypto/bn');
var Hash = require('../crypto/hash');
var ECDSA = require('../crypto/ecdsa');
var Schnorr = require('../crypto/schnorr');
var $ = require('../util/preconditions');
var BufferUtil = require('../util/buffer');
var Interpreter = require('../script/interpreter');
var _ = require('lodash');
const JSUtil = require('../util/js');
const blake2b = require('blake2b-wasm');
//const Transaction = require('./transaction');
//const Input = require('./input');

var SIGHASH_SINGLE_BUG = '0000000000000000000000000000000000000000000000000000000000000001';
var BITS_64_ON = 'ffffffffffffffff';

// By default, we sign with sighash_forkid
var DEFAULT_SIGN_FLAGS = Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID;


const TransactionSigningHashKey  = Buffer.from("TransactionSigningHash");

const blake2b_256 = (buf, key)=>{
  return blake2b(32, key).update(buf).digest();
}

var sighashForForkId = function(transaction, sighashType, inputNumber, subscript, satoshisBN) {
	var input = transaction.inputs[inputNumber];
	$.checkArgument(
		satoshisBN instanceof BN,
		'For ForkId=0 signatures, satoshis or complete input must be provided'
	);

	function GetForkId() {
		return 0; // In the UAHF, a fork id of 0 is used (see [4] REQ-6-2 NOTE 4)
	};

	function GetPrevoutHash(tx) {
		var writer = new BufferWriter()

		_.each(tx.inputs, function(input) {
			writer.writeReverse(input.prevTxId);
			writer.writeUInt32LE(input.outputIndex);
		});

		var buf = writer.toBuffer();
		var ret = Hash.sha256sha256(buf);
		return ret;
	}

	function GetSequenceHash(tx) {
		var writer = new BufferWriter()

		_.each(tx.inputs, function(input) {
			writer.writeUInt32LE(input.sequenceNumber);
		});

		var buf = writer.toBuffer();
		var ret = Hash.sha256sha256(buf);
		return ret;
	}

	function GetOutputsHash(tx, n) {
		var writer = new BufferWriter()

		if (_.isUndefined(n)) {
			_.each(tx.outputs, function(output) {
				output.toBufferWriter(writer);
			});
		} else {
			tx.outputs[n].toBufferWriter(writer);
		}

		var buf = writer.toBuffer();
		var ret = Hash.sha256sha256(buf);
		return ret;
	}

	var hashPrevouts = BufferUtil.emptyBuffer(32);
	var hashSequence = BufferUtil.emptyBuffer(32);
	var hashOutputs = BufferUtil.emptyBuffer(32);

	if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
		hashPrevouts = GetPrevoutHash(transaction);
	}

	if (!(sighashType & Signature.SIGHASH_ANYONECANPAY) &&
		(sighashType & 31) != Signature.SIGHASH_SINGLE &&
		(sighashType & 31) != Signature.SIGHASH_NONE) {
		hashSequence = GetSequenceHash(transaction);
	}

	if ((sighashType & 31) != Signature.SIGHASH_SINGLE && (sighashType & 31) != Signature.SIGHASH_NONE) {
		hashOutputs = GetOutputsHash(transaction);
	} else if ((sighashType & 31) == Signature.SIGHASH_SINGLE && inputNumber < transaction.outputs.length) {
		hashOutputs = GetOutputsHash(transaction, inputNumber);
	}


	function getHash(w) {

		var buf = w.toBuffer();
		var ret = Hash.sha256sha256(buf);
		ret = new BufferReader(ret).readReverse();
		return ret;
	};



	var writer = new BufferWriter()

	// Version
	writer.writeInt32LE(transaction.version);

	// Input prevouts/nSequence (none/all, depending on flags)
	writer.write(hashPrevouts);
	writer.write(hashSequence);

	//  outpoint (32-byte hash + 4-byte little endian)
	writer.writeReverse(input.prevTxId);
	writer.writeUInt32LE(input.outputIndex);

	// scriptCode of the input (serialized as scripts inside CTxOuts)
	writer.writeVarintNum(subscript.toBuffer().length)
	writer.write(subscript.toBuffer());

	// value of the output spent by this input (8-byte little endian)
	writer.writeUInt64LEBN(satoshisBN);

	// nSequence of the input (4-byte little endian) 
	var sequenceNumber = input.sequenceNumber;
	writer.writeUInt32LE(sequenceNumber);

	// Outputs (none/one/all, depending on flags)
	writer.write(hashOutputs);

	// Locktime
	writer.writeUInt32LE(transaction.nLockTime);

	// sighashType 
	writer.writeUInt32LE(sighashType >>> 0);

	var buf = writer.toBuffer();
	var ret = Hash.sha256sha256(buf);
	ret = new BufferReader(ret).readReverse();
	return ret;
}

/**
 * Returns a buffer of length 32 bytes with the hash that needs to be signed
 * for OP_CHECKSIG.
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Script} subscript the script that will be signed
 * @param {satoshisBN} input's amount (for  ForkId signatures)
 *
 */
var sighash = function sighash(transaction, sighashType, inputNumber, subscript, satoshisBN, flags) {
	//let ts0 = Date.now();
	var Transaction = require('./transaction');
	var Input = require('./input');
	

	if (_.isUndefined(flags)) {
		flags = DEFAULT_SIGN_FLAGS;
	}

	// Copy transaction
	//var txcopy = Transaction.shallowCopy(transaction);
	if(!transaction.___buffer){
		transaction.___buffer = transaction.toBuffer()
		transaction.___inputs = transaction.inputs.map(input=>{
			let params = {
				prevTxId: input.prevTxId,
				outputIndex: input.outputIndex,
				sequenceNumber: input.sequenceNumber,
				version: input.version
			}
			let inputCopy = new Input({...params, script:Script.empty()})

			inputCopy.___params = params;

			let bufferWriter = inputCopy.toBufferWriter();
			let buffer = bufferWriter.toBuffer();
			inputCopy.toBufferWriter = (writer)=>{
				if(!writer)
					return bufferWriter;
				writer.write(buffer);
				return writer;
			}

			return inputCopy;
		})
		let txCache = new Transaction(Buffer.from(transaction.___buffer));
		txCache.inputs = [];
		transaction.___buffer = txCache.toBuffer();
	}
	let txcopy = new Transaction(Buffer.from(transaction.___buffer));
	//let ts1 = Date.now()
	//console.log("#### shallowCopy", ts1-ts0)
	// Copy script
	subscript = new Script(subscript);
	//let ts2 = Date.now()
	//console.log("#### subscript", ts2-ts1)

	if (flags & Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION) {
		// Legacy chain's value for fork id must be of the form 0xffxxxx.
		// By xoring with 0xdead, we ensure that the value will be different
		// from the original one, even if it already starts with 0xff.
		var forkValue = sighashType >> 8;
		var newForkValue = 0xff0000 | (forkValue ^ 0xdead);
		sighashType = (newForkValue << 8) | (sighashType & 0xff)
	}

	if ((sighashType & Signature.SIGHASH_FORKID) && (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)) {
		return sighashForForkId(txcopy, sighashType, inputNumber, subscript, satoshisBN);
	}

	// For no ForkId sighash, separators need to be removed.
	subscript.removeCodeseparators();
	//let ts3 = Date.now()
	//console.log("#### removeCodeseparators", ts3-ts2)
	var i;

	///*
	//for (i = 0; i < txcopy.inputs.length; i++) {
		// Blank signatures for other inputs
		txcopy.inputs = transaction.___inputs.slice(0);
	//}
	/* 
	txcopy.inputs.map((input, index)=>{
		if(inputNumber == index)
			return
		input.clearSignatures()
	})
	//*/
	//let ts4 = Date.now()
	//console.log("#### txcopy.inputs", ts4-ts3)
	txcopy.inputs[inputNumber] = new Input({...txcopy.inputs[inputNumber].___params, script:subscript});
	//let ts5 = Date.now()
	//console.log("#### txcopy.inputs2", ts5-ts4)
	if ((sighashType & 31) === Signature.SIGHASH_NONE ||
		(sighashType & 31) === Signature.SIGHASH_SINGLE) {

		// clear all sequenceNumbers
		for (i = 0; i < txcopy.inputs.length; i++) {
			if (i !== inputNumber) {
				txcopy.inputs[i].sequenceNumber = 0;
			}
		}
	}

	if ((sighashType & 31) === Signature.SIGHASH_NONE) {
		txcopy.outputs = [];

	} else if ((sighashType & 31) === Signature.SIGHASH_SINGLE) {
		// The SIGHASH_SINGLE bug.
		// https://bitcointalk.org/index.php?topic=260595.0
		if (inputNumber >= txcopy.outputs.length) {
			return Buffer.from(SIGHASH_SINGLE_BUG, 'hex');
		}

		txcopy.outputs.length = inputNumber + 1;

		for (i = 0; i < inputNumber; i++) {
			txcopy.outputs[i] = new Output({
				satoshis: BN.fromBuffer(Buffer.from(BITS_64_ON, 'hex')),
				script: Script.empty()
			});
		}
	}

	if (sighashType & Signature.SIGHASH_ANYONECANPAY) {
		txcopy.inputs = [txcopy.inputs[inputNumber]];
	}
	//let ts6 = Date.now()
	//console.log("#### before BufferWriter", ts6-ts5)
	//JSUtil.LogBufferActive = true;
	let buf = new BufferWriter()
		.write(txcopy.toBuffer())
		.writeInt32LE(sighashType)
		.toBuffer()
	//let ts7 = Date.now()
	//console.log("#### after BufferWriter", inputNumber, ts7-ts6, ts7-ts0)
	let ret = blake2b_256(buf, TransactionSigningHashKey);
	//JSUtil.LogBufferActive = false;
	//let ts8 = Date.now()
	//console.log("#### after blake2b_256", ts8-ts7)
	return Buffer.from(ret);
}


var sighash2 = function sighash(transaction, sighashType, inputNumber, subscript, satoshisBN, flags) {

	if (_.isUndefined(flags)) {
		flags = DEFAULT_SIGN_FLAGS;
	}

	// Copy transaction
	var txcopy = transaction;//Transaction.shallowCopy(transaction);
	const inputs = transaction.inputs;
	const outputs = transaction.outputs;
	txcopy.inputs = [];

	// Copy script
	subscript = new Script(subscript);

	if (flags & Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION) {
		// Legacy chain's value for fork id must be of the form 0xffxxxx.
		// By xoring with 0xdead, we ensure that the value will be different
		// from the original one, even if it already starts with 0xff.
		var forkValue = sighashType >> 8;
		var newForkValue = 0xff0000 | (forkValue ^ 0xdead);
		sighashType = (newForkValue << 8) | (sighashType & 0xff)
	}

	if ((sighashType & Signature.SIGHASH_FORKID) && (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)) {
		return sighashForForkId(txcopy, sighashType, inputNumber, subscript, satoshisBN);
	}

	// For no ForkId sighash, separators need to be removed.
	subscript.removeCodeseparators();

	var i;

	for (i = 0; i < inputs.length; i++) {
		// Blank signatures for other inputs
		txcopy.inputs[i] = new Input(inputs[i]).setScript(Script.empty());
	}

	txcopy.inputs[inputNumber] = new Input(inputs[inputNumber]).setScript(subscript);

	if ((sighashType & 31) === Signature.SIGHASH_NONE ||
		(sighashType & 31) === Signature.SIGHASH_SINGLE) {

		// clear all sequenceNumbers
		for (i = 0; i < txcopy.inputs.length; i++) {
			if (i !== inputNumber) {
				txcopy.inputs[i].sequenceNumber = 0;
			}
		}
	}

	if ((sighashType & 31) === Signature.SIGHASH_NONE) {
		txcopy.outputs = [];

	} else if ((sighashType & 31) === Signature.SIGHASH_SINGLE) {
		// The SIGHASH_SINGLE bug.
		// https://bitcointalk.org/index.php?topic=260595.0
		if (inputNumber >= txcopy.outputs.length) {
			return Buffer.from(SIGHASH_SINGLE_BUG, 'hex');
		}

		//txcopy.outputs.length = inputNumber + 1;
		txcopy.outputs = [];

		for (i = 0; i < inputNumber; i++) {
			txcopy.outputs[i] = new Output({
				satoshis: BN.fromBuffer(Buffer.from(BITS_64_ON, 'hex')),
				script: Script.empty()
			});
		}
	}

	if (sighashType & Signature.SIGHASH_ANYONECANPAY) {
		txcopy.inputs = [txcopy.inputs[inputNumber]];
	}

	JSUtil.LogBufferActive = true;
	let buf = new BufferWriter()
		.write(txcopy.toBuffer())
		.writeInt32LE(sighashType)
		.toBuffer()
	let ret = blake2b_256(buf, TransactionSigningHashKey);
	JSUtil.LogBufferActive = false;
	transaction.inputs = inputs;
	transaction.outputs = outputs;
	return Buffer.from(ret);
}


/**
 * Create a signature
 *
 * @name Signing.sign
 * @param {Transaction} transaction
 * @param {PrivateKey} privateKey
 * @param {number} sighash
 * @param {number} inputIndex
 * @param {Script} subscript
 * @param {satoshisBN} input's amount
 * @param {signingMethod} signingMethod "ecdsa" or "schnorr" to sign a tx
 * @return {Signature}
 */
function sign(transaction, privateKey, sighashType, inputIndex, subscript, satoshisBN, flags, signingMethod) {
	//let ts0 = Date.now();
	var hashbuf = sighash(transaction, sighashType, inputIndex, subscript, satoshisBN, flags);
	//let ts1 = Date.now();
	//console.log("#### sighash.sign", "inputIndex:", inputIndex, "sighash time:", ts1-ts0)
	signingMethod = signingMethod || "ecdsa";
	let sig;

	if (signingMethod === "schnorr") {
		sig = Schnorr.sign(hashbuf, privateKey, 'little').set({
			nhashtype: sighashType
		});
		return sig;
	} else if (signingMethod === "ecdsa") {
		sig = ECDSA.sign(hashbuf, privateKey, 'little').set({
			nhashtype: sighashType
		});
		return sig;
	}
}

/**
 * Verify a signature
 *
 * @name Signing.verify
 * @param {Transaction} transaction
 * @param {Signature} signature
 * @param {PublicKey} publicKey
 * @param {number} inputIndex
 * @param {Script} subscript
 * @param {satoshisBN} input's amount
 * @param {flags} verification flags
 * @param {signingMethod} signingMethod "ecdsa" or "schnorr" to sign a tx
 * @return {boolean}
 */
function verify(transaction, signature, publicKey, inputIndex, subscript, satoshisBN, flags, signingMethod) {
	$.checkArgument(!_.isUndefined(transaction));
	$.checkArgument(!_.isUndefined(signature) && !_.isUndefined(signature.nhashtype));
	var hashbuf = sighash(transaction, signature.nhashtype, inputIndex, subscript, satoshisBN, flags);

	signingMethod = signingMethod || "ecdsa";

	if (signingMethod === "schnorr") {
		return Schnorr.verify(hashbuf, signature, publicKey, 'little')
	} else if (signingMethod === "ecdsa") {
		return ECDSA.verify(hashbuf, signature, publicKey, 'little');
	}
}

/**
 * @namespace Signing
 */
module.exports = {
	sighash: sighash,
	sign: sign,
	verify: verify
};