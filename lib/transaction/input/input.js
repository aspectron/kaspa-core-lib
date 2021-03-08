'use strict';

var _ = require('lodash');
var $ = require('../../util/preconditions');
var errors = require('../../errors');
var BN = require('../../crypto/bn');
var BufferWriter = require('../../encoding/bufferwriter');
var BufferReader = require('../../encoding/bufferreader');
var buffer = require('buffer');
var BufferUtil = require('../../util/buffer');
var JSUtil = require('../../util/js');
const {LogBuffer} = JSUtil;
var Script = require('../../script');
var Sighash = require('../sighash');
var Output = require('../output');
var logLevels = require('../../util/log').logLevels;

var MAXINT = 0xffffffff; // Math.pow(2, 32) - 1;
var DEFAULT_RBF_SEQNUMBER = MAXINT - 2;
var DEFAULT_SEQNUMBER = MAXINT;
var DEFAULT_LOCKTIME_SEQNUMBER = MAXINT - 1;
const SEQUENCE_LOCKTIME_DISABLE_FLAG = Math.pow(2, 31); // (1 << 31);
const SEQUENCE_LOCKTIME_TYPE_FLAG = Math.pow(2, 22); // (1 << 22);
const SEQUENCE_LOCKTIME_MASK = 0xffff;
const SEQUENCE_LOCKTIME_GRANULARITY = 512; // 512 seconds
const SEQUENCE_BLOCKDIFF_LIMIT = Math.pow(2, 16) - 1; // 16 bits 



function Input(params) {
    if (!(this instanceof Input)) {
        return new Input(params);
    }
    if (params) {
        return this._fromObject(params);
    }
}

Input.MAXINT = MAXINT;
Input.DEFAULT_SEQNUMBER = DEFAULT_SEQNUMBER;
Input.DEFAULT_LOCKTIME_SEQNUMBER = DEFAULT_LOCKTIME_SEQNUMBER;
Input.DEFAULT_RBF_SEQNUMBER = DEFAULT_RBF_SEQNUMBER;
Input.SEQUENCE_LOCKTIME_TYPE_FLAG = SEQUENCE_LOCKTIME_TYPE_FLAG;

Object.defineProperty(Input.prototype, 'script', {
    configurable: false,
    enumerable: true,
    get: function() {
        if (this.isNull()) {
            return null;
        }
        if (!this._script) {
            this._script = new Script(this._scriptBuffer);
            this._script._isInput = true;
        }
        return this._script;
    }
});

Input.fromObject = function(obj) {
    $.checkArgument(_.isObject(obj));
    var input = new Input();
    return input._fromObject(obj);
};

Input.prototype.version = 0;
Input.prototype._fromObject = function(params) {
    var prevTxId;
    if (_.isString(params.prevTxId) && JSUtil.isHexa(params.prevTxId)) {
        prevTxId = Buffer.from(params.prevTxId, 'hex');
    } else {
        prevTxId = params.prevTxId;
    }
    this.output = params.output ?
        (params.output instanceof Output ? params.output : new Output(params.output)) : undefined;
    this.prevTxId = prevTxId || params.txidbuf;
    this.outputIndex = _.isUndefined(params.outputIndex) ? params.txoutnum : params.outputIndex;
    this.sequenceNumber = _.isUndefined(params.sequenceNumber) ?
        (_.isUndefined(params.seqnum) ? DEFAULT_SEQNUMBER : params.seqnum) : params.sequenceNumber;
    if (_.isUndefined(params.script) && _.isUndefined(params.scriptBuffer)) {
        throw new errors.Transaction.Input.MissingScript();
    }
    this.setScript(params.scriptBuffer || params.script);
    if (params.version !== undefined)
        this.version = params.version;
    //console.log("input._fromObject: version, params", this.version, params)
    return this;
};

Input.prototype.toObject = Input.prototype.toJSON = function toObject() {
    var obj = {
        prevTxId: this.prevTxId.toString('hex'),
        outputIndex: this.outputIndex,
        sequenceNumber: this.sequenceNumber,
        script: this._scriptBuffer.toString('hex'),
        version: this.version
    };
    // add human readable form if input contains valid script
    if (this.script) {
        obj.scriptString = this.script.toString();
    }
    if (this.output) {
        obj.output = this.output.toObject();
    }
    return obj;
};

Input.fromBufferReader = function(br) {
    var input = new Input();
    input.prevTxId = br.read(32);
    input.outputIndex = br.readUInt32LE();
    let length = br.readUInt64LEBN().toNumber();
    if(length){
        length -= 2;
        input.version = br.readUInt16LE();
    }
    input._scriptBuffer = br.read(length);
    input.sequenceNumber = br.readUInt64LEBN().toNumber();
    //TODO: return different classes according to which input it is
    //e.g: CoinbaseInput, PublicKeyHashInput, MultiSigScriptHashInput, etc.
    return input;
};
/*
Input.fromBufferReader_v2 = function(br) {
    var input = {};
    input.prevTxId = br.read(32);
    input.outputIndex = br.readUInt32LE();
    let length = br.readUInt64LEBN().toNumber();
    if(length){
        length -= 2;
        input.version = br.readUInt16LE();
    }
    let scriptBuffer = br.read(length);
    input.sequenceNumber = br.readUInt64LEBN().toNumber();
    input.script = Script.fromBuffer(scriptBuffer)
    let klass = Input;
    console.log("#### isPublicKeyHashOut klass", scriptBuffer, input.script)
    if(input.script.isScriptHashIn()){
        console.log("#### isPublicKeyHashOut")
        const PublicKeyHashInput = require('./publickeyhash');
        klass = PublicKeyHashInput;
    }
    //TODO: return different classes according to which input it is
    //e.g: CoinbaseInput, PublicKeyHashInput, MultiSigScriptHashInput, etc.
    return new klass(input);
};
Input.prototype.toBufferWriter_org = function(writer) {
    if (!writer) {
        writer = new BufferWriter();
    }

    var script = this._scriptBuffer;

    //@ts-ignore
    let prevTxId = new BufferReader(this.prevTxId).readReverse()
    writer.write(this.prevTxId);
    //LogBuffer("$$$$ prevTxId1: ", this.prevTxId.toString("hex"), writer.bufs)
    writer.writeUInt32LE(this.outputIndex);
    //LogBuffer("$$$$ outputIndex: ", this.outputIndex, writer.bufs)
    let scriptBuf = Buffer.from(script, "hex");
    //if(JSUtil.LogBufferActive && JSUtil.debugLevel > logLevels.debug)
    //    console.log("$$$$ Input.version: ", this.version)
    if (scriptBuf.length) {
        let versionBuf = BN.fromNumber(this.version);
        //@ts-ignore
        scriptBuf = Buffer.concat([versionBuf.toBuffer({
            endian: 'little',
            size: 2
        }), scriptBuf]);
    }
    let bn = BN.fromNumber(scriptBuf.length);
    writer.writeUInt64LEBN(bn);
    //LogBuffer("$$$$ script.length: ", scriptBuf.length, writer.bufs)
    writer.write(scriptBuf);
    //LogBuffer("$$$$ script: ", script.toString("hex"), writer.bufs)
    bn = BN.fromNumber(this.sequenceNumber);
    writer.writeUInt64LEBN(bn);
    //LogBuffer("$$$$ sequenceNumber: ", this.sequenceNumber, writer.bufs)

    return writer;
};
*/
const BN_ZERO = BN.fromNumber(0);
const BN_ONE = BN.fromNumber(1);
const VERSION_BUFFERS = {
    '0': BN_ZERO.toBuffer({endian: 'little', size: 2}),
    '1': BN_ONE.toBuffer({endian: 'little', size: 2})
}

Input.prototype.toBufferWriter = function(writer) {
    if (!writer) {
        writer = new BufferWriter();
    }

    //var script = this._scriptBuffer;

    //@ts-ignore
    //let prevTxId = new BufferReader(this.prevTxId).readReverse()
    writer.write(this.prevTxId);
    //LogBuffer("$$$$ prevTxId1: ", this.prevTxId.toString("hex"), writer.bufs)
    writer.writeUInt32LE(this.outputIndex);
    //LogBuffer("$$$$ outputIndex: ", this.outputIndex, writer.bufs)
    
    //if(JSUtil.LogBufferActive && JSUtil.debugLevel > logLevels.debug)
    //    console.log("$$$$ Input.version: ", this.version)
    if (this._scriptBuffer.length) {
        //let scriptBuf = Buffer.from(this._scriptBuffer, "hex");
        //@ts-ignore
        let scriptBuf = Buffer.concat([ VERSION_BUFFERS[this.version], this._scriptBuffer]);
        writer.writeUInt64LEBN(BN.fromNumber(scriptBuf.length));
        writer.write(scriptBuf);
    }else{
        writer.writeUInt64LEBN(BN_ZERO);
        //LogBuffer("$$$$ script.length: ", scriptBuf.length, writer.bufs)
        //writer.write(scriptBuf);
    }
    
    //LogBuffer("$$$$ script: ", script.toString("hex"), writer.bufs)
    writer.writeUInt64LEBN(BN.fromNumber(this.sequenceNumber));
    //LogBuffer("$$$$ sequenceNumber: ", this.sequenceNumber, writer.bufs)

    return writer;
};

Input.prototype.setScript = function(script) {
    this._script = null;
    if (script instanceof Script) {
        this._script = script;
        this._script._isInput = true;
        this._scriptBuffer = script.toBuffer();
    } else if (script === null) {
        this._script = Script.empty();
        this._script._isInput = true;
        this._scriptBuffer = this._script.toBuffer();
    } else if (JSUtil.isHexa(script)) {
        // hex string script
        this._scriptBuffer = Buffer.from(script, 'hex');
    } else if (_.isString(script)) {
        // human readable string script
        this._script = new Script(script);
        this._script._isInput = true;
        this._scriptBuffer = this._script.toBuffer();
    } else if (BufferUtil.isBuffer(script)) {
        // buffer script
        this._scriptBuffer = Buffer.from(script);
    } else {
        throw new TypeError('Invalid argument type: script');
    }
    return this;
};

/**
 * Retrieve signatures for the provided PrivateKey.
 *
 * @param {Transaction} transaction - the transaction to be signed
 * @param {PrivateKey} privateKey - the private key to use when signing
 * @param {number} inputIndex - the index of this input in the provided transaction
 * @param {number} sigType - defaults to Signature.SIGHASH_ALL
 * @param {Buffer} addressHash - if provided, don't calculate the hash of the
 *     public key associated with the private key provided
 * @param {String} signingMethod "schnorr" or "ecdsa", default to "ecdsa" if not provided
 * @abstract
 */
Input.prototype.getSignatures = function() {
    throw new errors.AbstractMethodInvoked(
        'Trying to sign unsupported output type (only P2PKH and P2SH multisig inputs are supported)' +
        ' for input: ' + JSON.stringify(this)
    );
};

Input.prototype.isFullySigned = function() {
    throw new errors.AbstractMethodInvoked('Input#isFullySigned');
};

Input.prototype.isFinal = function() {
    return this.sequenceNumber !== 4294967295;
};

Input.prototype.addSignature = function() {
    throw new errors.AbstractMethodInvoked('Input#addSignature');
};

Input.prototype.clearSignatures = function() {
    throw new errors.AbstractMethodInvoked('Input#clearSignatures');
};

Input.prototype.isValidSignature = function(transaction, signature, signingMethod) {
    // FIXME: Refactor signature so this is not necessary
    signature.signature.nhashtype = signature.sigtype;
    return Sighash.verify(
        transaction,
        signature.signature,
        signature.publicKey,
        signature.inputIndex,
        this.output.script,
        this.output.satoshisBN,
        undefined,
        signingMethod
    );
};

/**
 * @returns true if this is a coinbase input (represents no input)
 */
Input.prototype.isNull = function() {
    return this.prevTxId.toString('hex') === '0000000000000000000000000000000000000000000000000000000000000000' &&
        this.outputIndex === 0xffffffff;
};

Input.prototype._estimateSize = function() {
    return this.toBufferWriter().toBuffer().length;
};


/**
 * Sets sequence number so that transaction is not valid until the desired seconds
 *  since the transaction is mined
 *
 * @param {Number} time in seconds
 * @return {Transaction} this
 */
Input.prototype.lockForSeconds = function(seconds) {
    $.checkArgument(_.isNumber(seconds));
    if (seconds < 0 || seconds >= SEQUENCE_LOCKTIME_GRANULARITY * SEQUENCE_LOCKTIME_MASK) {
        throw new errors.Transaction.Input.LockTimeRange();
    }
    seconds = parseInt(Math.floor(seconds / SEQUENCE_LOCKTIME_GRANULARITY));

    // SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 
    this.sequenceNumber = seconds | SEQUENCE_LOCKTIME_TYPE_FLAG;
    return this;
};

/**
 * Sets sequence number so that transaction is not valid until the desired block height differnece since the tx is mined
 *
 * @param {Number} height
 * @return {Transaction} this
 */
Input.prototype.lockUntilBlockHeight = function(heightDiff) {
    $.checkArgument(_.isNumber(heightDiff));
    if (heightDiff < 0 || heightDiff >= SEQUENCE_BLOCKDIFF_LIMIT) {
        throw new errors.Transaction.Input.BlockHeightOutOfRange();
    }
    // SEQUENCE_LOCKTIME_TYPE_FLAG = 0
    // SEQUENCE_LOCKTIME_DISABLE_FLAG = 0
    this.sequenceNumber = heightDiff;
    return this;
};


/**
 *  Returns a semantic version of the input's sequence nLockTime.
 *  @return {Number|Date}
 *  If sequence lock is disabled  it returns null,
 *  if is set to block height lock, returns a block height (number)
 *  else it returns a Date object.
 */
Input.prototype.getLockTime = function() {
    if (this.sequenceNumber & SEQUENCE_LOCKTIME_DISABLE_FLAG) {
        return null;
    }

    if (this.sequenceNumber & SEQUENCE_LOCKTIME_TYPE_FLAG) {
        var seconds = SEQUENCE_LOCKTIME_GRANULARITY * (this.sequenceNumber & SEQUENCE_LOCKTIME_MASK);
        return seconds;
    } else {
        var blockHeight = this.sequenceNumber & SEQUENCE_LOCKTIME_MASK;
        return blockHeight;
    }
};



module.exports = Input;