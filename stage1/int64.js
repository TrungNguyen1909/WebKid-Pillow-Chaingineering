//
// Tiny module that provides big (64bit) integers.
//
// Copyright (c) 2016 Samuel Groß
//
// Requires utils.js
//

// Datatype to represent 64-bit integers.
//
// Internally, the integer is stored as a Uint8Array in little endian byte order.
function Int64(v) {
    // The underlying byte array.
    var bytes = new Uint8Array(8);
    this.bytes = bytes;

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.getBytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have excactly 8 elements.");
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    // Return a double whith the same underlying bit representation.
    this.asDouble = function() {
        // Check for NaN
        if (bytes[7] == 0xff && (bytes[6] == 0xff || bytes[6] == 0xfe))
            throw new RangeError("Integer can not be represented by a double");

        return Struct.unpack(Struct.float64, bytes);
    };

    // Return a javascript value with the same underlying bit representation.
    // This is only possible for integers in the range [0x0001000000000000, 0xffff000000000000)
    // due to double conversion constraints.
    this.asJSValue = function() {
        if ((bytes[7] == 0 && bytes[6] == 0) || (bytes[7] == 0xff && bytes[6] == 0xff))
            throw new RangeError("Integer can not be represented by a JSValue");

        // For NaN-boxing, JSC adds 2^48 to a double value's bit pattern.
        this.assignSub(this, 0x1000000000000);
        var res = Struct.unpack(Struct.float64, bytes);
        this.assignAdd(this, 0x1000000000000);

        return res;
    };

    // Return the underlying bytes of this number as array.
    this.getBytes = function() {
        return Array.from(bytes);
    };

    // Return the byte at the given index.
    this.byteAt = function(i) {
        return bytes[i];
    };

    // Return the value of this number as unsigned hex string.
    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };
    
    this.asInt32 = function() {
        var value = new Int64(0);
        for (var i = 0; i < 8; i++) {
            if (i < 4) {
                value.bytes[i] = this.bytes[i];
            } else {
                value.bytes[i] = 0;
            }
        }
        
        return parseInt('0x' + hexlify(Array.from(value.bytes).reverse()).slice(-8));
    };
    
    this.asInt16 = function() {
        var value = new Int64(0);
        for (var i = 0; i < 8; i++) {
            if (i < 2) {
                value.bytes[i] = this.bytes[i];
            } else {
                value.bytes[i] = 0;
            }
        }
        
        return parseInt('0x' + hexlify(Array.from(value.bytes).reverse()).slice(-8));
    };

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.

    // Decorator for Int64 instance operations. Takes care
    // of converting arguments to Int64 instances if required.
    function operation(f, nargs) {
        return function() {
            if (arguments.length != nargs)
                throw Error("Not enough arguments for function " + f.name);
            for (var i = 0; i < arguments.length; i++)
                if (!(arguments[i] instanceof Int64))
                    arguments[i] = new Int64(arguments[i]);
            return f.apply(this, arguments);
        };
    }

    // this = -n (two's complement)
    this.assignNeg = operation(function neg(n) {
        for (var i = 0; i < 8; i++)
            bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }, 1);

    // this = a + b
    this.assignAdd = operation(function add(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a - b
    this.assignSub = operation(function sub(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a ^ b
    this.assignXor = operation(function xor(a, b) {
        for (var i = 0; i < 8; i++) {
            bytes[i] = a.byteAt(i) ^ b.byteAt(i);
        }
        return this;
    }, 2);
    
    // this = a & b
    this.assignAnd = operation(function and(a, b) {
        for (var i = 0; i < 8; i++) {
            bytes[i] = a.byteAt(i) & b.byteAt(i);
        }
        return this;
    }, 2);
    
    // this = a << b
    this.assignShiftLeft = operation(function shiftLeft(a, b) {
        for (var i = 0; i < 8; i++) {
            if (i < b) {
                bytes[i] = 0;
            } else {
                bytes[i] = a.byteAt(Sub(i, b).asInt32());
            }
        }
        return this;
    }, 2);
    
    // this = a >> b
    this.assignShiftRight = operation(function shiftRight(a, b) {
        for (var i = 0; i < 8; i++) {
            if (i < (8 - b)) {
                bytes[i] = a.byteAt(Add(i, b).asInt32());
            } else {
                bytes[i] = 0;
            }
        }
        return this;
    }, 2);
    return this;
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromDouble = function(d) {
    var bytes = Struct.pack(Struct.float64, d);
    return new Int64(bytes);
};

// Convenience functions. These allocate a new Int64 to hold the result.

// Return -n (two's complement)
function Neg(n) {
    return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
    return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
    return (new Int64()).assignSub(a, b);
}

// Return a ^ b
function Xor(a, b) {
    return (new Int64()).assignXor(a, b);
}

// Return a & b
function And(a, b) {
    return (new Int64()).assignAnd(a, b);
}

// Return a << b
function ShiftLeft(a, b) {
    return (new Int64()).assignShiftLeft(a, b);
}

// Return a >> b
function ShiftRight(a, b) {
    return (new Int64()).assignShiftRight(a, b);
}

// Some commonly used numbers.
Int64.Zero = new Int64(0);
Int64.One = new Int64(1);

// That's all the arithmetic we need for exploiting WebKit.. :)