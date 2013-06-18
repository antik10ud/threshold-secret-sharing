package com.k10ud.cryptography.tss.robust.ecc.impl;

import com.k10ud.cryptography.tss.robust.ecc.IECC;
import com.k10ud.cryptography.tss.robust.util.Bytes;

public class NullECC implements IECC {

	@Override
	public byte[] encode(byte[] data) {
		byte[] newdata = new byte[8 + data.length];
		int i = 0;
		Bytes.writeInt(data, i, 0); // ET 0
		i += 8;
		System.arraycopy(data, 0, newdata, i, data.length);
		i += data.length;
		return newdata;
	}

	@Override
	public int getIdentifier() {
		return 0;
	}

	@Override
	public byte[] decode(byte[] data) {
		return Bytes.strip(data, 8);
	}

	@Override
	public String toString() {
		return "NullECC";
	}

}
