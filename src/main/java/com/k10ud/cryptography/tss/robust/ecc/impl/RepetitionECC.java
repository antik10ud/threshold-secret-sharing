package com.k10ud.cryptography.tss.robust.ecc.impl;

import java.util.Arrays;

import com.k10ud.cryptography.tss.robust.ecc.IECC;
import com.k10ud.cryptography.tss.robust.util.Bytes;
//IMHO no sense
public class RepetitionECC implements IECC {

	private int repetitionCount;

	public RepetitionECC() {
		this(2);
	}

	public RepetitionECC(int repetitionCount) {
		if (repetitionCount % 2 != 0 || repetitionCount < 0 || repetitionCount > 8)
			throw new IllegalArgumentException("repetitionCount must be even [0..8]");
		this.repetitionCount = repetitionCount;
	}

	@Override
	public byte[] encode(byte[] data) {
		if (data == null)
			throw new IllegalArgumentException("null data");
		int length = data.length;
		byte[] newdata = new byte[4 + 4 + 4 + length * (1 + repetitionCount)];
		int i = 0;
		Bytes.writeInt(newdata, i, 1); // ET 1
		i += 4;
		Bytes.writeInt(newdata, i, length); // DL
		i += 4;
		Bytes.writeInt(newdata, i, length * repetitionCount); // RL
		i += 4;
		for (int j = 0; j <= repetitionCount; j++) { // Data + Redundancy 
			System.arraycopy(data, 0, newdata, i, length);
			i += length;
		}
		return newdata;
	}

	@Override
	public int getIdentifier() {
		return 1;
	}

	@Override
	public byte[] decode(byte[] data) {
		if (data == null)
			throw new IllegalArgumentException("null data");
		int i = 0;
		int ET = Bytes.readInt(data, 0);
		i += 4;
		if (ET != 1)
			throw new IllegalArgumentException("invalida data type " + ET);
		int DL = Bytes.readInt(data, i);
		i += 4;
		int RL = Bytes.readInt(data, i);
		i += 4;
		int R = (RL / DL) + 1;

		if (R == 1) {
			return Arrays.copyOfRange(data, i, data.length);
		} else {
			byte[] newdata = new byte[DL];
			int[] f = new int[R];
			for (int j = 0; j < DL; j++) {
				for (int k = 0, m = j; k < R; k++, m += DL)
					f[k] = data[i + m];
				newdata[j] = (byte) majority(f);
			}
			return newdata;
		}

	}

	private int majority(int[] f) {
		int flength = f.length;
		int x = f[0];
		boolean corrupted = false;
		for (int j = 0; j < flength; j++)
			if (f[j] != x) {
				corrupted = true;
				break;
			}

		if (!corrupted)
			return x;

		int thr = flength / 2;
		for (int i = 0, m = 1, t = 0; i < 8; i++, m <<= 1, t = 0) {
			for (int j = 0; j < flength; j++)
				if (((0xff & f[j]) & m) > 0)
					t++;
			if (t > thr)
				x = x | m;
		}
		return x;
	}

	@Override
	public String toString() {
		return "RepetitionECC [repetitionCount=" + repetitionCount + "]";
	}
}
