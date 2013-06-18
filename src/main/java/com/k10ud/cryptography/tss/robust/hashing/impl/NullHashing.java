package com.k10ud.cryptography.tss.robust.hashing.impl;

import com.k10ud.cryptography.tss.robust.hashing.IHashing;

public class NullHashing implements IHashing {

	private static final byte[] VOID_BYTE_ARRAY = {};

	public NullHashing() {
	}

	@Override
	public int getIdentifier() {
		return 0;
	}

	@Override
	public byte[] digest(byte[] a) {
		return VOID_BYTE_ARRAY;
	}

	@Override
	public int getHashSize() {
		return 0;
	}

	@Override
	public String toString() {
		return "NullHashing";
	}
}