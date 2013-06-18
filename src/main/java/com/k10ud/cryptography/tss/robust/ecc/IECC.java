package com.k10ud.cryptography.tss.robust.ecc;

public interface IECC {

	int getIdentifier();

	byte[] encode(byte[] data);

	byte[] decode(byte[] data);

}
