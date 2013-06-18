package com.k10ud.cryptography.tss.robust.util;

import java.util.ArrayList;

public class Wiper {
	ArrayList<byte[]> wipelist = new ArrayList<byte[]>();

	public byte[][] add(byte[][] aa) {
		for (byte[] a : aa)
			add(a);
		return aa;
	}

	public byte[] add(byte[] a) {
		wipelist.add(a);
		return a;
	}

	public void wipe() {
		for (byte[] a : wipelist)
			Bytes.wipe(a);
	}

}
