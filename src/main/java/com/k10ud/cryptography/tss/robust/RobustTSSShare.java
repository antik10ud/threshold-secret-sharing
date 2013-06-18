package com.k10ud.cryptography.tss.robust;

import java.util.Arrays;

import com.k10ud.cryptography.tss.robust.ecc.ICCException;
import com.k10ud.cryptography.tss.robust.ecc.IECC;
import com.k10ud.cryptography.tss.robust.util.Bytes;
import com.k10ud.cryptography.tss.robust.util.Hex;

public class RobustTSSShare {
	private static final byte[] MAGIC_NUMBER = { (byte) 0xf6, (byte) 0x28, (byte) 0xf9, (byte) 0x1b, (byte) 0x52, (byte) 0x02, (byte) 0x3d, (byte) 0x11 };

	public static final int IDENTIFIER_BYTES = 16;
	public static final int MAGIC_NUMBER_BYTES = MAGIC_NUMBER.length;

	public static byte[] MAGIC_NUMBER() {
		return Arrays.copyOf(MAGIC_NUMBER, MAGIC_NUMBER.length);
	}

	private final byte[] identifier;
	private final byte[] raw;
	private final int threshold;
	private final int hashingId;
	private final int eccId;

	public RobustTSSShare(byte[] identifier, int hashingId, int threshold, int eccId, byte[] raw) {
		if (identifier == null || identifier.length != IDENTIFIER_BYTES)
			throw new IllegalArgumentException("invalid identifer");
		if (raw == null || raw.length < 2)
			throw new IllegalArgumentException("raw identifer");
		this.identifier = identifier;
		this.hashingId = hashingId;
		this.threshold = threshold;
		this.eccId = eccId;
		this.raw = raw;
	}

	public RobustTSSShare(byte[] encoded) throws ICCException {
		if (encoded == null)
			throw new IllegalArgumentException("encoded is null");
		if (encoded.length < MAGIC_NUMBER_BYTES + 4)
			throw new IllegalArgumentException("invalid encoding");
		int i = MAGIC_NUMBER_BYTES;
		this.eccId = Bytes.readInt(encoded, i);
		i += 4;
		IECC icc = RobustTSSRegistry.instance.getICC(eccId);
		byte[] corrected = icc.decode(Arrays.copyOfRange(encoded, MAGIC_NUMBER_BYTES, encoded.length));
		i = 0;
		this.identifier = Arrays.copyOfRange(corrected, 0, IDENTIFIER_BYTES);
		i += IDENTIFIER_BYTES;
		this.hashingId = Bytes.readInt(corrected, i);
		i += 4;
		this.threshold = Bytes.readInt(corrected, i);
		i += 4;
		int sharelen = (int) Bytes.readLong(corrected, i);
		i += 8;
		if (corrected.length - i != sharelen)
			throw new IllegalArgumentException("invalid encoding");
		raw = Arrays.copyOfRange(corrected, i, corrected.length);
	}

	public byte[] getEncoded() throws ICCException {
		IECC ecc = RobustTSSRegistry.instance.getICC(eccId);
		return Bytes.join(MAGIC_NUMBER, ecc.encode(Bytes.join(//
				identifier, //
				Bytes.toArray(hashingId), //
				Bytes.toArray(threshold), //
				Bytes.toArray((long) raw.length), //
				raw //
				))); ////IMHO no sense = no effective ecc
	}

	public byte[] getIdentifier() {
		return identifier;
	}

	public byte[] getRaw() {
		return raw;
	}

	public int getThreshold() {
		return threshold;
	}

	public int getHashingId() {
		return hashingId;
	}

	public int getEccId() {
		return eccId;
	}

	@Override
	public String toString() {
		return "RobustTSSShare [" + (identifier != null ? "identifier=" + Hex.convert(identifier) + ", " : "") + "hashingId=" + hashingId + ", threshold="
				+ threshold + ", " + (raw != null ? "raw=" + Hex.convert(raw) + ", " : "") + "eccId=" + eccId + "]";
	}

}
