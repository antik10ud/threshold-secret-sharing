package com.k10ud.cryptography.tss.robust;

import java.util.HashMap;

import com.k10ud.cryptography.tss.robust.ecc.ICCException;
import com.k10ud.cryptography.tss.robust.ecc.IECC;
import com.k10ud.cryptography.tss.robust.ecc.impl.NullECC;
import com.k10ud.cryptography.tss.robust.ecc.impl.RepetitionECC;
import com.k10ud.cryptography.tss.robust.hashing.HashingException;
import com.k10ud.cryptography.tss.robust.hashing.IHashing;
import com.k10ud.cryptography.tss.robust.hashing.impl.NullHashing;
import com.k10ud.cryptography.tss.robust.hashing.impl.SHA1Hashing;
import com.k10ud.cryptography.tss.robust.hashing.impl.SHA256Hashing;

public enum RobustTSSRegistry {
	instance;

	private final HashMap<Integer, Class<? extends IHashing>> hashingRegistry;
	private final HashMap<Integer, Class<? extends IECC>> eccRegistry;

	RobustTSSRegistry() {
		hashingRegistry = new HashMap<>();
		eccRegistry = new HashMap<>();
		try {
			registerHashing(NullHashing.class);
			registerHashing(SHA1Hashing.class);
			registerHashing(SHA256Hashing.class);
			registerECC(NullECC.class);
			registerECC(RepetitionECC.class);
		} catch (InstantiationException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	public void registerHashing(Class<? extends IHashing> clas) throws InstantiationException, IllegalAccessException {
		IHashing newInstance = clas.newInstance();
		hashingRegistry.put(newInstance.getIdentifier(), clas);
	}

	public void registerECC(Class<? extends IECC> clas) throws InstantiationException, IllegalAccessException {
		IECC newInstance = clas.newInstance();
		eccRegistry.put(newInstance.getIdentifier(), clas);
	}

	public IECC getICC(int eccId) throws ICCException {
		Class<? extends IECC> clas = eccRegistry.get(eccId);
		if (clas == null)
			throw new ICCException("ECC not registered: " + eccId);
		try {
			return clas.newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			throw new ICCException(e);
		}
	}

	public IHashing getHashing(int hashingId) throws HashingException {
		Class<? extends IHashing> clas = hashingRegistry.get(hashingId);
		if (clas == null)
			throw new HashingException("Hashing not registered: " + hashingId);
		try {
			return clas.newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			throw new HashingException(e);
		}
	}

	public boolean containsHashingId(int identifier) {
		return hashingRegistry.containsKey(identifier);
	}

	public boolean containsECCId(int identifier) {
		return eccRegistry.containsKey(identifier);
	}

}
