package com.k10ud.cryptography.tss.robust;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import com.k10ud.cryptography.tss.robust.ecc.ICCException;
import com.k10ud.cryptography.tss.robust.util.Hex;

public class RobustThresholdSecretSharingTest {

	private static Random rnd = new SecureRandom();

	@Test
	public void kat() throws ICCException {
		RobustTSS tss = new RobustTSS();
		byte[] secret = Hex.convert("7465737400");
		byte[] identifier = new byte[RobustTSSShare.IDENTIFIER_BYTES];
		rnd.nextBytes(identifier);
		List<RobustTSSShare> shares = tss.createShares(secret,RobustTSSConfig.make().id(identifier),rnd);
		
		ArrayList<RobustTSSShare> shares2 = new ArrayList<> ();
		for (RobustTSSShare i:shares) {
			shares2.add(new RobustTSSShare(i.getEncoded()));
		}
		
		System.out.println(shares2);
		
		byte[] recovered = tss.recoverSecret(shares2);
		Assert.assertTrue("array mismatch", Arrays.equals(secret, recovered));
	}

}