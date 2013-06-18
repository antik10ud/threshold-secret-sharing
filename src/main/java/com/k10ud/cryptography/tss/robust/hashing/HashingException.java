package com.k10ud.cryptography.tss.robust.hashing;

public class HashingException extends Exception {
	private static final long serialVersionUID = 1L;

	public HashingException() {
		super();
	}

	public HashingException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public HashingException(String message, Throwable cause) {
		super(message, cause);
	}

	public HashingException(String message) {
		super(message);
	}

	public HashingException(Throwable cause) {
		super(cause);
	}

}
