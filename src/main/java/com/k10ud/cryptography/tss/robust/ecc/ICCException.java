package com.k10ud.cryptography.tss.robust.ecc;

public class ICCException extends Exception {
	private static final long serialVersionUID = 1L;

	public ICCException() {
		super();
	}

	public ICCException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public ICCException(String message, Throwable cause) {
		super(message, cause);
	}

	public ICCException(String message) {
		super(message);
	}

	public ICCException(Throwable cause) {
		super(cause);
	}

}
