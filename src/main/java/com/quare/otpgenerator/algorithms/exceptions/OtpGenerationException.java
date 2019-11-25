package com.quare.otpgenerator.algorithms.exceptions;

public class OtpGenerationException extends Exception{

	private static final long serialVersionUID = 3197991695949731267L;

	public OtpGenerationException() {
		super();
	}

	public OtpGenerationException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public OtpGenerationException(String message, Throwable cause) {
		super(message, cause);
	}

	public OtpGenerationException(String message) {
		super(message);
	}

	public OtpGenerationException(Throwable cause) {
		super(cause);
	}
	
	
	
}
