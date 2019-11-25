package com.quare.otpgenerator.algorithms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.quare.otpgenerator.algorithms.HashAlgorithm;
import com.quare.otpgenerator.algorithms.Totp;
import com.quare.otpgenerator.algorithms.exceptions.OtpGenerationException;
import com.tngtech.java.junit.dataprovider.DataProvider;
import com.tngtech.java.junit.dataprovider.DataProviderRunner;
import com.tngtech.java.junit.dataprovider.UseDataProvider;

@RunWith(DataProviderRunner.class)
public class TotpTest {

	private static final String KEY = "pippo";

	private static final Logger log = LoggerFactory.getLogger(TotpTest.class);

	private static final String PAR1 = "PAR1";

	private static final String PAR2 = "PAR2";
	
	@DataProvider
	public static Object[][] data() {
		return new Object[][] { 
			
			{ 6, HashAlgorithm.HMAC_SHA256 },
			{ 6, HashAlgorithm.HMAC_SHA512 },
			{ 8, HashAlgorithm.HMAC_SHA256 },
			{ 8, HashAlgorithm.HMAC_SHA512 },
			
		};
	}

	@Test
	@UseDataProvider("data")
	public void totpTest(int digits, HashAlgorithm hashAlgorithm) throws OtpGenerationException, InterruptedException  {
		

		log.debug("TEST digits = "+digits+", algo = " + hashAlgorithm.getCryptoLabel());
		
		int timestep=2;
		
		Totp totp = new Totp(timestep,0,digits, hashAlgorithm);
		
		String otp1 = totp.totp(KEY);
		String otp1Pars = totp.totp(KEY,PAR1,PAR2);
		String otp1Par1 = totp.totp(KEY,PAR1);
		String otp1Par2 = totp.totp(KEY,PAR2);
		
		Thread.sleep(timestep*1000);
		
		String otp2 = totp.totp(KEY);
		String otp2Pars = totp.totp(KEY,PAR1,PAR2);
		String otp2Par1 = totp.totp(KEY,PAR1);
		String otp2Par2 = totp.totp(KEY,PAR2);
		
		String otp3 = totp.totp(KEY, -1);
		String otp3Pars = totp.totp(KEY,-1,PAR1,PAR2);
		String otp3Par1 = totp.totp(KEY,-1,PAR1);
		String otp3Par2 = totp.totp(KEY,-1,PAR2);
		
		
		log.debug("otp1 = "+otp1);
		log.debug("otp1pars = "+otp1Pars);
		log.debug("otp1par1 = "+otp1Par1);
		log.debug("otp1par2 = "+otp1Par2);
		assertEquals(digits,otp1.length());
		assertTrue(otp1.matches("^[0-9]{"+digits+"}$"));
		assertEquals(digits,otp1Pars.length());
		assertTrue(otp1Pars.matches("^[0-9]{"+digits+"}$"));
		assertEquals(digits,otp1Par1.length());
		assertTrue(otp1Par1.matches("^[0-9]{"+digits+"}$"));
		assertEquals(digits,otp1Par2.length());
		assertTrue(otp1Par2.matches("^[0-9]{"+digits+"}$"));
		
		assertNotEquals(otp1, otp1Pars);
		assertNotEquals(otp1, otp1Par1);
		assertNotEquals(otp1, otp1Par2);		
		assertNotEquals(otp1Pars, otp1Par1);		
		assertNotEquals(otp1Pars, otp1Par2);	
		assertNotEquals(otp1Par1, otp1Par2);
		
		
		log.debug("otp2 = "+otp2);
		log.debug("otp2pars = "+otp2Pars);
		log.debug("otp2par1 = "+otp2Par1);
		log.debug("otp2par2 = "+otp2Par2);
		
		assertNotEquals(otp1, otp2);
		assertNotEquals(otp2, otp2Pars);
		assertNotEquals(otp2, otp2Par1);
		assertNotEquals(otp2, otp2Par2);	
		
		assertEquals(digits,otp2.length());
		assertTrue(otp2.matches("^[0-9]{"+digits+"}$"));
		
		log.debug("otp3 = "+otp3);	
		log.debug("otp3pars = "+otp3Pars);
		log.debug("otp3par1 = "+otp3Par1);
		log.debug("otp3par2 = "+otp3Par2);
		assertEquals(otp1, otp3);
		assertEquals(otp1Pars, otp3Pars);
		assertEquals(otp1Par1, otp3Par1);
		assertEquals(otp1Par2, otp3Par2);
		
		assertEquals(digits,otp2.length());
		assertTrue(otp2.matches("^[0-9]{"+digits+"}$"));
		
		
	}
}
