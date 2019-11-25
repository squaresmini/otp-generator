package otpGeneration.algorithm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tngtech.java.junit.dataprovider.DataProvider;
import com.tngtech.java.junit.dataprovider.DataProviderRunner;
import com.tngtech.java.junit.dataprovider.UseDataProvider;

import otpGeneration.algorithms.HashAlgorithm;
import otpGeneration.algorithms.Hotp;
import otpGeneration.algorithms.exceptions.OtpGenerationException;

@RunWith(DataProviderRunner.class)
public class HotpTest {

	private static final String KEY = "pippo";
	private static final String PARAM1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;Afjeofiejfksdncdksadwoq";
	private static final String PARAM2 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;Afjeofiejfksdncdksadwoq";
	private static final String PARAM3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;Afjeofiejfksdncdksadwor";

	private static final Logger log = LoggerFactory.getLogger(HotpTest.class);
	
	@DataProvider
	public static Object[][] data() {
		return new Object[][] { 
			{ 6, HashAlgorithm.HMAC_SHA256, 0L }, 
			{ 6, HashAlgorithm.HMAC_SHA256, 1L },
			{ 6, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE },
			{ 6, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE + 1 },
			{ 6, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE * 2  + 1 },
			{ 6, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE * 2  + 2 }, // 0
			
			{ 6, HashAlgorithm.HMAC_SHA512, 0L }, 
			{ 6, HashAlgorithm.HMAC_SHA512, 1L },
			{ 6, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE },
			{ 6, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE + 1 },
			{ 6, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE * 2  + 1 },
			{ 6, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE * 2  + 2 }, // 0
			
			{ 8, HashAlgorithm.HMAC_SHA256, 0L }, 
			{ 8, HashAlgorithm.HMAC_SHA256, 1L },
			{ 8, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE },
			{ 8, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE + 1 },
			{ 8, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE * 2  + 1 },
			{ 8, HashAlgorithm.HMAC_SHA256, Long.MAX_VALUE * 2  + 2 }, // 0
			
			{ 8, HashAlgorithm.HMAC_SHA512, 0L }, 
			{ 8, HashAlgorithm.HMAC_SHA512, 1L },
			{ 8, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE },
			{ 8, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE + 1 },
			{ 8, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE * 2  + 1 },
			{ 8, HashAlgorithm.HMAC_SHA512, Long.MAX_VALUE * 2  + 2 }, // 0
			
			
		};
	}

	@Test
	@UseDataProvider("data")
	public void hotpTest(int digits, HashAlgorithm hashAlgorithm, long counter) throws OtpGenerationException  {

		log.debug("binaryString = "+Long.toBinaryString(counter));
		
		Hotp hotp = new Hotp(digits, hashAlgorithm);
		
		String otp = hotp.hotp(KEY, counter);
		
		log.debug("otp = "+otp);
		
		String otpWithParam1 = hotp.hotp(KEY, counter, PARAM1);
		String otpWithParam2 = hotp.hotp(KEY, counter, PARAM2);
		String otpWithParam3 = hotp.hotp(KEY, counter, PARAM3);
		
		log.debug("otpWithParam1 = "+otpWithParam1);
		log.debug("otpWithParam2 = "+otpWithParam2);
		log.debug("otpWithParam3 = "+otpWithParam3);
		
		
		assertEquals(digits,otp.length());
		assertTrue(otp.matches("^[0-9]{"+digits+"}$"));
		assertEquals(digits,otpWithParam1.length());
		assertTrue(otpWithParam1.matches("^[0-9]{"+digits+"}$"));
		
		assertNotEquals(otp, otpWithParam1);
		assertNotEquals(otp, otpWithParam2);
		assertNotEquals(otp, otpWithParam3);
		assertNotEquals(otpWithParam1, otpWithParam2);
		assertNotEquals(otpWithParam1, otpWithParam3);
		assertNotEquals(otpWithParam2, otpWithParam3);
	}
	
	@Test(expected = OtpGenerationException.class)
	public void hotpKeyNullTest() throws OtpGenerationException  {
		Hotp hotp = new Hotp();
		hotp.hotp(null, 0L);
	}
}
