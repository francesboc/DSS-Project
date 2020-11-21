package cryptographic;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES {
	
	private static final String CIPHER_SUITE = "AES/ECB/PKCS5Padding";
	private static final int KEY_LENGTH = 32; //measured in byte
	private static byte [] key;
	public static final String CHAR_SET = "UTF-8";
	
	public static void setKey(String myKey) 
			throws AesException {
		try{
			key = myKey.getBytes(CHAR_SET);
		}
		catch(Exception e) {
			throw new AesException(e.getMessage());
		}
	}

	public static String decrypt(String strEncypted) throws AesException{
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_SUITE);
			SecretKeySpec secretKey = new SecretKeySpec(Arrays.copyOf(key, KEY_LENGTH), "AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);

			return Base64.getEncoder().encodeToString(cipher.doFinal(strEncypted.getBytes(CHAR_SET)));
		}
		catch(Exception e) {
			throw new AesException(e.getMessage());

		}
	}

	public static String encrypt(String strToEncrypt ) throws AesException {
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_SUITE);
			SecretKeySpec secretKey = new SecretKeySpec(Arrays.copyOf(key, KEY_LENGTH), "AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(CHAR_SET)));
		}
		catch(Exception e) {
			throw new AesException(e.getMessage());
			
		}

	}
	
	public static long getSafeLong() {
		return new SecureRandom().nextLong();
	}
	
	

}
