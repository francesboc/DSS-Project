package cryptographic;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * @brief implementing of AES cipher
 */

public class AES {
	
	private static final String CIPHER_SUITE = "AES/ECB/PKCS5Padding";
	private static final int KEY_LENGTH = 32; //measured in byte
	private static byte [] key;
	public static final String CHAR_SET = "UTF-8";

	/**
	 *
	 * @param myKey
	 * @throws AesException
	 */
	
	 public static void setKey(String myKey)
			throws AesException {
		try{
			key = myKey.getBytes(CHAR_SET);
		}
		catch(Exception e) {
			throw new AesException(e.getMessage());
		}
	}

	/**
	 *
	 * @param strEncrypted
	 * @param symmetricKey
	 * @return plain text
	 * @throws AesException
	 */
	 public static String decrypt(byte[] strEncrypted,byte[] symmetricKey) throws AesException{
		try {
			String tmp = new String(symmetricKey);
			Cipher cipher = Cipher.getInstance(CIPHER_SUITE);
			SecretKeySpec secretKey = new SecretKeySpec(Arrays.copyOf(tmp.getBytes(CHAR_SET), KEY_LENGTH), "AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] base64Decoded = Base64.getDecoder().decode(strEncrypted);

			return new String(cipher.doFinal(base64Decoded),CHAR_SET);
		}
		catch(Exception e) {
			throw new AesException(e.getMessage());

		}
	}

	/**
	 *
	 * @param strToEncrypt
	 * @return cipher text
	 * @throws AesException
	 */
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

	/**
	 *
	 * @return a safe random long
	 */
	public static long getSafeLong() {
		return new SecureRandom().nextLong();
	}
	
	

}
