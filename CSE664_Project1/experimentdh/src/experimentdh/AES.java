package experimentdh;


import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;

public class AES {
	static String IV = "AAAAAAAAAAAAAAAA";

	public static String CipherToString(byte[] cipher)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < cipher.length; i++)
				sb.append(cipher[i] + " ");
		return sb.toString();
	}
	
	public static byte[] encrypt(String plainText, String encryptionKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"),
				"AES");
		cipher.init(Cipher.ENCRYPT_MODE, key,
				new IvParameterSpec(IV.getBytes("UTF-8")));
		return cipher.doFinal(plainText.getBytes("UTF-8"));
	}

	public static String decrypt(byte[] cipherText, String encryptionKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"),
				"AES");
		cipher.init(Cipher.DECRYPT_MODE, key,
				new IvParameterSpec(IV.getBytes("UTF-8")));
		return new String(cipher.doFinal(cipherText), "UTF-8");
	}
}

