import java.util.Scanner;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoTests {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("Enter your secret!");
		Scanner sc = new Scanner(System.in);
		String secret = sc.nextLine();
		AEStest(secret);

	}

	public static void AEStest(String secret)throws Exception{
		byte[] plainText = secret.getBytes("UTF8");
		// Get a AES private key
		System.out.println("\nStart generating AES key");
		Key key = GenerateSymmetricKey(192);
		System.out.println("Finish generating AES key");
		
		// Creates the AES Cipher object (specifying the algorithm, mode, and
		// padding).
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding","BC");
		// Print the provider information
		System.out.println("\n" + cipher.getProvider().getInfo());
		//
		System.out.println("\nStart encryption");
		// Initializes the Cipher object.
		cipher.init(Cipher.ENCRYPT_MODE, key);
		// Encrypt the plaintext using the public key
		byte[] cipherText = cipher.doFinal(plainText);
		System.out.println("Finish encryption: ");
		System.out.println(new String(cipherText, "UTF8"));
		
		System.out.println("\nStart decryption");
		// Initializes the Cipher object.
		cipher.init(Cipher.DECRYPT_MODE, key);
		// Decrypt the ciphertext using the same key
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.println("Finish decryption: ");
		System.out.println(new String(newPlainText, "UTF8"));
	}
	
	public static SecretKey GenerateSymmetricKey(int keySizeInBits)throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
		keyGenerator.init(keySizeInBits);
		SecretKey secretkey = keyGenerator.generateKey();
		return secretkey;
	}

}
