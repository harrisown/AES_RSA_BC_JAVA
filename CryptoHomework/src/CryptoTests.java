import java.util.Scanner;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoTests {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		System.out.print("Enter your secret: ");
		Scanner sc = new Scanner(System.in);
		String secret = sc.nextLine();
		AEStest(secret);
		RSAtest(secret);
	}

	private static void RSAtest(String secret)throws Exception{
		System.out.println("---------RSA TEST--------");
		byte[] plainText = secret.getBytes("UTF8");
		System.out.println("Starting generation of RSA key pair...");
		KeyPair keys = GenerateASymmetricKeys(192);
		System.out.println("Finished generating RSA key pair");
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
		System.out.println("Starting encryption..");
		cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());//encrypt using the public key from KeyPair
		byte[] cipherText = cipher.doFinal(plainText);
		System.out.print("Finish encryption: ");
		System.out.println(new String(cipherText, "UTF8")+ " is the encrypted message!");
		
		System.out.println("Starting decryption...");
		cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());//decrypt using the private key from KeyPair
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.print("Finished decryption: ");
		System.out.println(new String(newPlainText, "UTF8")+ " is the decrypted ciphertext!");
		System.out.println("---------END OF RSA TEST--------");
		System.out.println("");

	}

	public static void AEStest(String secret) throws Exception {
		byte[] plainText = secret.getBytes("UTF8");

		System.out.println("---------AES TEST--------");
		System.out.println("");
		System.out.println("Starting generation of AES key...");
		Key key = GenerateSymmetricKey(192);
		System.out.println("Finished generating AES key");

		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
		System.out.println("Starting encryption..");
		cipher.init(Cipher.ENCRYPT_MODE, key); //encrypt using key

		byte[] cipherText = cipher.doFinal(plainText);
		System.out.print("Finish encryption: ");
		System.out.println(new String(cipherText, "UTF8")+ " is the encrypted message!");

		System.out.println("Starting decryption...");
		cipher.init(Cipher.DECRYPT_MODE, key);//decrypte using the same key!
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.print("Finished decryption: ");
		System.out.println(new String(newPlainText, "UTF8")+ " is the decrypted ciphertext!");
		System.out.println("---------END OF AES TEST---------");
		System.out.println("");
	}

	public static SecretKey GenerateSymmetricKey(int keySizeInBits)throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
		keyGenerator.init(keySizeInBits);
		SecretKey secretkey = keyGenerator.generateKey();
		return secretkey;
	}

	public static KeyPair GenerateASymmetricKeys(int keySizeInBits)throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA","BC"); 
         	keyGenerator.initialize(192); 
         	KeyPair keys = keyGenerator.generateKeyPair(); 
         	return keys;
	}

}
