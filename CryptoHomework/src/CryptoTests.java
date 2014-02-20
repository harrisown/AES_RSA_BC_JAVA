import java.util.Random;
import java.util.Scanner;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoTests {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		System.out.print("Enter your secret: ");
		Scanner sc = new Scanner(System.in);
		String secret = sc.nextLine();
		AEStest(secret);
		RSAtest(secret);
		sc.close();
	}

	private static void RSAtest(String secret)throws Exception{
		byte[] IV = new byte[16];
		Random random = new SecureRandom();
		random.nextBytes(IV);
		
		System.out.println("---------RSA TEST--------");
		byte[] plainText = secret.getBytes("UTF8");
		System.out.println("Starting generation of RSA key pair...");
		KeyPair keys = GenerateASymmetricKeys(512);
		System.out.println("Finished generating RSA key pair");
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
		System.out.println("Started encryption..");
		cipher.init(Cipher.ENCRYPT_MODE, keys.getPublic());//encrypt using the public key from KeyPair
		byte[] cipherText = cipher.doFinal(plainText);
		System.out.println("Finished encryption: ");
		System.out.println(new String(cipherText, "UTF8")+ " is the encrypted message!");
		
		System.out.println("Starting decryption...");
		cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());//decrypt using the private key from KeyPair
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.print("Finished decryption: ");
		System.out.println(new String(newPlainText, "UTF8")+ " is the decrypted ciphertext!");
		System.out.println("---------END OF RSA TEST--------");
		System.out.println("");
		RSASignAndVerify(secret,keys);

	}

	public static void AEStest(String secret) throws Exception {
		byte[] plainText = secret.getBytes("UTF8");

		System.out.println("---------AES TEST--------");
		System.out.println("");
		System.out.println("Starting generation of AES key...");
		Key key = GenerateSymmetricKey(128);
		byte[] IV = new byte[16];
		Random random = new SecureRandom();
		random.nextBytes(IV);
		
		System.out.println("Finished generating AES key");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		System.out.println("Starting encryption..");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV)); //encrypt using key

		byte[] cipherText = cipher.doFinal(plainText);
		System.out.print("Finish encryption: ");
		System.out.println(new String(cipherText, "UTF8")+ " is the encrypted message!");

		System.out.println("Starting decryption...");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));//decrypte using the same key!
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.print("Finished decryption: ");
		System.out.println(new String(newPlainText, "UTF8")+ " is the decrypted ciphertext!");
		System.out.println("---------END OF AES TEST---------");
		System.out.println("");
	}
	
	public static void RSASignAndVerify(String secret, KeyPair keyPair)throws Exception{
		System.out.println("------Sign and Verify with RSA!------");
	    Signature signature = Signature.getInstance("SHA1withRSA", "BC");
	    
	    signature.initSign(keyPair.getPrivate(), new SecureRandom());

	    signature.update(secret.getBytes());
	    
	    byte[] sigBytes = signature.sign();
	    signature.initVerify(keyPair.getPublic());
	    signature.update(secret.getBytes());
	    System.out.println("Signature is verified: "+signature.verify(sigBytes));
	    System.out.println("------End of Verification!------");

	}

	public static SecretKey GenerateSymmetricKey(int keySizeInBits)throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
		keyGenerator.init(keySizeInBits);
		SecretKey secretkey = keyGenerator.generateKey();
		return secretkey;
	}

	public static KeyPair GenerateASymmetricKeys(int keySizeInBits)throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA","BC"); 
        	keyGenerator.initialize(keySizeInBits,new SecureRandom()); 
        	KeyPair keys = keyGenerator.generateKeyPair(); 
        	return keys;
	}

}
