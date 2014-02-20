import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoTests {
public static ArrayList<String> stringArray = new ArrayList<String>();
public static char[] alphabet = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
	
	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		System.out.print("Enter your secret: ");
		Scanner sc = new Scanner(System.in);
		String secret = sc.nextLine();
		sc.close();

		AEStest(secret);
		RSAtest(secret);
		GenerateRandomStrings(25);//input is size of string in characters
		TimeTrials();
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

	public static void GenerateRandomStrings(int sizeOfString){
		Random rand = new Random();
		while(stringArray.size()!= 100){ //generate 100 random strings
			StringBuilder sb = new StringBuilder();
			
			for(int j = 0; j < sizeOfString;j++){
				sb.append(alphabet[rand.nextInt(25)]);
			}			
			if(!stringArray.contains(sb.toString())){
				stringArray.add(sb.toString());
			}
		}
	}
	
	public static void TimeTrials()throws Exception{
		Date d = new Date();
		long startTimeAES = d.getTime();
		for(int i = 0;i < 100;i++){
			AEStest(stringArray.get(i));
		}
		Date e = new Date();
		long endTimeAES = e.getTime();
		
		Date f = new Date();
		long startTimeRSA = f.getTime();
		for(int i = 0;i < 100;i++){
			RSAtest(stringArray.get(i));
		}
		Date g = new Date();
		long endTimeRSA = g.getTime();
		
		System.out.println("------TIME TRIALS COMPLETE!------");
		System.out.println("AES Encryption/Decryption Test took: "+ (endTimeAES-startTimeAES) +" milliseconds to complete");
		System.out.println("RSA Encryption/Decryption Test took: "+ (endTimeRSA-startTimeRSA) +" milliseconds to complete");
		System.out.println("AES was "+(endTimeRSA-startTimeRSA)/(endTimeAES-startTimeAES)+"x faster than RSA");
		
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
