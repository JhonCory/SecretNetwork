import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

// Encryption/Decryption methods used by both User and SecretServer
public class SecureMethods {
	// Given message, sender, and msg #, prepares a "regular" payload
	public static byte[] preparePayload(byte[] sender, byte[] message, int msgNum, byte[] key, boolean simMode) {
		byte[] msgNumBytes = String.valueOf(msgNum).getBytes();
		byte[] ptxtPayload = ComMethods.concatByteArrs(message, sender, msgNumBytes);
//
		ComMethods.report("Plaintext payload to be sent to SecretServer will be '"+ptxtPayload+"'.", simMode);
//
		byte[] ctxtPayload = encryptAES(ptxtPayload, key, true); // encrypt
		return ctxtPayload;
	}


	// Given "regular" payload, sender, and msg #, returns message in payload
	public static byte[] processPayload(byte[] sender, byte[] payload, int msgNum, byte[] key, boolean simMode) {
		byte[] decipheredPL = encryptAES(payload, key, false); // decrypt
		byte[] msgNumBytes = String.valueOf(msgNum).getBytes();

		// Check that the payload ends properly
		byte[] expectedEnd = ComMethods.concatByteArrs(sender, msgNumBytes);
		int messageLength = decipheredPL.length - expectedEnd.length;
		if (!Arrays.equals(Arrays.copyOfRange(decipheredPL, messageLength, decipheredPL.length), expectedEnd)) {
			ComMethods.handleBadResp();
		} 

		byte[] message = Arrays.copyOf(decipheredPL, messageLength);
		return message;
	}




	// Encrypts message using hybrid RSA encryption with public key <k_n, k_e>
	// Hybrid RSA encryption works by having the encryptor generate a random 
	// 128-bit symmetric key and appending it to the front of the payload
	public static byte[] encryptRSA(byte[] message, BigInteger k_n, BigInteger k_e, boolean simMode) {
		ComMethods.report("Encrypting "+message+" with hybrid RSA with k_n = "+k_n+", k_e = "+k_e+"...", simMode);

		String randoms = UUID.randomUUID().toString();
		byte[] randomBytes = randoms.getBytes();

		// Generate 128-bit throwaway key
		byte[] throwawayKey = ComMethods.genNonce();

		// Encrypt message using AES and throwaway key
		byte[] encryptedMsg = encryptAES(message, throwawayKey, true);

		// Encrypt key using RSA
		BigInteger bigIntKey = new BigInteger(throwawayKey); 

		// Debugging only
		if (bigIntKey.compareTo(k_n) != -1) {
			System.out.println("ERROR ~~ bigIntKey is too big!");
			System.out.println("bigIntKey = "+bigIntKey);
			System.out.println("k_n = "+k_n);
			System.exit(0);
		}


		BigInteger bigIntResult = bigIntKey.modPow(k_e, k_n);
		byte[] encryptedKey = bigIntResult.toByteArray();

		// Partition will be made of three consecutive bytes with vals 1,2,3
		byte[] partition = new byte[3];
		for (int i=0; i<partition.length; i++) 
			partition[i] = Byte.valueOf(String.valueOf(i+1));
		
		// Create payload of encrypted key, partition, and encrypted msg
		byte[] payload = ComMethods.concatByteArrs(encryptedKey,partition,encryptedMsg);

		ComMethods.report("Encrypting done.", simMode);
		ComMethods.report("", simMode);
		return payload;
	}



	// Decrypts message using hybrid RSA with private key <k_n, k_d>
	public static byte[] decryptRSA(byte[] payload, BigInteger k_n, BigInteger k_d, boolean simMode) {
		ComMethods.report("Decrypting '"+payload+"' with hybrid RSA with k_n = "+k_n+", k_d = "+k_d+"...", simMode);

		// Split payload into the RSA-encrypted key and AES-encrypted message
		byte[] partition = new byte[3];
		for (int i=0; i<partition.length; i++) 
			partition[i] = Byte.valueOf(String.valueOf(i+1));

		// Find and remove partition
		int index = 0;
		byte[] segment = null;
		while (!Arrays.equals(partition,segment) && index < payload.length-2) {
			segment = Arrays.copyOfRange(payload, index, index+3);
			index++;
		} 

		// For debugging
		if (index == payload.length-2) {
			System.out.println("ERROR ~~ partition not found in payload.");
			System.exit(0);
		}


		// Extract encrypted key and message
		byte[] encryptedKey = Arrays.copyOf(payload, index-1);	
		byte[] encryptedMessage = Arrays.copyOfRange(payload, index+2, payload.length);

		// Decrypt the key with RSA
		BigInteger bigIntKey = new BigInteger(encryptedKey);
		BigInteger bigIntResult = bigIntKey.modPow(k_d,k_n);	
		byte[] decryptedKey = bigIntResult.toByteArray();

		// Use the decrypted key to decrypt the message with AES
		byte[] decryptedMessage = encryptAES(encryptedMessage,  decryptedKey, false);
	
		ComMethods.report("Decrypting done. The message is \""+new String(decryptedMessage)+"\".", simMode);		
		ComMethods.report("", simMode);
		return decryptedMessage;
	}



	// Given the key, encrypt/decrypts message using AES, with PKCS#7 padding
	// Encrypts if encryption = true, Decrypts if encryption = false
	public static byte[] encryptAES(byte[] message, byte[] key, boolean encryption) {
		String algorithm = "AES/CBC/NoPadding";
		byte[] msg = message;

		// Add padding if encrypting
		if (encryption) {
			msg = addPadding(msg); 
		}

		byte[] output = new byte[0];
		try {	
			SecretKeySpec aesKey = new SecretKeySpec(key, 0, 16, "AES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());

            		Cipher cipher = Cipher.getInstance(algorithm);

			if (encryption) { 
				cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
			}

			// Perform the encryption
            		output = cipher.doFinal(msg);	

			if (!encryption) {
				output = removePadding(output);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}

		return output;
	}


	// Adds padding to a message using PKCS#7 padding method
	private static byte[] addPadding(byte[] message) {
		if (message.length % 16 != 0) {
			int paddingNeeded = 16*(1+message.length/16) - message.length;
			byte bytePadding = Byte.valueOf(String.valueOf(paddingNeeded));
			byte[] newMessage = new byte[message.length+paddingNeeded];

			for (int i=0; i<message.length; i++) {
				newMessage[i] = message[i];
			}
			for (int i=message.length; i<paddingNeeded + message.length; i++) {
				newMessage[i] = bytePadding;
			}
			return newMessage;
		} else {
			return message;
		}
	}


	// Discards padding from a message using PKCS#7 padding method
	private static byte[] removePadding(byte[] message) {
		int paddedBytes = (new Byte (message[message.length-1])).intValue();
		
		// Determine whether or not padding was used for this message
		boolean wasPadded = paddedBytes < 16 && paddedBytes > 0; 
		for (int i=1; i<paddedBytes && wasPadded; i++) {
			wasPadded = (new Byte(message[message.length-i-1])).intValue() == paddedBytes;
		}

		if (wasPadded) {
			byte[] originalMessage = new byte[message.length-paddedBytes];
			for (int i=0; i<originalMessage.length; i++) {
				originalMessage[i] = message[i];
			}
			return originalMessage;
		} else {
			return message;
		}
	}
}

