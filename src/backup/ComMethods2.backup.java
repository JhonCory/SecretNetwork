import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

// Methods common to both Users and the SecretServer objects
public class ComMethods {
	// Given message, sender, and msg #, prepares a "regular" payload
	public static String preparePayload(String sender, String message, int msgNum, String key, boolean simMode) {
		String payload = message + sender + msgNum;
		report("Payload to be sent to SecretServer will contain '"+payload+"'.", simMode);
		payload = encryptAES(payload, key, true);
		return payload;
	}

	// Given "regular" payload, sender, and msg #, returns message in payload
	public static String processPayload(String sender, String payload, int msgNum, String key, boolean simMode) {
		String decipheredPL = encryptAES(payload, key, false);
		report("Payload received contains '"+decipheredPL+"'.", simMode);

		if (!(decipheredPL.endsWith(sender+msgNum))) {
			handleBadResp();
		} 
		int endOfMessage = decipheredPL.indexOf(sender+msgNum);
		return decipheredPL.substring(0, endOfMessage);
	}




	// Encrypts message using hybrid RSA encryption with public key <k_n, k_e>
	// Hybrid RSA encryption works by having the encryptor generate a random 
	// 128-bit symmetric key and appending it to the front of the payload
	public static String encryptRSA(String message, BigInteger k_n, BigInteger k_e) {

//
		System.out.println();
//
		report("Encrypting "+message+" with hybrid RSA with k_n = "+k_n+", k_e = "+k_e+"...", true);

		String randoms = UUID.randomUUID().toString();
		byte[] randomBytes = randoms.getBytes();
//		byte[] randomBytes = DatatypeConverter.parseBase64Binary(randoms);
//		byte[] keyInBytes = getFirst16(randomBytes);

		// Generate 128-bit throwaway key
		String randomString = new String(randomBytes);
//		String randomString = DatatypeConverter.printBase64Binary(randomBytes);

//
		if (randomString.startsWith("-")) {
			randomString = randomString.substring(1,randomString.length());
		}
//
		String throwawayKey = randomString.substring(0,16);
//		String throwawayKey = DatatypeConverter.printBase64Binary(keyInBytes);


//
		System.out.println("=================================");
		System.out.println("unEncryptedKey = "+throwawayKey);
		System.out.println("unEncryptedMsg = "+message);
		System.out.println("=================================");
//



		// Encrypt message using AES and throwaway key
		String encryptedMsg = encryptAES(message, throwawayKey, true);

		// Encrypt key using RSA
		byte[] keyInBytes = throwawayKey.getBytes();
//		byte[] keyInBytes = DatatypeConverter.parseBase64Binary(throwawayKey);
		BigInteger bigIntKey = new BigInteger(keyInBytes); 
//
		if (bigIntKey.compareTo(k_n) != -1) {
			System.out.println("ERROR ~~ bigIntKey is too big!");
			System.out.println("bigIntKey = "+bigIntKey);
			System.out.println("k_n = "+k_n);
			System.exit(0);
		}
//


		BigInteger bigIntResult = bigIntKey.modPow(k_e, k_n);
   		String encryptedKey = bigIntResult.toString();

		// Create payload of encrypted key followed by encrypted msg
		String payload = encryptedKey + "///" + encryptedMsg;

		report("Encrypting done.", true);
//
		System.out.println("=================================");
		System.out.println("encryptedKey = "+encryptedKey);
		System.out.println("encryptedMsg = "+encryptedMsg);
		System.out.println("=================================");
		System.out.println("PAYLOAD = "+payload);
		System.out.println();
		System.out.println();
//
		return payload;
	}




	// Decrypts message using hybrid RSA with private key <k_n, k_d>
	public static String decryptRSA(String payload, BigInteger k_n, BigInteger k_d) {

//
		System.out.println();
		System.out.println();
//		
		report("Decrypting '"+payload+"' with hybrid RSA with k_n = "+k_n+", k_d = "+k_d+"...", true);

		// Split payload into the RSA-encrypted key and AES-encrypted message
		int x = payload.indexOf("///");
		String encryptedKey = payload.substring(0,x);	
		String encryptedMessage = payload.substring(x+3,payload.length());

//
		System.out.println("=================================");
		System.out.println("encryptedKey = "+encryptedKey);
		System.out.println("encryptedMessage = "+encryptedMessage);
		System.out.println("=================================");
//

		// Decrypt the key with RSA
		BigInteger bigIntKey = new BigInteger(encryptedKey);
		BigInteger bigIntResult = bigIntKey.modPow(k_d,k_n);	
		byte[] decryptedKeyInBytes = bigIntResult.toByteArray();
    		String decryptedKey = new String(decryptedKeyInBytes);

		// Use the decrypted key to decrypt the message with AES
		String decryptedMessage = encryptAES(encryptedMessage,  decryptedKey, false);

//
		System.out.println("=================================");
		System.out.println("decryptedKey = "+decryptedKey);
		System.out.println("decryptedMessage = "+decryptedMessage);
		System.out.println("=================================");
//
	
		report("Decrypting done. The message is "+decryptedMessage+".", true);
		return decryptedMessage;
	}


	// Given the key, encrypt/decrypts message using AES, with PKCS#7 padding
	// Encrypts if encryption = true, Decrypts if encryption = false
	public static String encryptAES(String message, String key, boolean encryption) {
		String algorithm = "AES/CBC/NoPadding";

//		byte[] msg = message.getBytes();
		byte[] msg = DatatypeConverter.parseBase64Binary(message);


//
		byte[] msg2 = message.getBytes();
//



//
		System.out.println();
		if (encryption) { System.out.println("!!! ENCRYPT AES !!!"); }
		else { System.out.println("!!! DECRYPT AES !!!"); }
		System.out.println("message = "+message);
		System.out.println("key = "+key);
		System.out.println("msg to be encrypted/decrypted = "+new String(msg));
		System.out.println("msg to be encrypted/decrypted = "+DatatypeConverter.printBase64Binary(msg));

		System.out.println("msg in bytes is the following: ");
		charByChar(msg,true);
		System.out.println();

		System.out.println("msg2 to be encrypted/decrypted = "+new String(msg));
		System.out.println("msg2 to be encrypted/decrypted = "+DatatypeConverter.printBase64Binary(msg2));
		System.out.println("msg2 in bytes is the following: ");
		charByChar(msg2,true);
		System.out.println("msg2.length = "+msg2.length);
		System.out.println();
		System.out.println();
//

		// Add padding if encrypting
		if (encryption) {
			msg = addPadding(msg); 
		}

//

		System.out.println("MSG CHECK = "+DatatypeConverter.printBase64Binary(msg));
		System.out.println("msg post addition of padding = "+new String(msg));
		System.out.println("msg post addition of padding = "+DatatypeConverter.printBase64Binary(msg));
		System.out.println("msg.length post addition of padding = "+msg.length);
		System.out.println();
//



		String outputText = new String();
		try {
			byte[] keyBytes = key.getBytes(); 
//			byte[] keyBytes = DatatypeConverter.parseBase64Binary(key);		


//
			System.out.println("keyBytes has "+keyBytes.length+" bytes.");
//
			SecretKeySpec aesKey = new SecretKeySpec(keyBytes, 0, 16, "AES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());

            		Cipher cipher = Cipher.getInstance(algorithm);

			if (encryption) { 
				cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
			}

//

			System.out.println("again, msg is "+new String(msg));
			System.out.println("again, msg is = "+DatatypeConverter.printBase64Binary(msg));
			System.out.println("again, msg.length = "+msg.length);
			System.out.println("Encrypting/Decrypting...");
			System.out.println();
		System.out.println("MSG CHECK = "+DatatypeConverter.printBase64Binary(msg));
			System.out.println("msg before encryption, in bytes:");
			charByChar(msg,true);
//

			// Perform the encryption
            		byte[] output = cipher.doFinal(msg);	
//
		System.out.println("MSG CHECK = "+DatatypeConverter.printBase64Binary(output));
			System.out.println("msg encrypted/decrypted into 'output'");
//			System.out.println("msg after encryption/decryption, in bytes:");
//			charByChar(output,true);
			System.out.println("output = "+new String(output));
			System.out.println("output = "+DatatypeConverter.printBase64Binary(output));
			System.out.println("output.length = "+output.length);
//		
			if (!encryption) {
				output = removePadding(output);
			}

//			
		System.out.println("MSG CHECK = "+DatatypeConverter.printBase64Binary(output));
			System.out.println("output after padding removal, in bytes:");
			charByChar(output,true);
			System.out.println("final output = "+new String(output));
			System.out.println("final output = "+DatatypeConverter.printBase64Binary(output));
			System.out.println("final output.length = "+output.length);
//

			outputText = DatatypeConverter.printBase64Binary(output);
//			outputText = new String(output);

//
//			byte[] outputBackToBytes = outputText.getBytes();
			byte[] outputBackToBytes = DatatypeConverter.parseBase64Binary(outputText);
			System.out.println("outputBackToBytes = "+new String(outputBackToBytes));
			System.out.println("outputBackToBytes = "+DatatypeConverter.printBase64Binary(outputBackToBytes));
			System.out.println("outputBackToBytes.length = "+outputBackToBytes.length);
//


//
			System.out.println("Here is output, with each byte value:");
			charByChar(output, true);
			System.out.println("Here is outputBackToBytes, with each byte value:");
			charByChar(outputBackToBytes, true);			
//
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}

//
		System.out.println();
//
		return outputText;
	}


	// Adds padding to a message using PKCS#7 padding method
	private static byte[] addPadding(byte[] message) {
//
		System.out.println();
		System.out.println("Adding padding");
//
		if (message.length % 16 != 0) {
			int paddingNeeded = 16*(1+message.length/16) - message.length;
			byte bytePadding = Byte.valueOf(String.valueOf(paddingNeeded));
			byte[] newMessage = new byte[message.length+paddingNeeded];

//
			System.out.println("message.length = "+message.length);
			System.out.println("newMessage.length = "+newMessage.length);
			System.out.println("paddingNeeded = "+paddingNeeded);
//
			for (int i=0; i<message.length; i++) {
				newMessage[i] = message[i];
			}
			for (int i=message.length; i<paddingNeeded + message.length; i++) {
				newMessage[i] = bytePadding;
			}

//
		System.out.println("message was "+DatatypeConverter.printBase64Binary(message));
		System.out.println("newMessage is "+DatatypeConverter.printBase64Binary(newMessage));
		System.out.println("message was "+new String(message));
		System.out.println("newMessage is "+new String(newMessage));
//		System.out.println("message, in bytes, was the following: ");
//		charByChar(message,true);
//		System.out.println("padded message, in bytes, is the following: ");
//		charByChar(newMessage,true);
		System.out.println();
//
			return newMessage;
		} else {
//
			System.out.println("(No padding needed)");
//
			return message;
		}
	}


	// Discards padding from a message using PKCS#7 padding method
	private static byte[] removePadding(byte[] message) {
		int paddedBytes = (new Byte (message[message.length-1])).intValue();
		
//
		System.out.println();
		System.out.println("Removing padding");
//		System.out.println("message is "+DatatypeConverter.printBase64Binary(message));
//		System.out.println("In bytes: ");
//		charByChar(message, true);
//		charByChar(message, false);
//
		// Determine whether or not padding was used for this message
		boolean wasPadded = paddedBytes < 16 && paddedBytes > 0; 
		for (int i=1; i<paddedBytes && wasPadded; i++) {
			wasPadded = (new Byte(message[message.length-i-1])).intValue() == paddedBytes;
		}

//
//		System.out.println();
//

		if (wasPadded) {
//
			System.out.println("Padding found. Padding has size "+paddedBytes);
//
			byte[] originalMessage = new byte[message.length-paddedBytes];
//
//			System.out.println("originalMessage.length = "+originalMessage.length);
//			System.out.println("message.length = "+message.length);
//
			for (int i=0; i<originalMessage.length; i++) {
				originalMessage[i] = message[i];
			}
			return originalMessage;
		} else {
//
			System.out.println("(no padding found)");
//
			return message;
		}
	}



	// Parses .txt file, finds user's name, and returns line below it
	// (i.e. the value corresponding to that user in the file)
	public static String getValueFor(String user, String fname) {
		String line = new String();
		try (BufferedReader br = new BufferedReader(new FileReader(fname))) {
			line = br.readLine();
    			while (!line.startsWith(user)) {
       				line = br.readLine();
    			} 
			line = br.readLine();

			br.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return line;
	}


	// Reads validusers.txt and outputs array of names of valid users
	public static String[] getValidUsers() {
		String[] resultArr = new String[0];
		try {
			BufferedReader in = new BufferedReader(new FileReader("validusers.txt"));
			String str;
		
			List<String> list = new ArrayList<String>();
			while ((str = in.readLine()) != null) {
				list.add(str);
        		}

        		resultArr = list.toArray(new String[0]);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
		return resultArr;
	} 


	// In simulationMode, used to state what's currently happening in the process
	public static void report(String str, boolean simulationMode) {
		if (simulationMode) {
			System.out.println(str);
		}
	}


	// If something goes wrong and security may have been breached, end program
	// NOTE: in real-world scenario, would just end comms or reask for password
	public static void handleBadResp() {
		System.out.println("ERROR ~ unexpected message sent. Exiting program for security reasons.");
		System.exit(0);
	}

//
	// Given array of bytes, prints out each byte, line by line
	// (For debugging only)
	private static void charByChar(byte[] arr, boolean hex) {
		System.out.println("Total # of bytes: "+arr.length);
		for (int i=0; i<arr.length; i++) {
			Byte thisByte = arr[i];
			if (!hex) {
				System.out.print(thisByte.toString());
			} else {
				System.out.print(String.format("%02X ", thisByte));	
			}
			System.out.print(", ");
			if ((i+1) % 16 == 0) {
				System.out.println();
			}
		}
		System.out.println();
	}
//

	// Given array of bytes, returns array of first 16 bytes
	private static byte[] getFirst16(byte[] oldArr) {
		byte[] newArr = new byte[16];
		for (int i=0; i<16; i++) {
			newArr[i] = oldArr[i];
		}
		return newArr;
	}
}

