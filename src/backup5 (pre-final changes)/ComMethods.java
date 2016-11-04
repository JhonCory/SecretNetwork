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

// Methods common to both Users and the SecretServer objects
public class ComMethods {
	// Given message, sender, and msg #, prepares a "regular" payload
	public static byte[] preparePayload(byte[] sender, byte[] message, int msgNum, byte[] key, boolean simMode) {
		byte[] msgNumBytes = String.valueOf(msgNum).getBytes();
		byte[] ptxtPayload = concatByteArrs(message, sender, msgNumBytes);
//
		report("Plaintext payload to be sent to SecretServer will be '"+ptxtPayload+"'.", simMode);
//
		byte[] ctxtPayload = encryptAES(ptxtPayload, key, true); // encrypt
		return ctxtPayload;
	}

	// Given "regular" payload, sender, and msg #, returns message in payload
	public static byte[] processPayload(byte[] sender, byte[] payload, int msgNum, byte[] key, boolean simMode) {
		byte[] decipheredPL = encryptAES(payload, key, false); // decrypt
//
		report("Payload received contains '"+new String(decipheredPL)+"'.", simMode);
		System.out.println("Deciphered Payload: ");
		charByChar(decipheredPL,true);
//
		
		byte[] msgNumBytes = String.valueOf(msgNum).getBytes();

		byte[] expectedEnd = concatByteArrs(sender, msgNumBytes);

//
		System.out.println("sender = "+new String(sender));
		System.out.println("sender in bytes:");
		charByChar(sender,true);
		System.out.println("msgNum = "+msgNum);
		System.out.println("msgNumBytes = "+new String(msgNumBytes));
		System.out.println("msgNumBytes in bytes:");
		charByChar(msgNumBytes,true);
		System.out.println("expectedEnd = "+new String(expectedEnd));
		System.out.println("expectedEnd in bytes:");
		charByChar(expectedEnd,true);
//

		int messageLength = decipheredPL.length - expectedEnd.length;
		if (!Arrays.equals(Arrays.copyOfRange(decipheredPL, messageLength, decipheredPL.length), expectedEnd)) {
			handleBadResp();
		} 
		byte[] message = Arrays.copyOf(decipheredPL, messageLength);
		return message;
	}




	// Encrypts message using hybrid RSA encryption with public key <k_n, k_e>
	// Hybrid RSA encryption works by having the encryptor generate a random 
	// 128-bit symmetric key and appending it to the front of the payload
	public static byte[] encryptRSA(byte[] message, BigInteger k_n, BigInteger k_e) {

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
		String throwawayKeyString = randomString.substring(0,16);
		byte[] throwawayKey = throwawayKeyString.getBytes();
//		String throwawayKey = DatatypeConverter.printBase64Binary(keyInBytes);


//
		System.out.println("=================================");
		System.out.println("unEncryptedKey = "+new String(throwawayKey));
		System.out.println("unEncryptedMsg = "+new String(message));
		System.out.println("=================================");
//



		// Encrypt message using AES and throwaway key
		byte[] encryptedMsg = encryptAES(message, throwawayKey, true);

		// Encrypt key using RSA
		BigInteger bigIntKey = new BigInteger(throwawayKey); 
//
		if (bigIntKey.compareTo(k_n) != -1) {
			System.out.println("ERROR ~~ bigIntKey is too big!");
			System.out.println("bigIntKey = "+bigIntKey);
			System.out.println("k_n = "+k_n);
			System.exit(0);
		}
//


		BigInteger bigIntResult = bigIntKey.modPow(k_e, k_n);
		byte[] encryptedKey = bigIntResult.toByteArray();

//
		System.out.println();
		System.out.println("RSA ENCRYPTION STEPS");
		System.out.println("unencryptedKey:");
		charByChar(throwawayKey,true);
		System.out.println("bigIntUnencryptedKey = "+bigIntKey);
		System.out.println("bigIntResult = "+bigIntResult);
		System.out.println("encryptedKey:");
		charByChar(encryptedKey,true);
		System.out.println();
//

		// Partition will be made of three consecutive bytes with vals 1,2,3
		byte[] partition = new byte[3];
		for (int i=0; i<partition.length; i++) 
			partition[i] = Byte.valueOf(String.valueOf(i+1));
		
		// Create payload of encrypted key, partition, and encrypted msg
		byte[] payload = concatByteArrs(encryptedKey,partition,encryptedMsg);

		report("Encrypting done.", true);
//
		System.out.println("=================================");
		System.out.println("encryptedKey = "+new String(encryptedKey));
		System.out.println("encryptedMsg = "+new String(encryptedMsg));
		System.out.println("=================================");
		System.out.println("PAYLOAD = "+payload);
		System.out.println();
		System.out.println();
//
		return payload;
	}



	// Decrypts message using hybrid RSA with private key <k_n, k_d>
	public static byte[] decryptRSA(byte[] payload, BigInteger k_n, BigInteger k_d) {

//
		System.out.println();
		System.out.println();
//		
		report("Decrypting '"+payload+"' with hybrid RSA with k_n = "+k_n+", k_d = "+k_d+"...", true);

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

//
		System.out.println("partition: ");
		charByChar(partition,true);
		System.out.println("payload: ");
		charByChar(payload,true);

//


		if (index == payload.length-2) {
			System.out.println("ERROR ~~ partition not found in payload.");
			System.exit(0);
		}

		// Extract encrypted key and message
		byte[] encryptedKey = Arrays.copyOf(payload, index-1);	
		byte[] encryptedMessage = Arrays.copyOfRange(payload, index+2, payload.length);

//
		System.out.println("=================================");
		System.out.println("encryptedKey = "+new String(encryptedKey));
		System.out.println("encryptedMessage = "+new String(encryptedMessage));
		System.out.println("=================================");
//

		// Decrypt the key with RSA
		BigInteger bigIntKey = new BigInteger(encryptedKey);
		BigInteger bigIntResult = bigIntKey.modPow(k_d,k_n);	
		byte[] decryptedKey = bigIntResult.toByteArray();

//
		System.out.println();
		System.out.println("RSA DECRYPTION STEPS");
		System.out.println("encryptedKey:");
		charByChar(encryptedKey,true);
		System.out.println("bigIntEncryptedKey = "+bigIntKey);
		System.out.println("bigIntResult = "+bigIntResult);
		System.out.println("decryptedKey:");
		charByChar(decryptedKey,true);
		System.out.println();
//


		// Use the decrypted key to decrypt the message with AES
		byte[] decryptedMessage = encryptAES(encryptedMessage,  decryptedKey, false);

//
		System.out.println("=================================");
		System.out.println("decryptedKey = "+new String(decryptedKey));
		System.out.println("decryptedMessage = "+new String(decryptedMessage));
		System.out.println("=================================");
//
	
		report("Decrypting done. The message is "+decryptedMessage+".", true);
		return decryptedMessage;
	}



	// Given the key, encrypt/decrypts message using AES, with PKCS#7 padding
	// Encrypts if encryption = true, Decrypts if encryption = false
	public static byte[] encryptAES(byte[] message, byte[] key, boolean encryption) {
		String algorithm = "AES/CBC/NoPadding";
		byte[] msg = message;

//
		System.out.println();
		if (encryption) { System.out.println("!!! ENCRYPT AES !!!"); }
		else { System.out.println("!!! DECRYPT AES !!!"); }
		System.out.println("message = "+message);
		System.out.println("message: ");
		charByChar(message,true);
		System.out.println("key: ");
		charByChar(key,true);
//

		// Add padding if encrypting
		if (encryption) {
			msg = addPadding(msg); 
		}

//

		System.out.println("msg post addition of padding = "+DatatypeConverter.printBase64Binary(msg));
		System.out.println("msg post addition of padding = "+new String(msg));
		System.out.println("msg.length post addition of padding = "+msg.length);
		System.out.println();
//



		byte[] output = new byte[0];
		try {	
//
			System.out.println("key has "+key.length+" bytes.");
//
			SecretKeySpec aesKey = new SecretKeySpec(key, 0, 16, "AES");
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
			System.out.println();
			System.out.println("msg before encryption, in bytes:");
			charByChar(msg,true);
			System.out.println("Encrypting/Decrypting...");
//

			// Perform the encryption
            		output = cipher.doFinal(msg);	

//
			System.out.println("msg encrypted/decrypted into 'output'");
			System.out.println("output = "+new String(output));
			System.out.println("output = "+DatatypeConverter.printBase64Binary(output));
			System.out.println("msg after encryption/decryption, in bytes:");
			charByChar(output,true);
//


			if (!encryption) {
				output = removePadding(output);
			}



//
			System.out.println("Here is final output, with each byte value:");
			charByChar(output, true);		
//
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}

//
		System.out.println();
//
		return output;
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
		System.out.println("message, in bytes, was the following: ");
		charByChar(message,true);
		System.out.println("padded message, in bytes, is the following: ");
		charByChar(newMessage,true);
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
	public static void charByChar(byte[] arr, boolean hex) {
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


//
	// Given array of bytes, returns array of first 16 bytes
	private static byte[] getFirst16(byte[] oldArr) {
		byte[] newArr = new byte[16];
		for (int i=0; i<16; i++) {
			newArr[i] = oldArr[i];
		}
		return newArr;
	}
//


	// Randomly generates a 128-bit array of bytes
	public static byte[] genNonce() {
		String randoms = UUID.randomUUID().toString();
		byte[] randomBytes = randoms.getBytes();
		//byte[] randomBytes = DatatypeConverter.parseBase64Binary(randoms);
		byte[] keyInBytes = getFirst16(randomBytes);
		return keyInBytes;

		// Generate 128-bit throwaway key
		//String randomString = new String(randomBytes);
//		String randomString = DatatypeConverter.printBase64Binary(randomBytes);

//
//		if (randomString.startsWith("-")) {
//			randomString = randomString.substring(1,randomString.length());
//		}
//
//		String throwawayKey = randomString.substring(0,16);
//		String throwawayKey = DatatypeConverter.printBase64Binary(keyInBytes);

/*
		byte[] backToBytes = DatatypeConverter.parseBase64Binary(throwawayKey);
		System.out.println("backToBytes = "+new String(backToBytes));
		System.out.println("backToBytes = "+DatatypeConverter.printBase64Binary(backToBytes));
		System.out.println("msg to be encrypted/decrypted = "+DatatypeConverter.printBase64Binary(backToBytes));
		System.out.println("msg in bytes is the following: ");
		charByChar(backToBytes,true);
		System.out.println("nonce.length = "+throwawayKey.length());
		System.out.println("nonce in bytes.length = "+keyInBytes.length);
		System.out.println();
*/

//		return throwawayKey;
	}


	// Concatenates two arrays of bytes
	public static byte[] concatByteArrs(byte[] a, byte[] b) {
   		int aLen = a.length;
   		int bLen = b.length;
   		byte[] c= new byte[aLen+bLen];
   		System.arraycopy(a, 0, c, 0, aLen);
   		System.arraycopy(b, 0, c, aLen, bLen);
   		return c;
	}

	// Concatenates three arrays of bytes
	public static byte[] concatByteArrs(byte[] a, byte[] b, byte[] c) {
		return concatByteArrs(concatByteArrs(a,b),c);
	}
}

