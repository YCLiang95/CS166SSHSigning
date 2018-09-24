package proj3;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

public class BlobSigner {
	
	
    /**
     * generate a signature file (dstSignatureFile) for fileToSign using
     * sshPrivateKeyFile.
     *
     * @param fileToSign the file containing the data to be signed.
     * @param sshPrivateKeyFile the ssh private key file with the signing key
     *                         to use.
     * @param dstSignatureFile the file to write the generated signature to.
     *                         the signature will be base64 encoded.
     */
    public static void signFile(
            File fileToSign, File sshPrivateKeyFile, File dstSignatureFile
    ) {
    	try {
    	byte[] plainText = LoadFile(fileToSign);
    	PrivateKey privateKey = LoadPrivate(sshPrivateKeyFile);
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(plainText);
		byte[] sig = Base64.getEncoder().encode(signature.sign());
		Files.write(Paths.get(dstSignatureFile.getAbsolutePath()), sig);
		dstSignatureFile.canWrite();
    	} catch (Exception e) {
    		System.out.print(e.getMessage());
    	}
    }
    
    //Code provided by the assignment
    private static ArrayList<byte[]> decodeLVBytes(byte toDecode[]) {
    	ArrayList<byte[]> list = new ArrayList<>();
    	ByteBuffer bb = ByteBuffer.wrap(toDecode);
    	while (bb.position() < bb.limit()) {
    		int len = bb.getInt();
    		byte bytes[] = new byte[len];
    		bb.get(bytes);
    		list.add(bytes);
    	}
    	return list;
    }
    
    //Derdecode obtained from approvded stack overflow answer
    //https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/30929175#30929175
    private static PrivateKey DerDecode(byte[] key) {
    	try {
    		DerInputStream der = new DerInputStream (key);
    		DerValue[] seq = der.getSequence(0);
            BigInteger modulus = seq[1].getBigInteger();
            BigInteger publicExp = seq[2].getBigInteger();
            BigInteger privateExp = seq[3].getBigInteger();
            BigInteger prime1 = seq[4].getBigInteger();
            BigInteger prime2 = seq[5].getBigInteger();
            BigInteger exp1 = seq[6].getBigInteger();
            BigInteger exp2 = seq[7].getBigInteger();
            BigInteger crtCoef = seq[8].getBigInteger();
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
    		KeyFactory factory = KeyFactory.getInstance("RSA");
    		return factory.generatePrivate(keySpec);
    	} catch (Exception e) {
    		System.out.println(e.getMessage());
    	}
    	return null;
    }
    
    //Load the private key file
    public static PrivateKey LoadPrivate(File sshPrivateKeyFile)  {
    	try {
    		Path path = Paths.get(sshPrivateKeyFile.getAbsolutePath());
    		String s = new String(Files.readAllBytes(path));
    		s = s.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    		s = s.replace("-----END RSA PRIVATE KEY-----", "");
    		s = s.replace("\n", "").replace("\r", "");
    		//System.out.print(s);
    		byte[] key = Base64.getDecoder().decode(s);
    		return  DerDecode(key);
    	} catch (Exception e) {
    		System.out.println(e.getMessage());
    		}
    	return null;
    }
    
    //Just load a file into byte[]
    public static byte[] LoadFile(File file) throws IOException {
    	Path path = Paths.get(file.getAbsolutePath());
    	return Files.readAllBytes(path);
    }

    //Load the public key file
    private static PublicKey LoadPublic(File file) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	Path path = Paths.get(file.getAbsolutePath());
    	String s = new String(Files.readAllBytes(path));
    	s = s.split(" ")[1];
       	ArrayList<byte[]> t = decodeLVBytes(Base64.getDecoder().decode(s));
    	
    	BigInteger modules = new BigInteger(1, t.get(2));
    	BigInteger expo = new BigInteger(1, t.get(1));
    	KeyFactory factory = KeyFactory.getInstance("RSA");	
    	return factory.generatePublic(new RSAPublicKeySpec(modules, expo));
    }
    

    /**
     * validate the signature file (signatureFile) corresponding to
     * signedFile using the public key in sshPublicKeyFile.
     * @param signedFile the file containing the data that was signed.
     * @param sshPublicKeyFile the file containing the public key corresponds
     *                        to the private key that was used to sign
     *                         signedFile.
     * @param signatureFile the base64 encoded signature generated with the
     *                      private key that corresponds to sshPublicKeyFile
     *                      over the data in the signedFile.
     * @return true if the signature is valid.
     */
    public static boolean validateSignature(
            File signedFile, File sshPublicKeyFile, File signatureFile
    ) { 
    	try {
    		PublicKey publicKey = LoadPublic(sshPublicKeyFile);
    		Signature signature = Signature.getInstance("SHA256withRSA");
    		signature.initVerify(publicKey);

    		byte[] signatureByte = Base64.getDecoder().decode(LoadFile(signatureFile));
    		byte[] signedFileByte = LoadFile(signedFile);
    		signature.update(signedFileByte);
    		return signature.verify(signatureByte);
    		//PrivateKey privateKey = LoadPrivate(sshPrivateKeyFile);
    	} catch (Exception e) {
    		System.out.println(e.getMessage());
    	}
    	
    	return false; 
    }
    
    //Testing main function
    //public static void main (String args[]) {
    //	signFile(new File("simpleFile"), new File("id_test"), new File("simpleFile2.sig"));
    //	boolean t = validateSignature(new File("simpleFile"), new File("id_test.pub"), new File("simpleFile2.sig"));
    //	System.out.println(t);
    //}
}
