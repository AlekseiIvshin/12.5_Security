package security;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VerSig {

	static final Logger logger = LoggerFactory.getLogger(VerSig.class);

	public boolean verify(File dataFile, File publicKey, File signatureFile) {

		PublicKey pubKey;
		try {
			pubKey = getPublicKey(publicKey);
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| InvalidKeySpecException | IOException e1) {
			logger.error("Get public key", e1);
			return false;
		}

		byte[] sigToVerify;
		try {
			sigToVerify = getSignature(signatureFile);
		} catch (IOException e2) {
			logger.error("Get file signature", e2);
			return false;
		}
		Signature sig;
		try {
			sig = getDataFileSignature(dataFile, pubKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException | IOException e1) {
			logger.error("Get file signature", e1);
			return false;
		}

		try {
			return sig.verify(sigToVerify);
		} catch (SignatureException e) {
			logger.error("Signature exception", e);
			return false;
		}
	}

	private PublicKey getPublicKey(File publicKeyFile)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			IOException, InvalidKeySpecException {
		FileInputStream keyFIS = new FileInputStream(publicKeyFile);

		byte[] encKey;
		try {
			encKey = new byte[keyFIS.available()];
			keyFIS.read(encKey);
		} finally {

			try {
				keyFIS.close();
			} catch (IOException e) {
				logger.error("Key file read closing error", e);
			}
		}

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		return keyFactory.generatePublic(pubKeySpec);
	}

	public byte[] getSignature(File signatureFile) throws IOException {

		FileInputStream sigFIS = new FileInputStream(signatureFile);

		byte[] sigToVerify;
		try {
			sigToVerify = new byte[sigFIS.available()];
			sigFIS.read(sigToVerify);
		} finally {

			try {
				sigFIS.close();
			} catch (IOException e) {
				logger.error("Key file read closing error", e);
			}
		}
		return sigToVerify;
	}

	public Signature getDataFileSignature(File dataFile, PublicKey publicKey)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException, IOException {
		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
		sig.initVerify(publicKey);

		FileInputStream dataFIS = new FileInputStream(dataFile);
		BufferedInputStream bufIn = new BufferedInputStream(dataFIS);

		byte[] buffer = new byte[1024];
		int len;
		try {
			while (bufIn.available() != 0) {
				len = bufIn.read(buffer);
				sig.update(buffer, 0, len);
			}
		} finally {
			try {
				bufIn.close();
			} catch (IOException e) {
				logger.error("Can't close data file read stream", e);
			}
		}
		return sig;
	}
}
