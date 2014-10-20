package security;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GenSig {

	static final Logger logger = LoggerFactory.getLogger(GenSig.class);

	public void sign(File f,File targetDirectory) {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.error("KeyPairGeneretor initialize error", e);
			return;
		}
		SecureRandom secureRandom;
		try {
			secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.error("SecureRandom initialize error", e);
			return;
		}

		keyGen.initialize(1024, secureRandom);

		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey publ = pair.getPublic();
		Signature dsa;
		try {
			dsa = Signature.getInstance("SHA1withDSA", "SUN");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.error("Signature initialize error", e);
			return;
		}

		try {
			dsa.initSign(priv);
		} catch (InvalidKeyException e) {
			logger.error("Init sign error", e);
			return;
		}

		FileInputStream inputStream;
		try {
			inputStream = new FileInputStream(f);
		} catch (FileNotFoundException e1) {
			logger.error("Input file error", e1);
			return;
		}
		BufferedInputStream bufferedInputStream = new BufferedInputStream(
				inputStream);
		byte[] buffer = new byte[1024];
		int len;
		try {
			while ((len = bufferedInputStream.read(buffer)) >= 0) {
				dsa.update(buffer, 0, len);
			}
		} catch (SignatureException | IOException e) {
			logger.error("Encode error", e);
		} finally {
			try {
				bufferedInputStream.close();
			} catch (IOException e) {
				logger.error("Can't close read stream", e);
			}
		}
		byte[] realSig;
		try {
			realSig = dsa.sign();
		} catch (SignatureException e) {
			logger.error("Can't close read stream", e);
			return;
		}

		FileOutputStream fileOutputStream;
		try {
			fileOutputStream = new FileOutputStream(targetDirectory+File.separator+"sig");
		} catch (FileNotFoundException e) {
			logger.error("File writer stream error", e);
			return;
		}
		try {
			fileOutputStream.write(realSig);
		} catch (IOException e) {
			logger.error("File writer stream error", e);
		} finally {
			try {
				fileOutputStream.close();
			} catch (IOException e) {
				logger.error("Can't close write stream", e);
			}
		}

		byte[] key = publ.getEncoded();
		
		FileOutputStream keyOutputStream;
		try {
			keyOutputStream = new FileOutputStream(targetDirectory+File.separator+"suepk");
		} catch (FileNotFoundException e) {
			logger.error("File writer stream error", e);
			return;
		}
		try {
			keyOutputStream.write(key);
		} catch (IOException e) {
			logger.error("File writer stream error", e);
			return;
		}finally {
			try {
				keyOutputStream.close();
			} catch (IOException e) {
				logger.error("Can't close write stream", e);
			}
		}
	}
}
