package security;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SigFile {

	static final Logger logger = LoggerFactory.getLogger(SigFile.class);

	private KeyReader keyReader;
	private ParamProvider<String> params;

	public SigFile(ParamProvider<String> params) {
		this.params = params;
	}

	public void sigFile(File file, File keyStore, File targetDirectory) {
		if(!targetDirectory.exists()){
			targetDirectory.mkdir();
		}
		String storePassword = params.getValue("store password");
		try {
			keyReader = new KeyReaderImpl(keyStore, storePassword);
		} catch (NoSuchAlgorithmException | CertificateException
				| KeyStoreException | IOException e1) {
			logger.error("Key store read error", e1);
			return;
		}

		String alias = params.getValue("alias");
		String keyPassword = params.getValue("key password");
		PrivateKey privateKey;
		try {
			privateKey = keyReader.getPrivateKey(alias, keyPassword);
		} catch (UnrecoverableKeyException | KeyStoreException
				| NoSuchAlgorithmException e1) {
			logger.error("Private key store read error", e1);
			return;
		}
		PublicKey publicKey;
		try {
			publicKey = keyReader.getPublicKey(alias);
		} catch (KeyStoreException e1) {
			logger.error("Public key store read error", e1);
			return;
		}

		
		sigFile(privateKey, keyStore, targetDirectory);
		writePublicKey(publicKey,targetDirectory);
	}

	private void sigFile(PrivateKey privateKey, File data, File targetDirectory) {
		Signature dsa;

		try {
			dsa = Signature.getInstance(privateKey.getAlgorithm(), "SUN");
			dsa.initSign(privateKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException e) {
			logger.error("Init sign error", e);
			return;
		}
		FileInputStream inputStream;
		try {
			inputStream = new FileInputStream(data);
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
			fileOutputStream = new FileOutputStream(targetDirectory
					+ File.separator + "sig");
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

	}

	private void writePublicKey(PublicKey publicKey, File targetDirectory) {
		byte[] key = publicKey.getEncoded();

		FileOutputStream keyOutputStream;
		try {
			keyOutputStream = new FileOutputStream(targetDirectory
					+ File.separator + "pubKey");
		} catch (FileNotFoundException e) {
			logger.error("File writer stream error", e);
			return;
		}
		try {
			keyOutputStream.write(key);
		} catch (IOException e) {
			logger.error("File writer stream error", e);
			return;
		} finally {
			try {
				keyOutputStream.close();
			} catch (IOException e) {
				logger.error("Can't close write stream", e);
			}
		}
	}
}
