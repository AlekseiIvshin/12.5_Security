package security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


public class KeyReaderImpl implements KeyReader {

	private KeyStore keyStore;
	

	public KeyReaderImpl(File store, String storePassword) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		keyStore = KeyStore.getInstance("jks");
		FileInputStream fis = new FileInputStream(store);
		keyStore.load(fis, storePassword.toCharArray());
		fis.close();
	}
	

	@Override
	public PrivateKey getPrivateKey(String alias, String keyPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		Key key = keyStore.getKey(alias, keyPassword.toCharArray());
		if (key instanceof PrivateKey) {
			return (PrivateKey) key;
		} else {
			return null;
		}
	}

	@Override
	public PublicKey getPublicKey(String alias) throws KeyStoreException {
		Certificate cert = keyStore.getCertificate(alias);
		return cert.getPublicKey();
	}

}
