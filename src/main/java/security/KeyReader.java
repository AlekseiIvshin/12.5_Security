package security;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;

public interface KeyReader {

	PrivateKey getPrivateKey(String alias, String keyPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException;

	PublicKey getPublicKey(String alias) throws KeyStoreException;

}
