package security;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

public class VerSigTest {

	@Test
	public void testVerify() {
		VerSig verSig = new VerSig();
		File dataFile = new File("src/test/resources/testData.txt");
		File publicKeyFile = new File("src/test/resources/suepk");
		File singFile = new File("src/test/resources/sig");
		verSig.verify(dataFile, publicKeyFile, singFile);
	}

}
