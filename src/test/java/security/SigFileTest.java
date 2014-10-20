package security;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

public class SigFileTest {

	@Test
	public void testSigFile() {
		ParamProvider<String> params = new ConsoleReader();
		params.setValue("store password", "storepass");
		params.setValue("key password", "signpass");
		params.setValue("alias", "sign");
		SigFile sigFile = new SigFile(params);
		// store pass = storepass
		// sign pass = signpass
		File dataFile = new File("src/test/resources/testData.txt");
		File keyStore = new File("src/test/resources/signstore");
		File targetDirectory = new File("src/test/resources/target/");
		sigFile.sigFile(dataFile, keyStore,targetDirectory);
	}

}
