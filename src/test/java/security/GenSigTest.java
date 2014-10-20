package security;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

public class GenSigTest {

	@Test
	public void testSign() {
		GenSig genSig = new GenSig();
		File test = new File("src/test/resources/testData.txt");
		File targetDirectory = new File("src/test/resources/");
		genSig.sign(test,targetDirectory);
	}

}
