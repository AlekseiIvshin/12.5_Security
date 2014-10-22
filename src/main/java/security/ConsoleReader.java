package security;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class ConsoleReader implements ParamProvider<String> {

	Map<String, String> values;
	Scanner scanner;

	public ConsoleReader() {
		values = new HashMap<String, String>();
		scanner = new Scanner(System.in);
	}

	@Override
	public String getValue(String name) {
		if (!values.containsKey(name)) {
			System.out.println("Enter value for '" + name + "'");
			String value = scanner.next();
			values.put(name, value);
		}
		return values.get(name);
	}

	@Override
	public void setValue(String name, String value) {
		values.put(name, value);
		
	}

}
