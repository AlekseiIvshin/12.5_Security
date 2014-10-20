package security;

public interface ParamProvider<T> {

	T getValue(String name);
	void setValue(String name,T value);
}
