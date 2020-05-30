/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author Atanu Bhowmick
 *
 */
public class RandomStringGenerator {

	private RandomStringGenerator() {
		// Private Constructor
	}

	private static final List<Character> RANDOM_CHARS;
	
	static {
		List<Character> charlist = new ArrayList<>();
		for (int i = 48; i <= 57; i++) {
			charlist.add((char) i);
		}
		for (int i = 65; i <= 90; i++) {
			charlist.add((char) i);
		}
		for (int i = 97; i <= 122; i++) {
			charlist.add((char) i);
		}
		Collections.shuffle(charlist, new SecureRandom());
		Collections.shuffle(charlist, new SecureRandom());
		RANDOM_CHARS = Collections.unmodifiableList(charlist);
	}

	/**
	 * Create Random String with given size
	 * 
	 * @param size
	 * @return Random String
	 */
	public static String getRandomString(int size) {
		StringBuilder builder = new StringBuilder(size);
		SecureRandom random = new SecureRandom();
		for (int i = 0; i < size; i++) {
			builder.append(RANDOM_CHARS.get(random.nextInt(RANDOM_CHARS.size())));
		}
		return builder.toString();
	}
}
