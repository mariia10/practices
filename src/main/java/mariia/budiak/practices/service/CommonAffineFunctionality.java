package mariia.budiak.practices.service;

import mariia.budiak.practices.model.AffineKey;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

abstract public class CommonAffineFunctionality {
    public static final HashMap<Character, Integer> ALPHABET_MAP = new HashMap<>();
    public static List<Character> ALPHABET =
            Arrays.asList(
                    'a', 'b', 'c', 'd', 'e', 'f', 'g',
                    'h', 'i', 'j', 'k', 'l', 'm', 'n',
                    'o', 'p', 'q', 'r', 's', 't', 'u',
                    'v', 'w', 'x', 'y', 'z');

    static {
        int i = 0;
        for (var ch : ALPHABET) {
            ALPHABET_MAP.put(ch, i);
            i++;
        }
    }

    protected void validate(AffineKey key) {
        var alphabetSize = ALPHABET.size();
        if ((key.getAlpha() == null || key.getBeta() == null)
                || gcd(alphabetSize, key.getAlpha()) != 1)
            throw new HttpClientErrorException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "задан неверный ключ");
    }

    protected int getMinusAlpha(long p, long a) {
        long pOriginal = p;
        long y1 = 0, y2 = 1;
        while (a != 1) {
            long quotient = p / a;
            long r = p % a;
            p = a;
            a = r;
            long tempR = y1 - y2 * quotient;
            y1 = y2;
            y2 = tempR;
        }
        return (int) (y2 < 0 ? y2 + pOriginal : y2);
    }

    protected int gcd(int first, int second) {
        return second == 0 ? first : gcd(second, first % second);
    }

}
