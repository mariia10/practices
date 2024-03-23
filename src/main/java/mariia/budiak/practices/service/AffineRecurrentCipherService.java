package mariia.budiak.practices.service;

import lombok.Getter;
import mariia.budiak.practices.model.AffineKey;
import mariia.budiak.practices.model.AffineRecurrentKeys;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.util.ArrayList;
import java.util.Map;

@Service
public class AffineRecurrentCipherService extends CommonAffineFunctionality {

    private static final Integer LIMIT = 10000;

    @Getter
    private final AffineRecurrentKeys keys = new AffineRecurrentKeys();

    public void setSubKeys(AffineRecurrentKeys keys) {
        if (keys.getAffineKeyHashMap().size() != 2) {
            throw new HttpClientErrorException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "необходимо задать 2 ключа");
        }
        keys.getAffineKeyHashMap().forEach((key, value) -> validate(value));
        //заполняю до 5000 тыс значение мапы
        this.keys.getAffineKeyHashMap().clear();
        var keysHashMap = this.keys.getAffineKeyHashMap();
        keysHashMap.putAll(keys.getAffineKeyHashMap());
        var n = ALPHABET.size();
        keysHashMap.get(1).setMinusAlpha(
                getMinusAlpha(n, keys.getAffineKeyHashMap().get(1).getAlpha()));
        keysHashMap.get(2).setMinusAlpha(
                getMinusAlpha(n, keys.getAffineKeyHashMap().get(2).getAlpha()));
        for (int i = 3; i <= LIMIT; i++) {
            var key = new AffineKey();
            key.setAlpha(keysHashMap.get(i - 1).getAlpha()
                    * keysHashMap.get(i - 2).getAlpha() % n);
            key.setBeta((keysHashMap.get(i - 1).getBeta()
                    + keysHashMap.get(i - 2).getBeta()) % n);
            key.setMinusAlpha(getMinusAlpha(n, key.getAlpha()));
            keysHashMap.put(i, key);
        }
    }

    public String encode(String phrase) {
        var rowPhraseList = new ArrayList<Character>();
        var n = ALPHABET.size();
        var counter = 1;
        for (var ch : phrase.toCharArray()) {
            if (ALPHABET_MAP.containsKey(ch)) {
                var x = ALPHABET_MAP.get(ch);
                var key = keys.getAffineKeyHashMap().get(counter);
                var y = (key.getAlpha() * x + key.getBeta()) % n;
                rowPhraseList.add(ALPHABET_MAP.entrySet()
                        .stream().filter(e -> e.getValue() == y)
                        .map(Map.Entry::getKey).findFirst().orElse(null));
                counter++;
                continue;
            }
            rowPhraseList.add(ch);
        }
        StringBuilder builder = new StringBuilder(rowPhraseList.size());
        rowPhraseList.forEach(builder::append);
        return builder.toString();
    }

    public String decode(String phrase) {
        var rowPhraseList = new ArrayList<Character>();
        var n = ALPHABET.size();
        var counter = 1;
        for (var ch : phrase.toCharArray()) {
            if (ALPHABET_MAP.containsKey(ch)) {
                var y = ALPHABET_MAP.get(ch);
                var key = keys.getAffineKeyHashMap().get(counter);
                var x = (y - key.getBeta()) * key.getMinusAlpha() % n;
                var xLast = x < 0 ? x + n : x;
                rowPhraseList.add(ALPHABET_MAP.entrySet()
                        .stream().filter(e -> e.getValue() == xLast)
                        .map(Map.Entry::getKey).findFirst().orElse(null));
                counter++;
                continue;
            }
            rowPhraseList.add(ch);
        }
        StringBuilder builder = new StringBuilder(rowPhraseList.size());
        rowPhraseList.forEach(builder::append);
        return builder.toString();
    }
}
