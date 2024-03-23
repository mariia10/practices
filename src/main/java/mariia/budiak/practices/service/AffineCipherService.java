package mariia.budiak.practices.service;

import lombok.Getter;
import mariia.budiak.practices.model.AffineKey;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.util.*;

@Service
public class AffineCipherService extends CommonAffineFunctionality{

    @Getter
    private final AffineKey affineKey = new AffineKey();

    public void setAffineKey(AffineKey key) {
        validate(key);

        affineKey.setAlpha(key.getAlpha());
        affineKey.setBeta(key.getBeta());
        affineKey.setMinusAlpha(getMinusAlpha(ALPHABET.size(), key.getAlpha()));

    }
    public String encode(String phrase) {
        var rowPhraseList = new ArrayList<Character>();
        var n = ALPHABET.size();
        for (var ch : phrase.toCharArray()) {
            if (ALPHABET_MAP.containsKey(ch)) {
                var x = ALPHABET_MAP.get(ch);
                var y = (affineKey.getAlpha() * x + affineKey.getBeta()) % n;
                rowPhraseList.add(ALPHABET_MAP.entrySet()
                        .stream().filter(e -> e.getValue() == y)
                        .map(Map.Entry::getKey).findFirst().orElse(null));
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
        for (var ch : phrase.toCharArray()) {
            if (ALPHABET_MAP.containsKey(ch)) {
                var y = ALPHABET_MAP.get(ch);
                var x = (y - affineKey.getBeta()) * affineKey.getMinusAlpha() % n;
                var xLast = x < 0 ? x + n : x;
                rowPhraseList.add(ALPHABET_MAP.entrySet()
                        .stream().filter(e -> e.getValue() == xLast)
                        .map(Map.Entry::getKey).findFirst().orElse(null));
                continue;
            }
            rowPhraseList.add(ch);
        }
        StringBuilder builder = new StringBuilder(rowPhraseList.size());
        rowPhraseList.forEach(builder::append);
        return builder.toString();
    }


}
