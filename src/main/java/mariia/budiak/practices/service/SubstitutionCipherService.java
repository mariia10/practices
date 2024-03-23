package mariia.budiak.practices.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import mariia.budiak.practices.model.SubKey;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.util.ArrayList;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Getter
public class SubstitutionCipherService {
    private final ObjectMapper mapper = new ObjectMapper();
    private SubKey subKey;

    public void setSubKey(SubKey key) {
        try {
            validate(key);
        } catch (JsonProcessingException e) {
            throw new HttpServerErrorException(HttpStatus.UNPROCESSABLE_ENTITY);
        }
        subKey = key;
    }

    public String encode(String phrase) throws JsonProcessingException {
        var json = mapper.writeValueAsString(subKey);
        phrase = phrase.toLowerCase();
        var chars = phrase.toCharArray();
        ArrayList<String> encodedChars = new ArrayList<>();
        JSONObject jsonObject = new JSONObject(json);
        for (var ch : chars) {
            if (jsonObject.keySet().contains(String.valueOf(ch))) {
                encodedChars.add(jsonObject.getString(String.valueOf(ch)));
                continue;
            }
            encodedChars.add(String.valueOf(ch));

        }
        return String.join("", encodedChars);
    }

    public String decode(String phrase) throws JsonProcessingException {
        var json = mapper.writeValueAsString(subKey);
        phrase = phrase.toLowerCase();
        var chars = phrase.toCharArray();
        ArrayList<String> decodedChars = new ArrayList<>();
        JSONObject jsonObject = new JSONObject(json);
        for (var ch : chars) {
            if (jsonObject.toMap().containsValue(String.valueOf(ch))) {
                decodedChars.add(jsonObject.toMap().entrySet().stream()
                        .filter(k -> k.getValue().toString()
                                .equals(String.valueOf(ch))).map(Map.Entry::getKey)
                        .findFirst().orElse(null));
                continue;
            }
            decodedChars.add(String.valueOf(ch));

        }
        return String.join("", decodedChars);
    }

    private void validate(SubKey subKey) throws JsonProcessingException {
        var json = mapper.writeValueAsString(subKey);
        JSONObject jsonObject = new JSONObject(json);
        var subMap = jsonObject.toMap();
        if (subMap.size() != 26) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "внесены не все соответствия");
        }
        if (subMap.values().stream().anyMatch(v -> v == null || v.toString().length() > 1)) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "был введен невалидный ключ");
        }
        var values = subMap.values().stream().map(Object::toString).collect(Collectors.toSet());
        if (subMap.values().size() > values.size()) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "обнаружена неоднозначная кодировка букв");
        }
    }
}
